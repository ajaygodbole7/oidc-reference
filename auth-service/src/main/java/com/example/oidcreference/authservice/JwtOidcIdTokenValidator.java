package com.example.oidcreference.authservice;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.JWKSourceBuilder;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.claims.ACR;
import com.nimbusds.openid.connect.sdk.claims.AccessTokenHash;
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;
import com.nimbusds.openid.connect.sdk.validators.AccessTokenValidator;
import com.nimbusds.openid.connect.sdk.validators.IDTokenValidator;
import java.text.ParseException;
import java.util.Collection;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.stereotype.Component;

@Component
class JwtOidcIdTokenValidator implements IdTokenValidator {
  private static final JWSAlgorithm ID_TOKEN_SIGNING_ALGORITHM = JWSAlgorithm.RS256;

  private final IDTokenValidator validator;
  private final String clientId;
  // Path into the ID-token claims that holds the roles array. Different IdPs
  // emit roles at different shapes:
  //   Keycloak: realm_access.roles          → ["realm_access", "roles"]
  //   Okta:     groups                      → ["groups"]
  //   Auth0:    https://my-app/roles        → ["https://my-app/roles"]
  // A list of path segments (rather than a dotted string) lets a single URL-
  // shaped segment carry slashes / dots without ambiguity.
  private final List<String> rolesClaimPath;

  @Autowired
  JwtOidcIdTokenValidator(OidcProviderMetadata md, AuthProperties props) {
    try {
      // cache TTL (10 min) > refresh-ahead trigger (5 min) + cache refresh
      // timeout (15 s default). Nimbus enforces this invariant so the
      // refresh-ahead thread always has time to refresh before expiry.
      JWKSource<SecurityContext> jwks = JWKSourceBuilder
          .create(md.jwksUri().toURL())
          .retrying(true)
          .rateLimited(60_000L)
          .cache(600_000L, 15_000L)
          .refreshAheadCache(300_000L, true)
          .outageTolerant(900_000L)
          .build();
      JWSKeySelector<SecurityContext> keySelector =
          new JWSVerificationKeySelector<>(ID_TOKEN_SIGNING_ALGORITHM, jwks);
      this.validator = new IDTokenValidator(
          new Issuer(md.issuer()),
          new ClientID(md.clientId()),
          keySelector,
          null);
      this.clientId = md.clientId();
      this.rolesClaimPath = List.copyOf(props.rolesClaimPath());
    } catch (Exception e) {
      throw new IllegalStateException("Failed to initialize ID token validator", e);
    }
  }

  // Package-private constructor for tests that need to inject a Nimbus
  // IDTokenValidator built against an in-memory JWKSet — avoids spinning up
  // an HTTP JWKS endpoint to exercise negative-path validation (alg=none,
  // alg confusion, wrong-iss/aud, expired, nonce mismatch, kid swap, etc.).
  JwtOidcIdTokenValidator(
      IDTokenValidator validator, String clientId, List<String> rolesClaimPath) {
    this.validator = validator;
    this.clientId = clientId;
    this.rolesClaimPath = List.copyOf(rolesClaimPath);
  }

  @Override
  public Map<String, Object> validate(
      String idToken, String accessToken, OAuthTransaction transaction) {
    try {
      JWT parsed = JWTParser.parse(idToken);
      IDTokenClaimsSet claims = validator.validate(parsed, new Nonce(transaction.nonce()));
      enforceAuthorizedParty(claims);
      enforceAtHash(parsed, claims, accessToken);
      return userClaims(claims, rolesClaimPath);
    } catch (BadCredentialsException e) {
      throw e;
    } catch (Exception e) {
      throw new BadCredentialsException("ID token validation failed", e);
    }
  }

  @Override
  public Map<String, Object> validateRefreshed(String idToken, String accessToken) {
    try {
      JWT parsed = JWTParser.parse(idToken);
      // null expected-nonce: a refresh response does not carry the login
      // nonce. All other checks (signature against JWKS, issuer, audience,
      // expiry) are still enforced by the Nimbus validator.
      IDTokenClaimsSet claims = validator.validate(parsed, null);
      enforceAuthorizedParty(claims);
      enforceAtHash(parsed, claims, accessToken);
      return userClaims(claims, rolesClaimPath);
    } catch (BadCredentialsException e) {
      throw e;
    } catch (Exception e) {
      throw new BadCredentialsException("refreshed ID token validation failed", e);
    }
  }

  // OIDC Core §3.1.3.7 steps 4-5. Keep this explicit rather than relying on
  // Nimbus behavior, which changed between dependency releases: multi-audience
  // ID tokens require azp, and every present azp must identify this client.
  private void enforceAuthorizedParty(IDTokenClaimsSet claims) {
    var audiences = claims.getAudience();
    var authorizedParty = claims.getAuthorizedParty();
    if (audiences.size() > 1 && authorizedParty == null) {
      throw new BadCredentialsException(
          "ID token with multiple audiences is missing azp");
    }
    if (authorizedParty != null && !clientId.equals(authorizedParty.getValue())) {
      throw new BadCredentialsException("ID token azp does not match the client id");
    }
  }

  // OIDC Core §3.1.3.7 step 7: when the ID token contains an at_hash claim,
  // verify it against the access token using the hash algorithm derived from
  // the ID token's JWS alg. at_hash is OPTIONAL for the code flow (the ID
  // token comes back from the token endpoint, over TLS, alongside the access
  // token), so a missing claim is accepted; but a PRESENT claim must match
  // or the token is rejected.
  private static void enforceAtHash(JWT parsed, IDTokenClaimsSet claims, String accessToken) {
    AccessTokenHash claimed = claims.getAccessTokenHash();
    if (claimed == null) {
      return;
    }
    if (!(parsed instanceof SignedJWT signed)) {
      throw new BadCredentialsException(
          "ID token carries at_hash but is not signed — cannot validate");
    }
    if (accessToken == null || accessToken.isBlank()) {
      throw new BadCredentialsException(
          "ID token carries at_hash but no access token was supplied for the check");
    }
    JWSAlgorithm algorithm = signed.getHeader().getAlgorithm();
    if (!ID_TOKEN_SIGNING_ALGORITHM.equals(algorithm)) {
      throw new BadCredentialsException(
          "ID token alg is not accepted for at_hash validation");
    }
    try {
      AccessTokenValidator.validate(
          new BearerAccessToken(accessToken),
          algorithm,
          claimed);
    } catch (Exception e) {
      throw new BadCredentialsException("at_hash mismatch", e);
    }
  }

  private static Map<String, Object> userClaims(
      IDTokenClaimsSet claims, List<String> rolesClaimPath) throws ParseException {
    Map<String, Object> result = new LinkedHashMap<>();
    putIfPresent(result, "sub", claims.getSubject() != null ? claims.getSubject().getValue() : null);
    putIfPresent(result, "preferred_username", claims.getStringClaim("preferred_username"));
    putIfPresent(result, "name", claims.getStringClaim("name"));
    putIfPresent(result, "email", claims.getStringClaim("email"));
    // Step-up assurance signals. auth_time (the epoch-seconds instant the user
    // last interactively authenticated) is the load-bearing claim the Resource
    // Server enforces freshness on; acr is surfaced when the IdP emits it. Both
    // are optional — absent on providers/realms that don't emit them, in which
    // case a freshness check treats the session as "cannot prove a recent auth".
    Date authTime = claims.getAuthenticationTime();
    if (authTime != null) {
      result.put("auth_time", authTime.toInstant().getEpochSecond());
    }
    putIfPresent(result, "acr", claims.getACR() != null ? claims.getACR().getValue() : null);
    result.put("roles", extractRoles(claims, rolesClaimPath));
    return result;
  }

  // Walk the configured path through the claims map. The terminal node must
  // be a Collection<?> (the OIDC-norm shape for roles/groups). Missing
  // intermediate nodes, wrong-typed terminals, and unwalkable shapes all
  // collapse to an empty list — we never throw on a missing roles claim.
  private static List<String> extractRoles(IDTokenClaimsSet claims, List<String> path)
      throws ParseException {
    if (path.isEmpty()) {
      return List.of();
    }
    Object node;
    if (path.size() == 1) {
      // Single-segment path: top-level claim. Use the raw claim accessor so
      // a URL-shaped name like "https://example/roles" is treated as one
      // claim name, not parsed as a JSON pointer.
      node = claims.getClaim(path.get(0));
    } else {
      Map<String, Object> head = claims.getJSONObjectClaim(path.get(0));
      node = head;
      for (int i = 1; i < path.size() && node instanceof Map<?, ?> m; i++) {
        node = m.get(path.get(i));
      }
    }
    if (!(node instanceof Collection<?> roles)) {
      return List.of();
    }
    return roles.stream().map(Object::toString).toList();
  }

  private static void putIfPresent(Map<String, Object> claims, String name, String value) {
    if (value != null && !value.isBlank()) {
      claims.put(name, value);
    }
  }
}
