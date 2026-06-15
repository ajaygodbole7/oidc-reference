package com.example.oidcreference.authservice;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.openid.connect.sdk.claims.AccessTokenHash;
import com.nimbusds.openid.connect.sdk.validators.IDTokenValidator;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.BadCredentialsException;

/**
 * Negative-path coverage for {@link JwtOidcIdTokenValidator}. The SUT is
 * normally wired against a remote JWKS endpoint via Nimbus's refresh-ahead
 * {@link com.nimbusds.jose.jwk.source.JWKSourceBuilder}; here we use the
 * package-private constructor to inject an {@link IDTokenValidator} built
 * against an in-memory {@link JWKSet} so each negative case can be exercised
 * deterministically without HTTP.
 *
 * <p>Issuer = {@code http://test}, ClientID = {@code test-client}, and the
 * transaction's nonce ({@code expected-nonce}) is the binding salt. Every
 * test below would still pass trivially if the SUT skipped the check it
 * targets — they are written so the green outcome <em>requires</em> the
 * corresponding Nimbus check (alg allowlist, iss, aud, exp, nonce,
 * signature) to be wired correctly.
 */
class JwtOidcIdTokenValidatorTest {

  private static final String ISSUER = "http://test";
  private static final String CLIENT_ID = "test-client";
  private static final String KID = "kid-1";
  private static final String EXPECTED_NONCE = "expected-nonce";
  private static final String ACCESS_TOKEN = "test-access-token-9d8a7b6c5e4f3a2b1c0d";

  private RSAKey signingKey;
  private IDTokenValidator validator;
  private JwtOidcIdTokenValidator sut;
  private OAuthTransaction transaction;

  @BeforeEach
  void setUp() throws Exception {
    signingKey = new RSAKeyGenerator(2048)
        .keyID(KID)
        .algorithm(JWSAlgorithm.RS256)
        .generate();
    JWKSet jwkSet = new JWKSet(signingKey.toPublicJWK());
    JWKSource<SecurityContext> source = new ImmutableJWKSet<>(jwkSet);
    JWSVerificationKeySelector<SecurityContext> selector =
        new JWSVerificationKeySelector<>(JWSAlgorithm.RS256, source);
    validator = new IDTokenValidator(
        new Issuer(ISSUER),
        new ClientID(CLIENT_ID),
        selector,
        null);
    sut = new JwtOidcIdTokenValidator(
        validator, CLIENT_ID, List.of("realm_access", "roles"));
    // This test exercises ID-token validation in isolation; the
    // tx_cookie_hash is irrelevant to the validator, but null is no
    // longer a legal production value (the callback fail-closes on
    // null). Pass an obvious sentinel so the constructor stays honest.
    transaction = new OAuthTransaction(
        "test-verifier",
        EXPECTED_NONCE,
        "/",
        Instant.now(),
        "not-used-by-id-token-validator");
  }

  @Test
  void validTokenReturnsExpectedClaims() throws Exception {
    String token = signRs256(claimsBuilder().build());

    Map<String, Object> claims = sut.validate(token, ACCESS_TOKEN, transaction);

    assertThat(claims).containsEntry("sub", "alice");
    assertThat(claims).containsEntry("preferred_username", "alice");
    assertThat(claims).containsEntry("name", "Alice Example");
    assertThat(claims).containsEntry("email", "alice@example.test");
    assertThat(claims).containsEntry("roles", List.of("user"));
  }

  @Test
  void algNoneIsRejected() {
    // PlainJWT serializes with header {"alg":"none"}; Nimbus rejects because
    // the validator's key selector requires a SignedJWT with an RS256 header.
    PlainJWT plain = new PlainJWT(claimsBuilder().build());
    String token = plain.serialize();

    assertThatThrownBy(() -> sut.validate(token, ACCESS_TOKEN, transaction))
        .isInstanceOf(BadCredentialsException.class);
  }

  @Test
  void algConfusionHs256IsRejected() throws Exception {
    byte[] secret = new byte[32];
    new SecureRandom().nextBytes(secret);
    SignedJWT jwt = new SignedJWT(
        new JWSHeader.Builder(JWSAlgorithm.HS256).keyID(KID).build(),
        claimsBuilder().build());
    jwt.sign(new MACSigner(secret));
    String token = jwt.serialize();

    // The RS256 allowlist on JWSVerificationKeySelector must reject any
    // HS256-signed token — even with a matching kid — because alg-confusion
    // attacks exploit verifiers that accept the token's declared algorithm.
    assertThatThrownBy(() -> sut.validate(token, ACCESS_TOKEN, transaction))
        .isInstanceOf(BadCredentialsException.class);
  }

  @Test
  void wrongIssuerIsRejected() throws Exception {
    String token = signRs256(claimsBuilder().issuer("http://attacker").build());

    assertThatThrownBy(() -> sut.validate(token, ACCESS_TOKEN, transaction))
        .isInstanceOf(BadCredentialsException.class);
  }

  @Test
  void wrongAudienceIsRejected() throws Exception {
    String token = signRs256(claimsBuilder().audience(List.of("other-client")).build());

    assertThatThrownBy(() -> sut.validate(token, ACCESS_TOKEN, transaction))
        .isInstanceOf(BadCredentialsException.class);
  }

  @Test
  void multipleAudiencesWithoutAuthorizedPartyAreRejected() throws Exception {
    String token = signRs256(claimsBuilder()
        .audience(List.of(CLIENT_ID, "another-audience"))
        .build());

    assertThatThrownBy(() -> sut.validate(token, ACCESS_TOKEN, transaction))
        .isInstanceOf(BadCredentialsException.class);
  }

  @Test
  void multipleAudiencesWithWrongAuthorizedPartyAreRejected() throws Exception {
    String token = signRs256(claimsBuilder()
        .audience(List.of(CLIENT_ID, "another-audience"))
        .claim("azp", "other-client")
        .build());

    assertThatThrownBy(() -> sut.validate(token, ACCESS_TOKEN, transaction))
        .isInstanceOf(BadCredentialsException.class);
  }

  @Test
  void multipleAudiencesWithExpectedAuthorizedPartyAreAccepted() throws Exception {
    String token = signRs256(claimsBuilder()
        .audience(List.of(CLIENT_ID, "another-audience"))
        .claim("azp", CLIENT_ID)
        .build());

    assertThat(sut.validate(token, ACCESS_TOKEN, transaction))
        .containsEntry("sub", "alice");
  }

  @Test
  void singleAudienceWithWrongAuthorizedPartyIsRejected() throws Exception {
    String token = signRs256(claimsBuilder()
        .claim("azp", "other-client")
        .build());

    assertThatThrownBy(() -> sut.validate(token, ACCESS_TOKEN, transaction))
        .isInstanceOf(BadCredentialsException.class);
  }

  @Test
  void refreshedTokenWithWrongAuthorizedPartyIsRejected() throws Exception {
    String token = signRs256(claimsBuilder()
        .claim("azp", "other-client")
        .build());

    assertThatThrownBy(() -> sut.validateRefreshed(token, ACCESS_TOKEN))
        .isInstanceOf(BadCredentialsException.class);
  }

  @Test
  void expiredIsRejected() throws Exception {
    String token = signRs256(claimsBuilder()
        .expirationTime(Date.from(Instant.now().minusSeconds(60)))
        .build());

    assertThatThrownBy(() -> sut.validate(token, ACCESS_TOKEN, transaction))
        .isInstanceOf(BadCredentialsException.class);
  }

  @Test
  void nonceMismatchIsRejected() throws Exception {
    String token = signRs256(claimsBuilder().claim("nonce", "wrong-nonce").build());

    assertThatThrownBy(() -> sut.validate(token, ACCESS_TOKEN, transaction))
        .isInstanceOf(BadCredentialsException.class);
  }

  @Test
  void signatureFromUnknownKeyIsRejected() throws Exception {
    // Generate a *second* RSA key that is NOT in the published JWKSet but
    // advertise the published kid in the header — a classic key-confusion
    // attempt. Signature verification must fail because the key actually
    // resolved from the JWKSet (kid-1) cannot verify a signature made by an
    // unrelated private key.
    RSAKey foreignKey = new RSAKeyGenerator(2048)
        .keyID(KID)
        .algorithm(JWSAlgorithm.RS256)
        .generate();
    SignedJWT jwt = new SignedJWT(
        new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(KID).build(),
        claimsBuilder().build());
    jwt.sign(new RSASSASigner(foreignKey));
    String token = jwt.serialize();

    assertThatThrownBy(() -> sut.validate(token, ACCESS_TOKEN, transaction))
        .isInstanceOf(BadCredentialsException.class);
  }

  @Test
  void malformedTokenIsRejected() {
    assertThatThrownBy(() -> sut.validate("not.a.jwt", ACCESS_TOKEN, transaction))
        .isInstanceOf(BadCredentialsException.class);
  }

  // -- OIDC Core §3.1.3.7 step 7: at_hash --------------------------------

  @Test
  void atHashMatchingTheAccessTokenIsAccepted() throws Exception {
    String atHash = AccessTokenHash.compute(
        new BearerAccessToken(ACCESS_TOKEN), JWSAlgorithm.RS256).getValue();
    String token = signRs256(claimsBuilder().claim("at_hash", atHash).build());

    Map<String, Object> claims = sut.validate(token, ACCESS_TOKEN, transaction);

    assertThat(claims).containsEntry("sub", "alice");
  }

  @Test
  void atHashMismatchIsRejected() throws Exception {
    // Compute at_hash against a DIFFERENT access token than the one we pass
    // in. Without this check, an attacker who substituted an access token
    // would slip past every other ID-token validation axis.
    String wrongHash = AccessTokenHash.compute(
        new BearerAccessToken("different-access-token"), JWSAlgorithm.RS256).getValue();
    String token = signRs256(claimsBuilder().claim("at_hash", wrongHash).build());

    assertThatThrownBy(() -> sut.validate(token, ACCESS_TOKEN, transaction))
        .isInstanceOf(BadCredentialsException.class);
  }

  @Test
  void atHashRejectsAlgorithmOutsideIdTokenAllowlistAtUseSite() throws Exception {
    byte[] secret = new byte[32];
    new SecureRandom().nextBytes(secret);
    OctetSequenceKey hmacKey = new OctetSequenceKey.Builder(secret)
        .keyID(KID)
        .algorithm(JWSAlgorithm.HS256)
        .build();
    JWKSource<SecurityContext> source = new ImmutableJWKSet<>(new JWKSet(hmacKey));
    IDTokenValidator hs256Validator = new IDTokenValidator(
        new Issuer(ISSUER),
        new ClientID(CLIENT_ID),
        new JWSVerificationKeySelector<>(JWSAlgorithm.HS256, source),
        null);
    JwtOidcIdTokenValidator hs256Sut = new JwtOidcIdTokenValidator(
        hs256Validator, CLIENT_ID, List.of("realm_access", "roles"));

    String atHash = AccessTokenHash.compute(
        new BearerAccessToken(ACCESS_TOKEN), JWSAlgorithm.HS256).getValue();
    SignedJWT jwt = new SignedJWT(
        new JWSHeader.Builder(JWSAlgorithm.HS256).keyID(KID).build(),
        claimsBuilder().claim("at_hash", atHash).build());
    jwt.sign(new MACSigner(secret));

    assertThatThrownBy(() -> hs256Sut.validate(jwt.serialize(), ACCESS_TOKEN, transaction))
        .isInstanceOf(BadCredentialsException.class)
        .hasMessageContaining("ID token alg is not accepted for at_hash validation");
  }

  // -- IdP-portable roles claim (G1) --------------------------------------

  @Test
  void rolesClaimPath_okta_topLevelGroupsClaim() throws Exception {
    // Okta puts roles in a top-level "groups" claim. Path = ["groups"].
    var oktaSut = new JwtOidcIdTokenValidator(validator, CLIENT_ID, List.of("groups"));
    String token = signRs256(claimsBuilder()
        .claim("groups", List.of("user", "admin"))
        .build());

    Map<String, Object> claims = oktaSut.validate(token, ACCESS_TOKEN, transaction);

    assertThat(claims).containsEntry("roles", List.of("user", "admin"));
  }

  @Test
  void rolesClaimPath_auth0_urlNamespacedClaim() throws Exception {
    // Auth0 emits roles via a namespaced URI-shaped claim. Path is a single
    // element so the URI's slashes aren't split — list-of-segments avoids
    // the dotted-string footgun.
    var auth0Sut = new JwtOidcIdTokenValidator(
        validator, CLIENT_ID, List.of("https://example.test/roles"));
    String token = signRs256(claimsBuilder()
        .claim("https://example.test/roles", List.of("editor"))
        .build());

    Map<String, Object> claims = auth0Sut.validate(token, ACCESS_TOKEN, transaction);

    assertThat(claims).containsEntry("roles", List.of("editor"));
  }

  @Test
  void rolesClaimPath_keycloak_nestedPath() throws Exception {
    // Keycloak default: realm_access.roles. Path = ["realm_access", "roles"]
    // and the default sut (set up with the Keycloak path in @BeforeEach)
    // already exercises this in validTokenReturnsExpectedClaims. This test
    // makes the contract explicit alongside the other IdP shapes.
    String token = signRs256(claimsBuilder().build());

    Map<String, Object> claims = sut.validate(token, ACCESS_TOKEN, transaction);

    assertThat(claims).containsEntry("roles", List.of("user"));
  }

  @Test
  void rolesClaimPath_missingClaimReturnsEmptyList() throws Exception {
    var oktaSut = new JwtOidcIdTokenValidator(validator, CLIENT_ID, List.of("groups"));
    // Build token WITHOUT the groups claim.
    String token = signRs256(claimsBuilder().build());

    Map<String, Object> claims = oktaSut.validate(token, ACCESS_TOKEN, transaction);

    assertThat(claims).containsEntry("roles", List.of());
  }

  @Test
  void atHashMissingIsAccepted() throws Exception {
    // OIDC Core: at_hash is OPTIONAL for the authorization-code flow when
    // the ID token is returned from the token endpoint. The validator must
    // NOT reject an ID token that simply omits the claim.
    String token = signRs256(claimsBuilder().build());

    Map<String, Object> claims = sut.validate(token, ACCESS_TOKEN, transaction);

    assertThat(claims).containsEntry("sub", "alice");
  }

  // -- step-up: auth_time / acr capture (P-step-up) -----------------------

  @Test
  void validateCapturesAuthTimeAndAcrWhenPresent() throws Exception {
    // Step-up assurance rides on auth_time (when the last interactive
    // authentication happened) and, when the IdP emits it, acr. The validator
    // must surface both into the claims map so they reach the session and
    // /auth/me. auth_time is normalized to epoch seconds (a Long).
    long authTime = Instant.now().minusSeconds(30).getEpochSecond();
    String token = signRs256(claimsBuilder()
        .claim("auth_time", authTime)
        .claim("acr", "1")
        .build());

    Map<String, Object> claims = sut.validate(token, ACCESS_TOKEN, transaction);

    assertThat(claims).containsEntry("auth_time", authTime);
    assertThat(claims).containsEntry("acr", "1");
  }

  @Test
  void validateOmitsAuthTimeAndAcrWhenAbsent() throws Exception {
    // A provider that emits neither (e.g. the minimal local realm without the
    // auth_time mapper) must not produce null/empty entries — the keys are
    // simply absent, and downstream freshness checks treat "no auth_time" as
    // "cannot prove a recent authentication".
    String token = signRs256(claimsBuilder().build());

    Map<String, Object> claims = sut.validate(token, ACCESS_TOKEN, transaction);

    assertThat(claims).doesNotContainKey("auth_time");
    assertThat(claims).doesNotContainKey("acr");
  }

  @Test
  void validateRefreshedCapturesAuthTimeAndAcr() throws Exception {
    // The refresh path must surface auth_time/acr too, so a token rotation
    // keeps the session's assurance level current (a re-auth bumps auth_time).
    long authTime = Instant.now().minusSeconds(5).getEpochSecond();
    String token = signRs256(claimsBuilder()
        .claim("auth_time", authTime)
        .claim("acr", "2")
        .build());

    Map<String, Object> claims = sut.validateRefreshed(token, ACCESS_TOKEN);

    assertThat(claims).containsEntry("auth_time", authTime);
    assertThat(claims).containsEntry("acr", "2");
  }

  // -- helpers --------------------------------------------------------------

  private JWTClaimsSet.Builder claimsBuilder() {
    Instant now = Instant.now();
    return new JWTClaimsSet.Builder()
        .issuer(ISSUER)
        .audience(CLIENT_ID)
        .subject("alice")
        .issueTime(Date.from(now))
        .expirationTime(Date.from(now.plusSeconds(300)))
        .claim("nonce", EXPECTED_NONCE)
        .claim("preferred_username", "alice")
        .claim("name", "Alice Example")
        .claim("email", "alice@example.test")
        .claim("realm_access", Map.of("roles", List.of("user")));
  }

  private String signRs256(JWTClaimsSet claims) throws Exception {
    SignedJWT jwt = new SignedJWT(
        new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(KID).build(),
        claims);
    jwt.sign(new RSASSASigner(signingKey));
    return jwt.serialize();
  }
}
