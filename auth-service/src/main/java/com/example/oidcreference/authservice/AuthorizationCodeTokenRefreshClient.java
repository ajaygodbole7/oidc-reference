package com.example.oidcreference.authservice;

import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.RefreshTokenGrant;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponseParser;
import com.nimbusds.openid.connect.sdk.token.OIDCTokens;
import java.io.IOException;
import java.time.Instant;
import java.util.Map;
import org.springframework.stereotype.Component;

@Component
class AuthorizationCodeTokenRefreshClient implements TokenRefreshClient {
  private final OidcProviderMetadata md;
  private final AuthProperties props;
  private final IdTokenValidator idTokenValidator;

  AuthorizationCodeTokenRefreshClient(
      OidcProviderMetadata md, AuthProperties props, IdTokenValidator idTokenValidator) {
    this.md = md;
    this.props = props;
    this.idTokenValidator = idTokenValidator;
  }

  @Override
  public SessionRecord refresh(SessionRecord session) {
    var grant = new RefreshTokenGrant(new RefreshToken(session.refreshToken()));
    var auth = new ClientSecretBasic(new ClientID(md.clientId()), new Secret(md.clientSecret()));
    var tokenRequest = new TokenRequest(md.tokenEndpoint(), auth, grant);

    var response = parse(tokenRequest);

    if (!response.indicatesSuccess()) {
      var err = response.toErrorResponse().getErrorObject();
      if (OAuth2Error.INVALID_GRANT.getCode().equals(err.getCode())) {
        throw new InvalidRefreshTokenException("refresh token rejected by authorization server");
      }
      throw new IllegalStateException("refresh failed: " + err);
    }

    var success = (OIDCTokenResponse) response.toSuccessResponse();
    OIDCTokens oidcTokens = success.getOIDCTokens();

    String newAccess = oidcTokens.getAccessToken().getValue();
    // Rotation contract:
    //   require-rotation=true (default): the AS MUST return a new
    //   refresh_token that differs from the one we sent. Missing or
    //   reused refresh tokens are treated as a rotation failure and
    //   surface as InvalidRefreshTokenException — the same path the
    //   controller takes on Keycloak's invalid_grant. Silently reusing
    //   the old token would defeat the AS's reuse-detection chain and
    //   make this BFF a compatibility downgrade.
    //   require-rotation=false: legacy behavior, retained as an explicit
    //   escape hatch for IdPs that don't rotate.
    String newRefresh;
    if (oidcTokens.getRefreshToken() == null) {
      if (Boolean.TRUE.equals(props.refreshRequireRotation())) {
        throw new InvalidRefreshTokenException(
            "authorization server omitted refresh_token in rotation response");
      }
      newRefresh = session.refreshToken();
    } else {
      newRefresh = oidcTokens.getRefreshToken().getValue();
      if (Boolean.TRUE.equals(props.refreshRequireRotation())
          && newRefresh.equals(session.refreshToken())) {
        throw new InvalidRefreshTokenException(
            "authorization server returned the same refresh_token (no rotation)");
      }
    }
    String responseIdToken = oidcTokens.getIDTokenString();
    String newIdToken;
    Map<String, Object> newClaims;
    if (responseIdToken != null) {
      // Re-validate the refreshed id_token (signature / issuer / audience /
      // expiry / at_hash — no nonce on a refresh response) and re-read identity
      // + roles. An unvalidated token would be stored verbatim and later
      // emitted as id_token_hint on logout; re-reading claims means an IdP-side
      // change such as a revoked role takes effect on this refresh instead of
      // lingering for the full absolute-session TTL.
      newClaims = idTokenValidator.validateRefreshed(responseIdToken, newAccess);
      newIdToken = responseIdToken;
    } else {
      newIdToken = session.idToken();
      newClaims = session.claims();
    }

    // Pin the refreshed identity to the session (P4). A refresh must not change
    // WHO the session belongs to: if the IdP returns an id_token whose `sub`
    // differs from the session's, fail closed — surfaced as the same
    // InvalidRefreshTokenException as invalid_grant, so the controller
    // invalidates the session rather than silently re-indexing it under a new
    // subject. Low exploitability (the refresh leg is client-authenticated,
    // server-to-server — not attacker-reachable without IdP/channel compromise),
    // but a cheap fail-closed guard worth showing. Only enforced when both subs
    // are present; a no-id_token refresh reuses the prior claims, so `sub` is
    // unchanged by construction and this is a no-op.
    Object priorSub = session.claims() == null ? null : session.claims().get("sub");
    Object refreshedSub = newClaims == null ? null : newClaims.get("sub");
    if (priorSub != null && refreshedSub != null && !priorSub.equals(refreshedSub)) {
      throw new InvalidRefreshTokenException(
          "refreshed identity (sub) does not match the session");
    }

    long lifetime = oidcTokens.getAccessToken().getLifetime();
    Instant accessExpiresAt = lifetime > 0
        ? Instant.now().plusSeconds(lifetime)
        : Instant.now().plusSeconds(300);

    Object refreshExpiresInRaw = success.getCustomParameters().get("refresh_expires_in");
    Long refreshExpiresIn = AuthorizationCodeTokenExchangeClient
        .parseRefreshExpiresIn(refreshExpiresInRaw);

    return new SessionRecord(
        newAccess,
        newRefresh,
        newIdToken,
        accessExpiresAt,
        refreshExpiresIn == null ? null : Instant.now().plusSeconds(refreshExpiresIn),
        session.createdAt(),
        session.absoluteExpiresAt(),
        // Rotation re-mints the refresh token; re-stamp the age baseline so
        // refreshMintedAt always tracks the live refresh token (B5).
        Instant.now(),
        newClaims);
  }

  // Package-private + overridable so a test subclass can stub the
  // response without bringing up an HTTP server. Production callers
  // always go through the OIDC token endpoint over real HTTP.
  com.nimbusds.oauth2.sdk.TokenResponse parse(TokenRequest tokenRequest) {
    try {
      return OIDCTokenResponseParser.parse(
          IdpHttp.withTimeouts(
              tokenRequest.toHTTPRequest(),
              props.idpConnectTimeout(), props.idpReadTimeout()).send());
    } catch (IOException | ParseException e) {
      throw new IllegalStateException("refresh token request failed", e);
    }
  }
}
