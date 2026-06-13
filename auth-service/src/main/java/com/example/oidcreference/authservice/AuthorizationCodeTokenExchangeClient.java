package com.example.oidcreference.authservice;

import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.AuthorizationCodeGrant;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.pkce.CodeVerifier;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponseParser;
import java.net.URI;
import java.time.Instant;
import org.jspecify.annotations.Nullable;
import org.springframework.stereotype.Component;

@Component
class AuthorizationCodeTokenExchangeClient implements TokenExchangeClient {
  private final OidcProviderMetadata md;
  private final IdTokenValidator idTokenValidator;
  private final AuthProperties props;

  AuthorizationCodeTokenExchangeClient(
      OidcProviderMetadata md, IdTokenValidator idTokenValidator, AuthProperties props) {
    this.md = md;
    this.idTokenValidator = idTokenValidator;
    this.props = props;
  }

  @Override
  public SessionRecord exchange(String code, String state, String redirectUri, OAuthTransaction transaction) {
    var grant = new AuthorizationCodeGrant(
        new AuthorizationCode(code),
        URI.create(redirectUri),
        new CodeVerifier(transaction.verifier()));
    var clientAuth = new ClientSecretBasic(new ClientID(md.clientId()), new Secret(md.clientSecret()));
    var tokenRequest = new TokenRequest(md.tokenEndpoint(), clientAuth, grant);

    com.nimbusds.oauth2.sdk.TokenResponse tokenResponse = parse(tokenRequest);

    if (!tokenResponse.indicatesSuccess()) {
      throw new IllegalStateException(
          "token exchange failed: " + tokenResponse.toErrorResponse().getErrorObject());
    }

    var successResponse = (OIDCTokenResponse) tokenResponse.toSuccessResponse();
    var oidcTokens = successResponse.getOIDCTokens();
    var idTokenString = oidcTokens.getIDTokenString();
    var refreshToken = oidcTokens.getRefreshToken();
    if (idTokenString == null || refreshToken == null) {
      throw new IllegalStateException("token endpoint response missing id_token or refresh_token");
    }

    var accessToken = oidcTokens.getAccessToken();
    long lifetime = accessToken.getLifetime();
    Instant accessExpiresAt = Instant.now().plusSeconds(lifetime > 0 ? lifetime : 300);

    // Some IdPs emit refresh_expires_in as a JSON string ("1800") instead
    // of a number. Tolerate both.
    Object refreshExpiresInRaw = successResponse.getCustomParameters().get("refresh_expires_in");
    Long refreshExpiresIn = parseRefreshExpiresIn(refreshExpiresInRaw);

    return new SessionRecord(
        accessToken.getValue(),
        refreshToken.getValue(),
        idTokenString,
        accessExpiresAt,
        refreshExpiresIn == null ? null : Instant.now().plusSeconds(refreshExpiresIn),
        idTokenValidator.validate(idTokenString, accessToken.getValue(), transaction));
  }

  // Package-private + overridable so a test subclass can stub the token-
  // endpoint response without an HTTP server, mirroring
  // AuthorizationCodeTokenRefreshClient.parse. This is the seam that makes the
  // exchange→id_token-validation wiring unit-testable; production callers
  // always go through the OIDC token endpoint over real HTTP (with timeouts).
  // Narrow catch — a broad catch(Exception) would hide programmer-error
  // RuntimeExceptions from Nimbus (null state, malformed config) as if they
  // were transport failures.
  com.nimbusds.oauth2.sdk.TokenResponse parse(TokenRequest tokenRequest) {
    try {
      return OIDCTokenResponseParser.parse(
          IdpHttp.withTimeouts(
              tokenRequest.toHTTPRequest(),
              props.idpConnectTimeout(), props.idpReadTimeout()).send());
    } catch (java.io.IOException | com.nimbusds.oauth2.sdk.ParseException e) {
      throw new IllegalStateException("token exchange failed", e);
    }
  }

  // Accept both Number-typed (canonical) and String-typed (some IdPs)
  // forms. refresh_expires_in is a Keycloak-ism — most IdPs (Okta, Auth0,
  // Entra) never send it. Absent, zero/negative, or unparseable values all
  // mean the refresh token's lifetime is UNKNOWN: return null so the
  // session stores no refresh expiry and SessionRecord.refreshTokenExpired()
  // never short-circuits on a fabricated deadline. Inventing a value here
  // (the previous behavior hardcoded 1800s) would kill valid sessions on
  // any IdP that simply doesn't emit the claim.
  static @Nullable Long parseRefreshExpiresIn(@Nullable Object raw) {
    return switch (raw) {
      case Number n when n.longValue() > 0 -> n.longValue();
      case String s -> {
        try {
          long v = Long.parseLong(s.trim());
          yield v > 0 ? v : null;
        } catch (NumberFormatException e) {
          yield null;
        }
      }
      case null, default -> null;
    };
  }
}
