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
import org.springframework.stereotype.Component;

@Component
class AuthorizationCodeTokenExchangeClient implements TokenExchangeClient {
  private static final long DEFAULT_REFRESH_EXPIRES_IN = 1800L;

  private final OidcProviderMetadata md;
  private final IdTokenValidator idTokenValidator;

  AuthorizationCodeTokenExchangeClient(OidcProviderMetadata md, IdTokenValidator idTokenValidator) {
    this.md = md;
    this.idTokenValidator = idTokenValidator;
  }

  @Override
  public SessionRecord exchange(String code, String state, String redirectUri, OAuthTransaction transaction) {
    var grant = new AuthorizationCodeGrant(
        new AuthorizationCode(code),
        URI.create(redirectUri),
        new CodeVerifier(transaction.verifier()));
    var clientAuth = new ClientSecretBasic(new ClientID(md.clientId()), new Secret(md.clientSecret()));
    var tokenRequest = new TokenRequest(md.tokenEndpoint(), clientAuth, grant);

    com.nimbusds.oauth2.sdk.TokenResponse tokenResponse;
    try {
      tokenResponse = OIDCTokenResponseParser.parse(tokenRequest.toHTTPRequest().send());
    } catch (java.io.IOException | com.nimbusds.oauth2.sdk.ParseException e) {
      // Narrow catch — mirrors AuthorizationCodeTokenRefreshClient.parse.
      // A broad catch(Exception) hides programmer-error RuntimeExceptions
      // from Nimbus (null state, malformed config) as if they were
      // transport failures.
      throw new IllegalStateException("token exchange failed", e);
    }

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
    // of a number. Tolerate both — falling back to the default silently on
    // a string-typed value would lie about the AS's intent.
    Object refreshExpiresInRaw = successResponse.getCustomParameters().get("refresh_expires_in");
    long refreshExpiresIn = parseRefreshExpiresIn(refreshExpiresInRaw);

    return new SessionRecord(
        accessToken.getValue(),
        refreshToken.getValue(),
        idTokenString,
        accessExpiresAt,
        Instant.now().plusSeconds(refreshExpiresIn),
        idTokenValidator.validate(idTokenString, accessToken.getValue(), transaction));
  }

  // Accept both Number-typed (canonical) and String-typed (some IdPs)
  // forms. Reject negative / zero / unparseable values by falling back
  // to the default — those are configuration errors rather than valid
  // signals.
  static long parseRefreshExpiresIn(Object raw) {
    return switch (raw) {
      case Number n when n.longValue() > 0 -> n.longValue();
      case String s -> {
        try {
          long v = Long.parseLong(s.trim());
          yield v > 0 ? v : DEFAULT_REFRESH_EXPIRES_IN;
        } catch (NumberFormatException e) {
          yield DEFAULT_REFRESH_EXPIRES_IN;
        }
      }
      case null, default -> DEFAULT_REFRESH_EXPIRES_IN;
    };
  }
}
