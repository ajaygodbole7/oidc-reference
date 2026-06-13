package com.example.oidcreference.authservice;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.TokenErrorResponse;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;
import com.nimbusds.openid.connect.sdk.token.OIDCTokens;
import java.net.URI;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.BadCredentialsException;

class AuthorizationCodeTokenExchangeClientTest {

  // ----- id_token validation wiring (the seam every controller test stubs) ---
  //
  // exchange() must run the token-endpoint id_token through idTokenValidator
  // .validate() and persist the VALIDATOR's claims. If that call were ever
  // dropped, an UNVALIDATED id_token would be stored (and later emitted as
  // id_token_hint on logout) and the nonce binding would be skipped — and
  // nothing else would catch it: every controller test stubs this client, and
  // the live e2e only ever sees valid Keycloak tokens. These tests pin the
  // wiring directly.

  @Test
  void exchangeValidatesIdTokenAndStoresValidatorClaims() {
    var tokens = new OIDCTokens("header.payload.sig", accessToken("access-xyz"),
        new RefreshToken("refresh-xyz"));
    var validator = new RecordingValidator(Map.of("sub", "alice", "roles", List.of("user")));
    var client = clientReturning(tokens, validator);
    var tx = new OAuthTransaction(
        "0123456789012345678901234567890123456789012", "nonce-123", "/", Instant.now(), "tx-hash");

    SessionRecord session = client.exchange("code", "state", "http://app/cb", tx);

    // validate() saw the response id_token, the access token, and the SAME
    // transaction (the nonce binding flows through it).
    assertThat(validator.calls).isEqualTo(1);
    assertThat(validator.lastIdToken).isEqualTo("header.payload.sig");
    assertThat(validator.lastAccessToken).isEqualTo("access-xyz");
    assertThat(validator.lastTransaction).isSameAs(tx);
    // Stored claims are the validator's output, and the tokens are persisted.
    assertThat(session.claims()).containsEntry("roles", List.of("user"));
    assertThat(session.idToken()).isEqualTo("header.payload.sig");
    assertThat(session.accessToken()).isEqualTo("access-xyz");
    assertThat(session.refreshToken()).isEqualTo("refresh-xyz");
  }

  @Test
  void exchangeFailsClosedWhenIdTokenValidationRejects() {
    var tokens = new OIDCTokens("header.payload.sig", accessToken("access-xyz"),
        new RefreshToken("refresh-xyz"));
    var client = clientReturning(tokens, rejectingValidator());
    var tx = new OAuthTransaction(
        "0123456789012345678901234567890123456789012", "nonce-123", "/", Instant.now(), "tx-hash");

    assertThatThrownBy(() -> client.exchange("code", "state", "http://app/cb", tx))
        .isInstanceOf(BadCredentialsException.class);
  }

  @Test
  void exchangeFailsClosedWhenTokenEndpointRejectsTheCode() {
    // A PKCE-verifier mismatch (or a reused / expired code) makes the token
    // endpoint return 400 invalid_grant. The exchange MUST fail closed — never
    // reach id_token validation or create a session — exactly as a live PKCE
    // mismatch against Keycloak would. (C4: unit complement to the live
    // happy-path PKCE round-trip in e2e-auth.)
    var client = new AuthorizationCodeTokenExchangeClient(metadata(), rejectingValidator(), props()) {
      @Override
      TokenResponse parse(TokenRequest tokenRequest) {
        return new TokenErrorResponse(OAuth2Error.INVALID_GRANT);
      }
    };
    var tx = new OAuthTransaction(
        "0123456789012345678901234567890123456789012", "nonce-123", "/", Instant.now(), "tx-hash");

    assertThatThrownBy(() -> client.exchange("code", "state", "http://app/cb", tx))
        .isInstanceOf(IllegalStateException.class);
  }

  private static AccessToken accessToken(String value) {
    return new BearerAccessToken(value, 300, null);
  }

  private static AuthorizationCodeTokenExchangeClient clientReturning(
      OIDCTokens tokens, IdTokenValidator validator) {
    return new AuthorizationCodeTokenExchangeClient(metadata(), validator, props()) {
      @Override
      TokenResponse parse(TokenRequest tokenRequest) {
        return new OIDCTokenResponse(tokens);
      }
    };
  }

  private static AuthProperties props() {
    return new AuthProperties(
        "idp", "", java.time.Duration.ofSeconds(60),
        java.time.Duration.ofSeconds(1800), java.time.Duration.ofSeconds(28800),
        null,
        URI.create("http://idp.example"), null, null, null, null,
        "oidc-reference-auth", "test-secret", Set.of("openid"),
        List.of("realm_access", "roles"),
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        true, "oidc-reference-api-gateway", "oidc-reference-auth-internal",
        java.time.Duration.ofSeconds(3), java.time.Duration.ofSeconds(5), "");
  }

  private static OidcProviderMetadata metadata() {
    return new OidcProviderMetadata(
        "oidc-reference-auth",
        "test-secret",
        URI.create("http://idp.example/authorize"),
        URI.create("http://idp.example/token"),
        URI.create("http://idp.example/jwks"),
        URI.create("http://idp.example/logout"),
        "http://idp.example",
        Set.of("openid", "profile"));
  }

  private static IdTokenValidator rejectingValidator() {
    return new IdTokenValidator() {
      @Override
      public Map<String, Object> validate(String idToken, String accessToken, OAuthTransaction tx) {
        throw new BadCredentialsException("id_token rejected");
      }

      @Override
      public Map<String, Object> validateRefreshed(String idToken, String accessToken) {
        throw new UnsupportedOperationException("refresh path not exercised here");
      }
    };
  }

  private static final class RecordingValidator implements IdTokenValidator {
    private final Map<String, Object> claims;
    private int calls;
    private String lastIdToken;
    private String lastAccessToken;
    private OAuthTransaction lastTransaction;

    RecordingValidator(Map<String, Object> claims) {
      this.claims = claims;
    }

    @Override
    public Map<String, Object> validate(String idToken, String accessToken, OAuthTransaction tx) {
      calls++;
      lastIdToken = idToken;
      lastAccessToken = accessToken;
      lastTransaction = tx;
      return claims;
    }

    @Override
    public Map<String, Object> validateRefreshed(String idToken, String accessToken) {
      throw new UnsupportedOperationException("refresh path not exercised here");
    }
  }

  // ----- transport timeouts -----

  @Test
  void exchangeFailsFastAgainstAHungTokenEndpoint() throws Exception {
    // Same failure mode as the refresh client: Nimbus HTTPRequest defaults
    // to infinite connect/read timeouts, so a stalled token endpoint hangs
    // the /auth/callback/idp request thread forever. The exchange must
    // surface a transport failure within its read timeout.
    try (java.net.ServerSocket hung = new java.net.ServerSocket(0, 1)) {
      var md = new OidcProviderMetadata(
          "oidc-reference-auth",
          "test-secret",
          URI.create("http://idp.example/authorize"),
          URI.create("http://127.0.0.1:" + hung.getLocalPort() + "/token"),
          URI.create("http://idp.example/jwks"),
          URI.create("http://idp.example/logout"),
          "http://idp.example",
          Set.of("openid"));
      var client = new AuthorizationCodeTokenExchangeClient(md, rejectingValidator(), props());
      // Nimbus CodeVerifier requires 43-128 chars.
      var transaction = new OAuthTransaction(
          "0123456789012345678901234567890123456789012345",
          "nonce",
          "/",
          Instant.now(),
          "tx-hash");

      org.junit.jupiter.api.Assertions.assertTimeoutPreemptively(
          java.time.Duration.ofSeconds(10),
          () -> assertThatThrownBy(() -> client.exchange(
                  "code-1",
                  "state-1",
                  "http://127.0.0.1:5173/auth/callback/idp",
                  transaction))
              .isInstanceOf(IllegalStateException.class)
              .hasMessageContaining("token exchange failed"));
    }
  }

  // ----- refresh_expires_in parsing (IdP portability) -----
  //
  // refresh_expires_in is a Keycloak-ism; most IdPs never emit it. The
  // contract is: a positive Number or numeric String is honored, everything
  // else (absent, zero, negative, garbage) means UNKNOWN and must yield
  // null — never a fabricated default that would make
  // SessionRecord.refreshTokenExpired() kill valid sessions on IdPs that
  // simply do not send the claim.

  @Test
  void numericRefreshExpiresInIsParsed() {
    assertThat(AuthorizationCodeTokenExchangeClient.parseRefreshExpiresIn(900L)).isEqualTo(900L);
    assertThat(AuthorizationCodeTokenExchangeClient.parseRefreshExpiresIn(" 900 ")).isEqualTo(900L);
  }

  @Test
  void absentRefreshExpiresInIsUnknownNotFabricated() {
    assertThat(AuthorizationCodeTokenExchangeClient.parseRefreshExpiresIn(null)).isNull();
  }

  @Test
  void nonPositiveOrGarbageRefreshExpiresInIsUnknown() {
    assertThat(AuthorizationCodeTokenExchangeClient.parseRefreshExpiresIn(0L)).isNull();
    assertThat(AuthorizationCodeTokenExchangeClient.parseRefreshExpiresIn(-5L)).isNull();
    assertThat(AuthorizationCodeTokenExchangeClient.parseRefreshExpiresIn("0")).isNull();
    assertThat(AuthorizationCodeTokenExchangeClient.parseRefreshExpiresIn("soon")).isNull();
    assertThat(AuthorizationCodeTokenExchangeClient.parseRefreshExpiresIn(Map.of())).isNull();
  }
}
