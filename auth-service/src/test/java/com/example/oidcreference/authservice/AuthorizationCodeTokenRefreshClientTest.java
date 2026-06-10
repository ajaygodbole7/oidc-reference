package com.example.oidcreference.authservice;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;
import com.nimbusds.openid.connect.sdk.token.OIDCTokens;
import java.net.URI;
import java.time.Instant;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;

/**
 * Focused tests for the refresh-token rotation policy enforced by
 * {@link AuthorizationCodeTokenRefreshClient}. The HTTP send is stubbed
 * by overriding {@code parse} on a subclass — production behavior is
 * unchanged. See {@link AuthProperties#refreshRequireRotation} for the
 * rationale on defaulting to strict rotation.
 */
class AuthorizationCodeTokenRefreshClientTest {

  private static final String OLD_REFRESH = "old-refresh-token";

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

  private static SessionRecord oldSession() {
    Instant now = Instant.now();
    return new SessionRecord(
        "old-access-token",
        OLD_REFRESH,
        "old-id-token",
        now.plusSeconds(10),
        now.plusSeconds(1800),
        now,
        now.plusSeconds(43200),
        Map.of("sub", "alice"));
  }

  private static AuthProperties props(boolean requireRotation) {
    return new AuthProperties(
        "idp",
        "",
        java.time.Duration.ofSeconds(60),
        java.time.Duration.ofSeconds(1800),
        java.time.Duration.ofSeconds(28800),
        URI.create("http://idp.example"),
        null,
        null,
        null,
        null,
        "oidc-reference-auth",
        "test-secret",
        Set.of("openid"),
        java.util.List.of("realm_access", "roles"),
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        requireRotation,
        "oidc-reference-api-gateway",
        "oidc-reference-auth-internal");
  }

  // Stub HTTP-less subclass: pretends the AS returned `tokens`. The default
  // validator throws if validateRefreshed is called — fine for token responses
  // with no id_token (the rotation tests), which never reach that path.
  private static AuthorizationCodeTokenRefreshClient clientReturning(
      OIDCTokens tokens, boolean requireRotation) {
    return clientReturning(tokens, requireRotation, validatorReturning(Map.of()));
  }

  private static AuthorizationCodeTokenRefreshClient clientReturning(
      OIDCTokens tokens, boolean requireRotation, IdTokenValidator validator) {
    return new AuthorizationCodeTokenRefreshClient(metadata(), props(requireRotation), validator) {
      @Override
      TokenResponse parse(TokenRequest tokenRequest) {
        return new OIDCTokenResponse(tokens);
      }
    };
  }

  // Stub validator whose refresh path returns a fixed claims map. validate()
  // (the login path) is never reached by the refresh client.
  private static IdTokenValidator validatorReturning(Map<String, Object> refreshedClaims) {
    return new IdTokenValidator() {
      @Override
      public Map<String, Object> validate(String idToken, String accessToken, OAuthTransaction tx) {
        throw new UnsupportedOperationException("login-path validate not used in refresh tests");
      }

      @Override
      public Map<String, Object> validateRefreshed(String idToken, String accessToken) {
        return refreshedClaims;
      }
    };
  }

  private static OIDCTokens tokensWith(String refreshTokenValue) {
    AccessToken access = new BearerAccessToken("new-access-token", 300, null);
    RefreshToken refresh = refreshTokenValue == null ? null : new RefreshToken(refreshTokenValue);
    return new OIDCTokens(access, refresh);
  }

  private static OIDCTokens tokensWithIdToken(String idToken, String refreshTokenValue) {
    AccessToken access = new BearerAccessToken("new-access-token", 300, null);
    RefreshToken refresh = refreshTokenValue == null ? null : new RefreshToken(refreshTokenValue);
    return new OIDCTokens(idToken, access, refresh);
  }

  private static SessionRecord sessionWithRoles(java.util.List<String> roles) {
    Instant now = Instant.now();
    return new SessionRecord(
        "old-access-token",
        OLD_REFRESH,
        "old-id-token",
        now.plusSeconds(10),
        now.plusSeconds(1800),
        now,
        now.plusSeconds(43200),
        Map.of("sub", "alice", "roles", roles));
  }

  // ----- require-rotation = true (default) -----

  @Test
  void rotatedRefreshTokenIsAccepted() {
    var client = clientReturning(tokensWith("brand-new-refresh-token"), true);

    SessionRecord refreshed = client.refresh(oldSession());

    assertThat(refreshed.refreshToken()).isEqualTo("brand-new-refresh-token");
    assertThat(refreshed.accessToken()).isEqualTo("new-access-token");
  }

  @Test
  void missingRefreshTokenIsRejectedWhenRotationRequired() {
    var client = clientReturning(tokensWith(null), true);

    assertThatThrownBy(() -> client.refresh(oldSession()))
        .isInstanceOf(InvalidRefreshTokenException.class)
        .hasMessageContaining("omitted refresh_token");
  }

  @Test
  void reusedRefreshTokenIsRejectedWhenRotationRequired() {
    // AS returned the SAME refresh token we sent — that's a rotation
    // failure, not a happy path. Treat it as invalid_grant so the
    // controller invalidates the session.
    var client = clientReturning(tokensWith(OLD_REFRESH), true);

    assertThatThrownBy(() -> client.refresh(oldSession()))
        .isInstanceOf(InvalidRefreshTokenException.class)
        .hasMessageContaining("same refresh_token");
  }

  @Test
  void refreshReReadsRolesFromNewIdToken() {
    // The IdP revoked a role and reflects it in the id_token on the refresh
    // response. The refreshed session must carry the NEW claims (roles=[user]),
    // not the stale ones copied from the prior session (roles=[admin]).
    var freshClaims = Map.<String, Object>of("sub", "alice", "roles", java.util.List.of("user"));
    var tokens = tokensWithIdToken("new-id-token", "brand-new-refresh-token");
    var client = clientReturning(tokens, true, validatorReturning(freshClaims));

    SessionRecord refreshed = client.refresh(sessionWithRoles(java.util.List.of("admin")));

    assertThat(refreshed.claims()).containsEntry("roles", java.util.List.of("user"));
    assertThat(refreshed.idToken()).isEqualTo("new-id-token");
  }

  // ----- refresh_expires_in handling (IdP portability) -----

  @Test
  void missingRefreshExpiresInLeavesRefreshExpiryUnknown() {
    // Keycloak emits refresh_expires_in; Okta/Auth0/Entra do not. An absent
    // claim means the refresh token's lifetime is UNKNOWN — fabricating a
    // value (the old behavior hardcoded 1800s) makes refreshTokenExpired()
    // kill perfectly valid sessions on IdPs that never sent an expiry.
    // Unknown must be stored as null, which refreshTokenExpired() already
    // treats as "never expired on this basis".
    var client = clientReturning(tokensWith("brand-new-refresh-token"), true);

    SessionRecord refreshed = client.refresh(oldSession());

    assertThat(refreshed.refreshExpiresAt()).isNull();
  }

  @Test
  void presentRefreshExpiresInIsHonored() {
    var tokens = tokensWith("brand-new-refresh-token");
    var client = new AuthorizationCodeTokenRefreshClient(
        metadata(), props(true), validatorReturning(Map.of())) {
      @Override
      TokenResponse parse(TokenRequest tokenRequest) {
        return new OIDCTokenResponse(tokens, Map.of("refresh_expires_in", 900L));
      }
    };

    Instant before = Instant.now();
    SessionRecord refreshed = client.refresh(oldSession());

    assertThat(refreshed.refreshExpiresAt())
        .isBetween(before.plusSeconds(900), Instant.now().plusSeconds(901));
  }

  // ----- transport timeouts -----

  @Test
  void refreshFailsFastAgainstAHungTokenEndpoint() throws Exception {
    // A ServerSocket that is never accept()ed completes the TCP handshake
    // (kernel backlog) and then never responds — the canonical hung IdP.
    // Nimbus HTTPRequest defaults to connect/read timeout 0 (infinite), so
    // without explicit timeouts this refresh blocks a servlet thread forever
    // WHILE HOLDING the per-sid refresh lock: one hung Keycloak becomes
    // auth-service thread-pool exhaustion. The client must surface a
    // transport failure within its read timeout instead.
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
      var client = new AuthorizationCodeTokenRefreshClient(
          md, props(true), validatorReturning(Map.of()));

      org.junit.jupiter.api.Assertions.assertTimeoutPreemptively(
          java.time.Duration.ofSeconds(10),
          () -> assertThatThrownBy(() -> client.refresh(oldSession()))
              .isInstanceOf(IllegalStateException.class)
              .hasMessageContaining("refresh token request failed"));
    }
  }

  // ----- require-rotation = false (explicit escape hatch) -----

  @Test
  void missingRefreshTokenIsToleratedWhenRotationDisabled() {
    // Explicit opt-out for IdPs that don't rotate. The session keeps
    // its existing refresh_token so the next refresh can still proceed.
    var client = clientReturning(tokensWith(null), false);

    SessionRecord refreshed = client.refresh(oldSession());

    assertThat(refreshed.refreshToken()).isEqualTo(OLD_REFRESH);
    assertThat(refreshed.accessToken()).isEqualTo("new-access-token");
  }

  @Test
  void reusedRefreshTokenIsToleratedWhenRotationDisabled() {
    var client = clientReturning(tokensWith(OLD_REFRESH), false);

    SessionRecord refreshed = client.refresh(oldSession());

    assertThat(refreshed.refreshToken()).isEqualTo(OLD_REFRESH);
  }

  // ----- ConfigurationProperties binding -----
  //
  // Guards against a yaml typo silently letting the @DefaultValue mask
  // the real configured value. The unit tests above construct
  // AuthProperties directly and would not catch a misnamed key.
  // Uses Spring Binder directly rather than @SpringBootTest so the
  // assertion stays focused (no OIDC discovery, no servlet context).

  @Test
  void refreshRequireRotationBindsFromKebabCaseKey() {
    // app.refresh-require-rotation is the on-disk yaml key. If the
    // Java field name on AuthProperties is renamed (or the yaml key
    // is rewritten in application.yml) and they drift apart, the
    // binder falls back to @DefaultValue=true and this assertion
    // catches the regression.
    AuthProperties bound = bindProperties(Map.of(
        "app.issuer-uri", "http://idp.example",
        "app.client-id", "oidc-reference-auth",
        "app.client-secret", "test-secret",
        "app.scopes", "openid",
        "app.cookie-signing-key", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        "app.refresh-require-rotation", "false"));
    assertThat(bound.refreshRequireRotation()).isFalse();
  }

  @Test
  void refreshRequireRotationDefaultsToTrueWhenUnspecified() {
    AuthProperties bound = bindProperties(Map.of(
        "app.issuer-uri", "http://idp.example",
        "app.client-id", "oidc-reference-auth",
        "app.client-secret", "test-secret",
        "app.scopes", "openid",
        "app.cookie-signing-key", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="));
    assertThat(bound.refreshRequireRotation()).isTrue();
  }

  private static AuthProperties bindProperties(Map<String, String> properties) {
    var source = new org.springframework.boot.context.properties.source
        .MapConfigurationPropertySource(properties);
    return new org.springframework.boot.context.properties.bind.Binder(source)
        .bindOrCreate("app", AuthProperties.class);
  }
}
