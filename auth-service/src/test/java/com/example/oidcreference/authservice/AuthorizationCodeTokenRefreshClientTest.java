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
        Map.of("sub", "alice"),
        "xsrf-1");
  }

  private static AuthProperties props(boolean requireRotation) {
    return new AuthProperties(
        "idp",
        "",
        java.time.Duration.ofSeconds(60),
        URI.create("http://idp.example"),
        "oidc-reference-auth",
        "test-secret",
        Set.of("openid"),
        java.util.List.of("realm_access", "roles"),
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        requireRotation);
  }

  // Stub HTTP-less subclass: pretends the AS returned `tokens`.
  private static AuthorizationCodeTokenRefreshClient clientReturning(
      OIDCTokens tokens, boolean requireRotation) {
    return new AuthorizationCodeTokenRefreshClient(metadata(), props(requireRotation)) {
      @Override
      TokenResponse parse(TokenRequest tokenRequest) {
        return new OIDCTokenResponse(tokens);
      }
    };
  }

  private static OIDCTokens tokensWith(String refreshTokenValue) {
    AccessToken access = new BearerAccessToken("new-access-token", 300, null);
    RefreshToken refresh = refreshTokenValue == null ? null : new RefreshToken(refreshTokenValue);
    return new OIDCTokens(access, refresh);
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
