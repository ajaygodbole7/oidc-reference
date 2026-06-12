package com.example.oidcreference.authservice;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import org.junit.jupiter.api.Test;

class SessionRecordTest {

  // Keycloak ssoSessionMaxLifespan in oidc-reference-realm.json (line 13).
  // The BFF absolute ceiling MUST stay at or below this: a ceiling above the
  // IdP SSO max means Keycloak terminates the SSO session first, the next
  // refresh returns invalid_grant, and an active user is ejected early with a
  // misleading "session invalidated" outcome (C13/C14).
  private static final Duration IDP_SSO_MAX_LIFESPAN = Duration.ofSeconds(36000);

  @Test
  void absoluteCeilingStaysUnderIdpSsoMaxLifespan() {
    SessionRecord session = new SessionRecord(
        "access",
        "refresh",
        "id",
        Instant.now().plusSeconds(300),
        Instant.now().plusSeconds(1800),
        Map.of("sub", "alice"));

    Duration ceiling = Duration.between(session.createdAt(), session.absoluteExpiresAt());

    assertThat(ceiling)
        .as("BFF absolute ceiling is 8h")
        .isBetween(Duration.ofHours(8), Duration.ofHours(8).plusSeconds(5));
    assertThat(ceiling)
        .as("BFF absolute ceiling must be <= IdP SSO max lifespan (C14)")
        .isLessThanOrEqualTo(IDP_SSO_MAX_LIFESPAN);
  }

  @Test
  void refreshTokenExpiredIsTrueOnlyWhenExpiryIsPast() {
    SessionRecord live = sessionWithRefreshExpiry(Instant.now().plusSeconds(60));
    SessionRecord expired = sessionWithRefreshExpiry(Instant.now().minusSeconds(1));
    SessionRecord noExpiry = sessionWithRefreshExpiry(null);

    assertThat(live.refreshTokenExpired()).isFalse();
    assertThat(expired.refreshTokenExpired()).isTrue();
    assertThat(noExpiry.refreshTokenExpired())
        .as("a session with no stored refresh expiry is never treated as expired")
        .isFalse();
  }

  // --- B5: optional IdP-independent refresh-token-age ceiling ---------------
  // refresh_expires_in is a Keycloak-ism; Okta/Auth0/Entra omit it, so
  // refreshExpiresAt is null and the IdP-derived check can never fire. The
  // app.max-refresh-token-age knob bounds refresh-token age regardless,
  // measured from refreshMintedAt.

  @Test
  void maxRefreshTokenAgeExceededTreatsRefreshAsExpired() {
    // No IdP refresh expiry (Okta/Auth0/Entra shape), refresh token minted 2h
    // ago, ceiling 1h -> expired on the age check alone.
    SessionRecord session = sessionMintedAgo(Duration.ofHours(2), null);

    assertThat(session.refreshTokenExpired(Duration.ofHours(1)))
        .as("refresh token older than the configured max age is expired")
        .isTrue();
  }

  @Test
  void maxRefreshTokenAgeWithinCeilingIsNotExpired() {
    SessionRecord session = sessionMintedAgo(Duration.ofMinutes(10), null);

    assertThat(session.refreshTokenExpired(Duration.ofHours(1)))
        .as("refresh token younger than the configured max age is not expired")
        .isFalse();
  }

  @Test
  void unconfiguredMaxAgeFallsBackToIdpRefreshExpiry() {
    // maxRefreshTokenAge null -> behavior is exactly the IdP-only check.
    SessionRecord live = sessionWithRefreshExpiry(Instant.now().plusSeconds(60));
    SessionRecord expired = sessionWithRefreshExpiry(Instant.now().minusSeconds(1));
    SessionRecord noExpiry = sessionWithRefreshExpiry(null);

    assertThat(live.refreshTokenExpired(null)).isFalse();
    assertThat(expired.refreshTokenExpired(null)).isTrue();
    assertThat(noExpiry.refreshTokenExpired(null))
        .as("null IdP expiry + unconfigured max age -> never expired")
        .isFalse();
  }

  @Test
  void maxAgeCheckSkippedWhenRefreshMintedAtIsNull() {
    // Backward compatibility: an old session/fixture with no refreshMintedAt
    // deserializes fine and simply skips the age check even when configured.
    SessionRecord legacy = new SessionRecord(
        "access",
        "refresh",
        "id",
        Instant.now().plusSeconds(300),
        null, // no IdP refresh expiry
        Instant.now().minus(Duration.ofHours(13)),
        Instant.now().plus(Duration.ofHours(8)),
        null, // no refreshMintedAt (legacy)
        Map.of("sub", "alice"));

    assertThat(legacy.refreshTokenExpired(Duration.ofHours(1)))
        .as("missing refreshMintedAt skips the age check (back-compat)")
        .isFalse();
  }

  private static SessionRecord sessionWithRefreshExpiry(Instant refreshExpiresAt) {
    return new SessionRecord(
        "access",
        "refresh",
        "id",
        Instant.now().plusSeconds(300),
        refreshExpiresAt,
        Map.of("sub", "alice"));
  }

  // A session whose current refresh token was minted `mintedAgo` in the past,
  // with the given IdP refresh expiry (null = IdP omitted refresh_expires_in).
  private static SessionRecord sessionMintedAgo(Duration mintedAgo, Instant refreshExpiresAt) {
    Instant now = Instant.now();
    return new SessionRecord(
        "access",
        "refresh",
        "id",
        now.plusSeconds(300),
        refreshExpiresAt,
        now.minus(Duration.ofHours(1)),
        now.plus(Duration.ofHours(7)),
        now.minus(mintedAgo),
        Map.of("sub", "alice"));
  }
}
