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
        Map.of("sub", "alice"),
        "xsrf");

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

  private static SessionRecord sessionWithRefreshExpiry(Instant refreshExpiresAt) {
    return new SessionRecord(
        "access",
        "refresh",
        "id",
        Instant.now().plusSeconds(300),
        refreshExpiresAt,
        Map.of("sub", "alice"),
        "xsrf");
  }
}
