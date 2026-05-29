package com.example.oidcreference.authservice;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import com.fasterxml.jackson.annotation.JsonProperty;

// Field names on the wire MUST match SPEC-0001 §7.2 (sess:{sid} schema
// contract). The Auth Service is the sole writer; the API Gateway is a
// tolerant reader that depends on `access_token` and
// `access_token_expires_at` exactly. We pin each wire name with
// @JsonProperty so a Java-side rename can't silently break the contract.
// The Java fields stay camelCase for readability.
record SessionRecord(
    @JsonProperty("access_token") String accessToken,
    @JsonProperty("refresh_token") String refreshToken,
    @JsonProperty("id_token") String idToken,
    @JsonProperty("access_token_expires_at") Instant expiresAt,
    @JsonProperty("refresh_token_expires_at") Instant refreshExpiresAt,
    @JsonProperty("created_at") Instant createdAt,
    @JsonProperty("absolute_expires_at") Instant absoluteExpiresAt,
    @JsonProperty("claims") Map<String, Object> claims,
    @JsonProperty("xsrf_token") String xsrfToken) {
  private static final Duration ABSOLUTE_TTL = Duration.ofHours(12);
  // Sliding TTL applied to sess:{sid} on every read. Capped by
  // absoluteExpiresAt so the hard 12h ceiling can't be extended past
  // its construction-time value via repeated access. This used to live
  // in both AuthController and InternalRefreshController; consolidating
  // here so a future TTL change happens once.
  static final Duration SESSION_IDLE_TTL = Duration.ofMinutes(30);

  SessionRecord(
      String accessToken,
      String refreshToken,
      String idToken,
      Instant expiresAt,
      Instant refreshExpiresAt,
      Map<String, Object> claims,
      String xsrfToken) {
    this(
        accessToken,
        refreshToken,
        idToken,
        expiresAt,
        refreshExpiresAt,
        Instant.now(),
        Instant.now().plus(ABSOLUTE_TTL),
        claims,
        xsrfToken);
  }

  /**
   * @param refreshWindow how far before {@link #expiresAt} a refresh should
   *     be triggered; configured via {@code app.session-refresh-window}.
   */
  boolean requiresRefresh(Duration refreshWindow) {
    return expiresAt.isBefore(Instant.now().plus(refreshWindow));
  }

  boolean absoluteExpired() {
    return !absoluteExpiresAt.isAfter(Instant.now());
  }

  /**
   * Sliding idle TTL for the next state-store write/extend, capped by
   * the absolute ceiling. Returns {@link Duration#ZERO} when the
   * absolute TTL has elapsed — callers MUST treat ZERO as "evict the
   * key" (a {@code SET ... EX 0} or {@code EXPIRE key 0} both delete
   * the key, never extend it).
   */
  Duration nextTtl() {
    var remainingAbsolute = Duration.between(Instant.now(), absoluteExpiresAt);
    if (remainingAbsolute.isNegative() || remainingAbsolute.isZero()) {
      return Duration.ZERO;
    }
    return remainingAbsolute.compareTo(SESSION_IDLE_TTL) < 0
        ? remainingAbsolute
        : SESSION_IDLE_TTL;
  }
}
