package com.example.oidcreference.authservice;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.net.URI;
import java.time.Duration;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.slf4j.LoggerFactory;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.mock.env.MockEnvironment;

/**
 * Focused unit tests for the boot-time sentinel guard. Avoids @SpringBootTest
 * because the validator's behavior is entirely a function of properties +
 * Environment and we want fast, single-purpose assertions.
 */
@ExtendWith(OutputCaptureExtension.class)
class SecretSentinelValidatorTest {
  private static final String SENTINEL = "LOCAL_DEV_AUTH_CLIENT_SECRET__CHANGE_BEFORE_DEPLOY";
  private static final String COOKIE_KEY_SENTINEL = SecretSentinelValidator.DEV_COOKIE_SIGNING_KEY;
  private static final String REAL_KEY = "BASE64_REAL_KEY_AAAAAAAAAAAAAAAAAAAAAAAAAA=";

  @Test
  void refusesToStart_whenSentinelInUseUnderNoExplicitProfile() {
    // No active profile is NOT a local opt-in. A copied artifact run without an
    // explicit local/dev/test profile must FAIL CLOSED rather than ship a dev
    // sentinel with only a WARN (the unsafe-by-omission posture, SPEC-0002 D2).
    var props = properties(SENTINEL, REAL_KEY);
    var env = new MockEnvironment();  // no active profile
    assertThatThrownBy(() -> new SecretSentinelValidator(props, env).validateOnReady())
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("Refusing to run with default dev secrets");
  }

  @Test
  void warnsForCookieKeySentinel(CapturedOutput out) {
    var props = properties("real-client-secret", COOKIE_KEY_SENTINEL);
    var env = new MockEnvironment();
    env.setActiveProfiles("local");  // explicit local opt-in downgrades to WARN
    new SecretSentinelValidator(props, env).validateOnReady();
    assertThat(out.getOut()).contains(
        "APP_COOKIE_SIGNING_KEY is the local-dev sentinel");
  }

  @Test
  void silentWhenNoSentinelInUse(CapturedOutput out) {
    var props = properties("real-secret", REAL_KEY);
    new SecretSentinelValidator(props, new MockEnvironment()).validateOnReady();
    // No WARN about sentinels — the validator should be silent on this path.
    assertThat(out.getOut()).doesNotContain("local-dev sentinel");
  }

  @Test
  void cookieKeySentinelDetectedByLiteralMatch_notSubstring(CapturedOutput out) {
    // The cookie key sentinel is identified by exact value match, not by
    // a marker substring (unlike client secrets, which carry the literal
    // CHANGE_BEFORE_DEPLOY marker). A real base64 key that merely starts
    // with "AAAA" must NOT be flagged.
    var props = properties("real-secret", "AAAAAAAA-but-this-is-a-real-key-aaaaaaaaaaaa=");
    new SecretSentinelValidator(props, new MockEnvironment()).validateOnReady();
    assertThat(out.getOut()).doesNotContain("APP_COOKIE_SIGNING_KEY is the local-dev sentinel");
  }

  @Test
  void refusesToStartWhenSentinelMeetsProductionProfile() {
    var props = properties(SENTINEL, REAL_KEY);
    var env = new MockEnvironment();
    env.setActiveProfiles("prod");
    var validator = new SecretSentinelValidator(props, env);
    assertThatThrownBy(validator::validateOnReady)
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("Refusing to run with default dev secrets");
  }

  @Test
  void productionProfileLowercaseMatch() {
    var props = properties("real-secret", COOKIE_KEY_SENTINEL);
    var env = new MockEnvironment();
    env.setActiveProfiles("Production");
    assertThatThrownBy(() -> new SecretSentinelValidator(props, env).validateOnReady())
        .isInstanceOf(IllegalStateException.class);
  }

  @Test
  void refusesToStart_underAnyNonLocalNamedProfile_notJustProd() {
    // The guard must fail closed for ANY profile that is not an explicit
    // local-dev profile — staging/uat/etc. boot with the all-zeros dev key
    // otherwise, which is forgeable CSRF + tx-binding material.
    var props = properties(SENTINEL, REAL_KEY);
    var env = new MockEnvironment();
    env.setActiveProfiles("staging");
    assertThatThrownBy(() -> new SecretSentinelValidator(props, env).validateOnReady())
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("Refusing to run with default dev secrets");
  }

  @Test
  void refusesToStart_whenCookieKeyTooShort_underNonLocalProfile() {
    // A valid-base64 but sub-256-bit key is brute-forceable HMAC material.
    // "AAAA" decodes to 3 bytes. Must fail closed outside local dev.
    var props = properties("real-client-secret", "AAAA");
    var env = new MockEnvironment();
    env.setActiveProfiles("staging");
    assertThatThrownBy(() -> new SecretSentinelValidator(props, env).validateOnReady())
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("at least 32 bytes");
  }

  @Test
  void warnsButPasses_underExplicitLocalProfile() {
    // An explicit local-dev profile (local/dev/test) is allow-listed: the
    // sentinel warns but does not abort boot.
    var props = properties("real-secret", COOKIE_KEY_SENTINEL);
    var env = new MockEnvironment();
    env.setActiveProfiles("local");
    new SecretSentinelValidator(props, env).validateOnReady();
    // reached here without throwing — local profile must not fail closed
  }

  private static AuthProperties properties(String clientSecret, String cookieKey) {
    return new AuthProperties(
        "idp",
        "",                                       // base-url
        Duration.ofSeconds(60),
        Duration.ofSeconds(1800),
        Duration.ofSeconds(28800),
        URI.create("http://idp.example"),
        null,
        null,
        null,
        null,
        "oidc-reference-auth",
        clientSecret,
        Set.of("openid"),
        java.util.List.of("realm_access", "roles"),
        cookieKey,
        true,
        "oidc-reference-api-gateway",
        "oidc-reference-auth-internal");
  }

  @SuppressWarnings("unused")
  private static org.slf4j.Logger ensureRootLoggerInfo() {
    // Force ROOT logger to INFO so WARN passes through CapturedOutput in
    // environments where the test JVM defaults differ. Returning the
    // logger keeps the method live for use in fixtures, kept here as a
    // hook for future tests that need explicit log-level control.
    return LoggerFactory.getLogger("");
  }
}
