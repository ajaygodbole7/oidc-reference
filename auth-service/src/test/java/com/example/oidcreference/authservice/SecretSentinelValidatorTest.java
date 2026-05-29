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
  void warnsButPasses_whenSentinelInUseUnderNoExplicitProfile(CapturedOutput out) {
    var props = properties(SENTINEL, REAL_KEY);
    var env = new MockEnvironment();  // no active profile
    new SecretSentinelValidator(props, env).validateOnReady();
    assertThat(out.getOut()).contains(
        "AUTH_CLIENT_SECRET is the local-dev sentinel");
  }

  @Test
  void warnsForCookieKeySentinel(CapturedOutput out) {
    var props = properties("real-client-secret", COOKIE_KEY_SENTINEL);
    new SecretSentinelValidator(props, new MockEnvironment()).validateOnReady();
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

  private static AuthProperties properties(String clientSecret, String cookieKey) {
    return new AuthProperties(
        "idp",
        "",                                       // base-url
        Duration.ofSeconds(60),
        URI.create("http://idp.example"),
        "oidc-reference-auth",
        clientSecret,
        Set.of("openid"),
        java.util.List.of("realm_access", "roles"),
        cookieKey,
        true);
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
