package com.example.oidcreference.authservice;

import jakarta.annotation.PostConstruct;
import java.util.Base64;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;

/**
 * Refuses to ship known-dev or weak secrets to a non-local profile, and warns
 * when the sentinel values are in use at all.
 *
 * <p>The reference repo seeds three confidential-client secrets and one
 * cookie-signing key for zero-config local dev. Each default value contains
 * the marker {@value #SENTINEL_MARKER} so any text search across the realm
 * file, application.yml, compose.yaml, and scripts surfaces every place a
 * deployment must rotate before going live.
 *
 * <p>The guard fails closed: a sentinel secret, or a cookie-signing key that
 * decodes to fewer than {@value #MIN_COOKIE_KEY_BYTES} bytes, aborts boot under
 * <em>any</em> profile that is not an explicit local-dev profile
 * ({@link #LOCAL_PROFILES}, or no profile at all). Only those local profiles
 * downgrade the condition to a WARN. The check runs at bean initialization
 * ({@link PostConstruct}) so it aborts before the embedded web server begins
 * accepting traffic — not after, the way an ApplicationReadyEvent listener
 * would.
 */
@Component
class SecretSentinelValidator {
  static final String SENTINEL_MARKER = "CHANGE_BEFORE_DEPLOY";
  // Cookie-signing-key dev sentinel: 32 zero-bytes base64-encoded. Standard
  // base64 forbids the underscores in SENTINEL_MARKER, so the cookie key has
  // its own literal sentinel. Shared with api-gateway/plugins/bff-session.lua
  // so both processes detect the same dev key.
  static final String DEV_COOKIE_SIGNING_KEY = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
  // HmacSHA256 needs a full 256-bit (32-byte) key to resist brute force. A
  // shorter key is rejected outside local dev just like a sentinel.
  static final int MIN_COOKIE_KEY_BYTES = 32;
  // Profiles treated as inner-loop local dev. Anything else — staging, uat,
  // prod, or any custom environment name — is non-local and fails closed.
  private static final List<String> LOCAL_PROFILES = List.of("local", "dev", "test");
  private static final Logger log = LoggerFactory.getLogger(SecretSentinelValidator.class);

  private final AuthProperties props;
  private final Environment env;

  SecretSentinelValidator(AuthProperties props, Environment env) {
    this.props = props;
    this.env = env;
  }

  @PostConstruct
  void validateOnReady() {
    boolean clientSecretIsSentinel = containsSentinel(props.clientSecret());
    boolean cookieKeyIsSentinel = isDevCookieKey(props.cookieSigningKey());
    boolean cookieKeyTooShort = isCookieKeyTooShort(props.cookieSigningKey());

    if (!clientSecretIsSentinel && !cookieKeyIsSentinel && !cookieKeyTooShort) {
      return;
    }

    if (!isLocalProfile()) {
      // Fail-closed: only an explicit local-dev profile may run with dev or
      // weak secrets. The exception aborts bean initialization, so the web
      // server never starts and SpringApplication.run() exits non-zero.
      if (clientSecretIsSentinel || cookieKeyIsSentinel) {
        throw new IllegalStateException(
            "Refusing to run with default dev secrets outside a local profile. "
                + "Set AUTH_CLIENT_SECRET and APP_COOKIE_SIGNING_KEY explicitly.");
      }
      throw new IllegalStateException(
          "APP_COOKIE_SIGNING_KEY must decode to at least " + MIN_COOKIE_KEY_BYTES
              + " bytes (256-bit) for HmacSHA256; the configured key is shorter.");
    }

    if (clientSecretIsSentinel) {
      log.warn("AUTH_CLIENT_SECRET is the local-dev sentinel — replace before any non-local deploy.");
    }
    if (cookieKeyIsSentinel) {
      log.warn("APP_COOKIE_SIGNING_KEY is the local-dev sentinel — replace before any non-local deploy.");
    }
    if (cookieKeyTooShort && !cookieKeyIsSentinel) {
      log.warn(
          "APP_COOKIE_SIGNING_KEY decodes to fewer than {} bytes — weak HMAC key, replace before any non-local deploy.",
          MIN_COOKIE_KEY_BYTES);
    }
  }

  // Local when no profile is active (the inner-loop default) or every active
  // profile is in the local allow-list. Any other named profile is non-local.
  private boolean isLocalProfile() {
    String[] active = env.getActiveProfiles();
    if (active.length == 0) {
      return true;
    }
    for (String profile : active) {
      if (!LOCAL_PROFILES.contains(profile.toLowerCase())) {
        return false;
      }
    }
    return true;
  }

  private static boolean containsSentinel(String value) {
    return value != null && value.contains(SENTINEL_MARKER);
  }

  private static boolean isDevCookieKey(String value) {
    return DEV_COOKIE_SIGNING_KEY.equals(value);
  }

  // True only when the value is valid base64 that decodes to fewer than
  // MIN_COOKIE_KEY_BYTES. An unparseable value is left to SignedCsrfSupport's
  // runtime decode (which throws a clear "not valid Base64" error) rather than
  // misreported as a length problem here.
  private static boolean isCookieKeyTooShort(String value) {
    if (value == null) {
      return false;
    }
    try {
      return Base64.getDecoder().decode(value).length < MIN_COOKIE_KEY_BYTES;
    } catch (IllegalArgumentException e) {
      return false;
    }
  }
}
