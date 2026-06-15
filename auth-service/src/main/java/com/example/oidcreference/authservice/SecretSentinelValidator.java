package com.example.oidcreference.authservice;

import jakarta.annotation.PostConstruct;
import java.util.Base64;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;

/**
 * Boot-time fail-closed guard for unsafe-by-omission configuration. Refuses to
 * ship known-dev or weak secrets to a non-local profile (warning when sentinel
 * values are in use at all), and refuses to boot a non-local profile without an
 * explicit {@code app.base-url} so the public origin is never derived from
 * spoofable {@code X-Forwarded-*} headers.
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
 * ({@link #LOCAL_PROFILES}) — including when no profile is active at all, so a
 * copied artifact that forgets to set a profile cannot ship a dev sentinel with
 * only a WARN. Only an explicit local profile downgrades the condition to a
 * WARN. The check runs at bean initialization
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
    // An un-decodable cookie-signing key cannot be HmacSHA256 material — it would
    // throw at the first CSRF op in EVERY profile. Fail fast at boot, before the
    // web server starts, regardless of profile (the dev sentinel is valid base64,
    // so local dev is unaffected; only a genuinely malformed key trips this).
    if (isInvalidBase64(props.cookieSigningKey())) {
      throw new IllegalStateException(
          "APP_COOKIE_SIGNING_KEY is not valid base64 and cannot be used as an "
              + "HmacSHA256 key. Set a base64-encoded 256-bit key.");
    }

    // Public-origin trust anchor. Outside a local profile, app.base-url MUST name
    // the public-facing origin. When it is blank, AuthController.baseUrl() falls
    // back to deriving the origin — and the secure-cookie / __Host-sid decision —
    // from X-Forwarded-Host / X-Forwarded-Proto, which any client can spoof. That
    // fallback is the inner-loop dev convenience; in a real deployment it is a
    // Host-header-injection footgun regardless of which gateway or IdP sits in
    // front. Fail closed so a copied artifact cannot ship header-derived origin
    // resolution simply by forgetting APP_BASE_URL (SECURITY.md §D-1 —
    // unsafe-by-omission). This is environment-portable hardening: it does not
    // assume the reference gateway, only that prod must not trust forwarded
    // headers for the origin.
    if (!isLocalProfile() && isBlank(props.baseUrl())) {
      throw new IllegalStateException(
          "APP_BASE_URL must be set to the public-facing origin outside a local "
              + "profile. Without it the OAuth redirect_uri and the secure-cookie "
              + "decision are derived from spoofable X-Forwarded-* headers.");
    }

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

  // Local ONLY when at least one profile is active and every active profile is
  // in the local allow-list. No active profile is NOT local: a copied artifact
  // run without an explicit local/dev/test opt-in must fail closed rather than
  // ship a dev sentinel with only a WARN (SECURITY.md §D-1 — unsafe-by-omission).
  private boolean isLocalProfile() {
    String[] active = env.getActiveProfiles();
    if (active.length == 0) {
      return false;
    }
    for (String profile : active) {
      if (!LOCAL_PROFILES.contains(profile.toLowerCase())) {
        return false;
      }
    }
    return true;
  }

  private static boolean isBlank(String value) {
    return value == null || value.isBlank();
  }

  private static boolean containsSentinel(String value) {
    return value != null && value.contains(SENTINEL_MARKER);
  }

  private static boolean isDevCookieKey(String value) {
    return DEV_COOKIE_SIGNING_KEY.equals(value);
  }

  // True only when the value is valid base64 that decodes to fewer than
  // MIN_COOKIE_KEY_BYTES. An unparseable value is handled earlier (validateOnReady
  // fails boot via isInvalidBase64), so it never reaches here as a length problem.
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

  // A non-empty value that the base64 decoder rejects. Null/empty is left to the
  // required-property machinery, not flagged as malformed base64 here.
  private static boolean isInvalidBase64(String value) {
    if (value == null || value.isEmpty()) {
      return false;
    }
    try {
      Base64.getDecoder().decode(value);
      return false;
    } catch (IllegalArgumentException e) {
      return true;
    }
  }
}
