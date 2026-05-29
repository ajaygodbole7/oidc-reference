package com.example.oidcreference.authservice;

import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;

/**
 * Refuses to ship known-dev secrets to a non-dev profile, and warns when the
 * sentinel values are in use at all.
 *
 * <p>The reference repo seeds three confidential-client secrets and one
 * cookie-signing key for zero-config local dev. Each default value contains
 * the marker {@value #SENTINEL_MARKER} so any text search across the realm
 * file, application.yml, compose.yaml, and scripts surfaces every place a
 * deployment must rotate before going live. If the Spring active profiles
 * contain any of {@link #PRODUCTION_PROFILES} while a sentinel is in use,
 * the application fails to start.
 */
@Component
class SecretSentinelValidator {
  static final String SENTINEL_MARKER = "CHANGE_BEFORE_DEPLOY";
  // Cookie-signing-key dev sentinel: 32 zero-bytes base64-encoded. Standard
  // base64 forbids the underscores in SENTINEL_MARKER, so the cookie key has
  // its own literal sentinel. Shared with api-gateway/plugins/bff-session.lua
  // so both processes detect the same dev key.
  static final String DEV_COOKIE_SIGNING_KEY = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
  private static final List<String> PRODUCTION_PROFILES = List.of("prod", "production");
  private static final Logger log = LoggerFactory.getLogger(SecretSentinelValidator.class);

  private final AuthProperties props;
  private final Environment env;

  SecretSentinelValidator(AuthProperties props, Environment env) {
    this.props = props;
    this.env = env;
  }

  @EventListener(ApplicationReadyEvent.class)
  void validateOnReady() {
    boolean clientSecretIsSentinel = containsSentinel(props.clientSecret());
    boolean cookieKeyIsSentinel = isDevCookieKey(props.cookieSigningKey());
    if (!clientSecretIsSentinel && !cookieKeyIsSentinel) {
      return;
    }
    if (isProductionProfile()) {
      // Fail-closed: a production profile must never see a sentinel secret.
      // The exception bubbles out of the ApplicationReadyEvent listener and
      // the SpringApplication.run() main loop exits non-zero.
      throw new IllegalStateException(
          "Refusing to run with default dev secrets in a production profile. "
              + "Set AUTH_CLIENT_SECRET and APP_COOKIE_SIGNING_KEY explicitly.");
    }
    if (clientSecretIsSentinel) {
      log.warn("AUTH_CLIENT_SECRET is the local-dev sentinel — replace before any non-local deploy.");
    }
    if (cookieKeyIsSentinel) {
      log.warn("APP_COOKIE_SIGNING_KEY is the local-dev sentinel — replace before any non-local deploy.");
    }
  }

  private boolean isProductionProfile() {
    for (String active : env.getActiveProfiles()) {
      if (PRODUCTION_PROFILES.contains(active.toLowerCase())) {
        return true;
      }
    }
    return false;
  }

  private static boolean containsSentinel(String value) {
    return value != null && value.contains(SENTINEL_MARKER);
  }

  private static boolean isDevCookieKey(String value) {
    return DEV_COOKIE_SIGNING_KEY.equals(value);
  }
}
