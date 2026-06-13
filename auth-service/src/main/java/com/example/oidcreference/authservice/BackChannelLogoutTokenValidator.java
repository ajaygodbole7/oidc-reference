package com.example.oidcreference.authservice;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.JWKSourceBuilder;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.Map;
import java.util.Optional;
import org.jspecify.annotations.Nullable;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.stereotype.Component;

@Component
class BackChannelLogoutTokenValidator {
  static final String LOGOUT_EVENT =
      "http://schemas.openid.net/event/backchannel-logout";
  private static final JOSEObjectType LOGOUT_JWT_TYPE = new JOSEObjectType("logout+jwt");
  private static final Duration MAX_IAT_AGE = Duration.ofMinutes(5);
  private static final Duration CLOCK_SKEW = Duration.ofSeconds(60);

  private final DefaultJWTProcessor<SecurityContext> processor;
  private final OidcProviderMetadata md;
  private final Clock clock;

  @Autowired
  BackChannelLogoutTokenValidator(OidcProviderMetadata md) {
    this(md, Clock.systemUTC(), jwksProcessor(md));
  }

  BackChannelLogoutTokenValidator(
      OidcProviderMetadata md, Clock clock, DefaultJWTProcessor<SecurityContext> processor) {
    this.md = md;
    this.clock = clock;
    this.processor = processor;
  }

  LogoutToken validate(String serialized) {
    try {
      JWTClaimsSet claims = processor.process(serialized, null);
      requireIssuer(claims);
      requireAudience(claims);
      requireFreshIat(claims);
      requireLogoutEvent(claims);
      rejectNonce(claims);
      String jti = stringClaim(claims, "jti")
          .orElseThrow(() -> new BadCredentialsException("logout_token missing jti"));
      String sub = stringClaim(claims, "sub").orElse(null);
      String sid = stringClaim(claims, "sid").orElse(null);
      if ((sub == null || sub.isBlank()) && (sid == null || sid.isBlank())) {
        throw new BadCredentialsException("logout_token missing sub/sid");
      }
      return new LogoutToken(sub, sid, jti);
    } catch (BadCredentialsException e) {
      throw e;
    } catch (Exception e) {
      throw new BadCredentialsException("logout_token validation failed: " + e.getMessage(), e);
    }
  }

  private void requireIssuer(JWTClaimsSet claims) {
    if (!md.issuer().equals(claims.getIssuer())) {
      throw new BadCredentialsException("logout_token issuer mismatch");
    }
  }

  private void requireAudience(JWTClaimsSet claims) {
    if (!claims.getAudience().contains(md.clientId())) {
      throw new BadCredentialsException("logout_token audience mismatch");
    }
  }

  static void verifyLogoutJwtType(JOSEObjectType type, SecurityContext context)
      throws BadJOSEException {
    if (JOSEObjectType.JWT.equals(type) || LOGOUT_JWT_TYPE.equals(type)) {
      return;
    }
    throw new BadJOSEException("JOSE header typ (type) " + type + " not allowed");
  }

  private void requireFreshIat(JWTClaimsSet claims) {
    Date issued = claims.getIssueTime();
    if (issued == null) {
      throw new BadCredentialsException("logout_token missing iat");
    }
    Instant iat = issued.toInstant();
    Instant now = clock.instant();
    if (iat.isBefore(now.minus(MAX_IAT_AGE)) || iat.isAfter(now.plus(CLOCK_SKEW))) {
      throw new BadCredentialsException("logout_token stale iat");
    }
  }

  private void requireLogoutEvent(JWTClaimsSet claims) {
    Object events = claims.getClaim("events");
    if (!(events instanceof Map<?, ?> map) || !(map.get(LOGOUT_EVENT) instanceof Map<?, ?>)) {
      throw new BadCredentialsException("logout_token missing logout event");
    }
  }

  private void rejectNonce(JWTClaimsSet claims) {
    if (claims.getClaim("nonce") != null) {
      throw new BadCredentialsException("logout_token must not contain nonce");
    }
  }

  private static Optional<String> stringClaim(JWTClaimsSet claims, String name) {
    Object value = claims.getClaim(name);
    if (!(value instanceof String stringValue) || stringValue.isBlank()) {
      return Optional.empty();
    }
    return Optional.of(stringValue);
  }

  private static DefaultJWTProcessor<SecurityContext> jwksProcessor(OidcProviderMetadata md) {
    try {
      JWKSource<SecurityContext> jwks = JWKSourceBuilder
          .create(md.jwksUri().toURL())
          .retrying(true)
          .rateLimited(60_000L)
          .cache(600_000L, 15_000L)
          .refreshAheadCache(300_000L, true)
          .outageTolerant(900_000L)
          .build();
      JWSKeySelector<SecurityContext> keySelector =
          new JWSVerificationKeySelector<>(JWSAlgorithm.RS256, jwks);
      DefaultJWTProcessor<SecurityContext> processor = new DefaultJWTProcessor<>();
      processor.setJWSTypeVerifier(BackChannelLogoutTokenValidator::verifyLogoutJwtType);
      processor.setJWSKeySelector(keySelector);
      return processor;
    } catch (Exception e) {
      throw new IllegalStateException("Failed to initialize logout_token validator", e);
    }
  }

  // A logout_token carries sub, sid, or both (validate() rejects neither);
  // each is individually nullable.
  record LogoutToken(@Nullable String sub, @Nullable String sid, String jti) {}
}
