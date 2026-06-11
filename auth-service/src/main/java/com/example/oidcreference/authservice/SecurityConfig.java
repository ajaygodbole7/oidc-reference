package com.example.oidcreference.authservice;

import java.util.Collection;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.jwt.JwtClaimValidator;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoders;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter;

// Two filter chains:
//  /internal/** runs first (Order 1), OAuth Resource Server, JWT auth required.
//  /auth/**, fallthrough runs second (Order 2), STATELESS, permitAll —
//  CSRF, cookies, and session lifecycle are owned by AuthController.
@Configuration
class SecurityConfig {

  @Bean
  @Order(1)
  SecurityFilterChain internalSecurityFilterChain(HttpSecurity http, JwtDecoder internalJwtDecoder)
      throws Exception {
    return http
        .securityMatcher("/internal/**")
        .csrf(AbstractHttpConfigurer::disable)
        .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
        .authorizeHttpRequests(authorize -> authorize.anyRequest().authenticated())
        .oauth2ResourceServer(o -> o.jwt(jwt -> jwt.decoder(internalJwtDecoder)))
        .build();
  }

  @Bean
  @Order(2)
  SecurityFilterChain publicSecurityFilterChain(HttpSecurity http) throws Exception {
    return http
        .csrf(AbstractHttpConfigurer::disable)
        .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
        .authorizeHttpRequests(authorize -> authorize.anyRequest().permitAll())
        .headers(headers -> headers
            .contentTypeOptions(o -> {})
            .frameOptions(f -> f.deny())
            .referrerPolicy(r -> r.policy(ReferrerPolicyHeaderWriter.ReferrerPolicy.NO_REFERRER)))
        .build();
  }

  // Audience binding is enforced here (filter layer). InternalResolveController
  // re-asserts aud + azp/client_id defensively before doing any session work.
  // ConditionalOnMissingBean lets tests inject a stub JwtDecoder without the
  // prod bean racing to do an HTTP discovery call to the (mocked) issuer.
  @Bean
  @org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean
  JwtDecoder internalJwtDecoder(AuthProperties props) {
    NimbusJwtDecoder decoder = props.jwksUri() == null
        ? (NimbusJwtDecoder) JwtDecoders.fromIssuerLocation(props.issuerUri().toString())
        : NimbusJwtDecoder
            .withJwkSetUri(props.jwksUri().toString())
            .jwsAlgorithm(SignatureAlgorithm.RS256)
            .build();
    // Spring Security 6.x ships the building blocks we used to hand-roll:
    //   - JwtValidators.createDefaultWithIssuer covers iss + exp + nbf.
    //   - JwtClaimValidator wraps a per-claim predicate.
    //   - DelegatingOAuth2TokenValidator composes them and aggregates errors.
    // Spring's stack stays canonical so a future Spring Security bump picks
    // up upstream fixes (e.g., timestamp-skew handling) without us re-tracing.
    decoder.setJwtValidator(
        internalJwtValidator(props.issuerUri().toString(), props.internalAudience()));
    return decoder;
  }

  // internalAudience is parameterized (not a constant) so the configurable
  // value is enforced at the filter and unit-tested with a non-default audience
  // (SecurityConfigTest).
  static OAuth2TokenValidator<Jwt> internalJwtValidator(String issuerUri, String internalAudience) {
    OAuth2TokenValidator<Jwt> defaults = JwtValidators.createDefaultWithIssuer(issuerUri);
    OAuth2TokenValidator<Jwt> audience = new JwtClaimValidator<>(
        JwtClaimNames.AUD, aud -> hasInternalAudience(aud, internalAudience));
    return new DelegatingOAuth2TokenValidator<>(defaults, audience);
  }

  static boolean hasInternalAudience(Object aud, String expected) {
    if (aud instanceof String value) {
      return expected.equals(value);
    }
    if (aud instanceof Collection<?> values) {
      return values.stream().anyMatch(expected::equals);
    }
    return false;
  }
}
