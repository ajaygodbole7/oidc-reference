package com.example.oidcreference.authservice;

import java.util.List;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
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
  private static final String INTERNAL_AUDIENCE = "oidc-reference-auth-internal";

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

  // Audience binding is enforced here (filter layer). InternalRefreshController
  // re-asserts aud + azp/client_id defensively before doing any session work.
  // ConditionalOnMissingBean lets tests inject a stub JwtDecoder without the
  // prod bean racing to do an HTTP discovery call to the (mocked) issuer.
  @Bean
  @org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean
  JwtDecoder internalJwtDecoder(AuthProperties props) {
    NimbusJwtDecoder decoder =
        (NimbusJwtDecoder) JwtDecoders.fromIssuerLocation(props.issuerUri().toString());
    // Spring Security 6.x ships the building blocks we used to hand-roll:
    //   - JwtValidators.createDefaultWithIssuer covers iss + exp + nbf.
    //   - JwtClaimValidator wraps a per-claim predicate.
    //   - DelegatingOAuth2TokenValidator composes them and aggregates errors.
    // Spring's stack stays canonical so a future Spring Security bump picks
    // up upstream fixes (e.g., timestamp-skew handling) without us re-tracing.
    OAuth2TokenValidator<Jwt> defaults =
        JwtValidators.createDefaultWithIssuer(props.issuerUri().toString());
    OAuth2TokenValidator<Jwt> audience = new JwtClaimValidator<List<String>>(
        JwtClaimNames.AUD,
        aud -> aud != null && aud.contains(INTERNAL_AUDIENCE));
    decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(defaults, audience));
    return decoder;
  }
}
