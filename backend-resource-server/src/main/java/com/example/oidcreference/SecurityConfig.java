package com.example.oidcreference;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ProblemDetail;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.jwt.JwtClaimValidator;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import tools.jackson.databind.ObjectMapper;

@Configuration
class SecurityConfig {
  private static final Logger SECURITY_AUDIT = LoggerFactory.getLogger("security.audit");

  // Browser never reaches the Resource Server directly. CORS is denied for
  // browser origins as defense in depth; the BFF proxies on /api/**.
  @Bean
  SecurityFilterChain securityFilterChain(
      HttpSecurity http,
      JwtAuthenticationConverter jwtAuthenticationConverter,
      AuthenticationEntryPoint authenticationEntryPoint,
      AccessDeniedHandler accessDeniedHandler) throws Exception {
    return http
        .csrf(AbstractHttpConfigurer::disable)
        .cors(Customizer.withDefaults())
        .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
        .authorizeHttpRequests(authorize -> authorize
            // A user-defined SecurityFilterChain governs ALL ports, including
            // the dedicated localhost management port (9082) — Boot does not
            // give actuator its own chain once this bean exists. The container
            // health probe (curl :9082/actuator/health) needs an unauthenticated
            // path, so /actuator/health (+ its k8s liveness/readiness sub-probes)
            // is permitted HERE. Scope it to health ONLY: metrics/prometheus/info
            // fall through to anyRequest().denyAll() and require auth, so no
            // operational data is served unauthenticated even if the
            // loopback-only management port is ever published. health
            // show-details=when-authorized keeps the permitted body a terse
            // UP/DOWN.
            .requestMatchers("/actuator/health", "/actuator/health/**").permitAll()
            .requestMatchers("/api/public").permitAll()
            .requestMatchers("/api/me").authenticated()
            .requestMatchers("/api/user-data").hasAuthority("SCOPE_api.read")
            .requestMatchers("/api/admin").hasAuthority("ROLE_admin")
            .requestMatchers("/api/jobs").hasAuthority("SCOPE_service.jobs")
            .requestMatchers("/api/_test/echo").authenticated()
            .anyRequest().denyAll())
        .oauth2ResourceServer(o -> o
            .jwt(jwt -> jwt.jwtAuthenticationConverter(jwtAuthenticationConverter))
            .authenticationEntryPoint(authenticationEntryPoint)
            .accessDeniedHandler(accessDeniedHandler))
        .exceptionHandling(e -> e
            .authenticationEntryPoint(authenticationEntryPoint)
            .accessDeniedHandler(accessDeniedHandler))
        .build();
  }

  @Bean
  JwtDecoder jwtDecoder(
      @Value("${spring.security.oauth2.resourceserver.jwt.issuer-uri}") String issuerUri,
      @Value("${spring.security.oauth2.resourceserver.jwt.jwk-set-uri:}") String jwkSetUri,
      AppProperties properties) {
    String requiredAudience = properties.audience();
    NimbusJwtDecoder decoder = jwkSetUri == null || jwkSetUri.isBlank()
        ? NimbusJwtDecoder
            .withIssuerLocation(issuerUri)
            .jwsAlgorithm(SignatureAlgorithm.RS256)
            .build()
        : NimbusJwtDecoder
            .withJwkSetUri(jwkSetUri)
            .jwsAlgorithm(SignatureAlgorithm.RS256)
            .build();
    decoder.setJwtValidator(jwtValidator(issuerUri, requiredAudience));
    return decoder;
  }

  // Package-private so negative-path unit tests can exercise the exact same
  // validator chain the production decoder uses (issuer + default exp/iat/nbf
  // + required-audience). Keeps the prod path and the test path in lockstep:
  // if a validator is added here, the negative suite picks it up for free.
  static OAuth2TokenValidator<Jwt> jwtValidator(String issuerUri, String audience) {
    OAuth2TokenValidator<Jwt> defaults = JwtValidators.createDefaultWithIssuer(issuerUri);
    OAuth2TokenValidator<Jwt> audienceValidator = new JwtClaimValidator<Object>(
        JwtClaimNames.AUD,
        aud -> hasAudience(aud, audience));
    // RFC 9068 §2.1 RECOMMENDS access tokens carry typ=at+JWT, and a typ-header
    // validator would be defense-in-depth. It is deliberately NOT added:
    // the threat it guards — an ID token presented as an access token — is
    // already blocked here by the audience pin, because this realm's ID tokens
    // carry aud=oidc-reference-auth while access tokens carry the configured API
    // audience. Adding a strict typ=at+JWT check would also require reconfiguring
    // Keycloak to emit at+JWT (it sends typ=JWT by default), or the RS would 401
    // every token. The audience pin is the load-bearing control; typ validation
    // is a deliberate non-goal (see OIDC-compliance.md / production-hardening.md).
    return new DelegatingOAuth2TokenValidator<>(defaults, audienceValidator);
  }

  private static boolean hasAudience(Object aud, String audience) {
    if (aud instanceof String value) {
      return audience.equals(value);
    }
    if (aud instanceof Collection<?> values) {
      return values.stream().anyMatch(audience::equals);
    }
    return false;
  }

  @Bean
  JwtAuthenticationConverter jwtAuthenticationConverter(AppProperties properties) {
    return jwtAuthenticationConverter(properties.rolesClaimPath());
  }

  // Maps standard `scope` / `scp` claims -> SCOPE_* and the configured
  // roles claim path -> ROLE_*. Package-private (not a @Bean) so a unit test
  // can exercise it directly with an explicit claim path.
  JwtAuthenticationConverter jwtAuthenticationConverter(List<String> rolesClaimPath) {
    JwtGrantedAuthoritiesConverter scopes = new JwtGrantedAuthoritiesConverter();
    scopes.setAuthorityPrefix("SCOPE_");
    JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
    converter.setJwtGrantedAuthoritiesConverter(jwt -> {
      Collection<GrantedAuthority> all = new ArrayList<>(scopes.convert(jwt));
      Object claim = nestedClaim(jwt.getClaims(), rolesClaimPath);
      if (claim instanceof Collection<?> roles) {
        for (Object role : roles) {
          if (role != null && !role.toString().isBlank()) {
            all.add(new SimpleGrantedAuthority("ROLE_" + role));
          }
        }
      }
      return all;
    });
    return converter;
  }

  // Returns null when the path doesn't resolve (a missing or non-map segment) —
  // callers null-tolerate via `instanceof Collection`.
  private static @Nullable Object nestedClaim(Map<String, Object> claims, List<String> path) {
    Object current = claims;
    for (String segment : path) {
      if (!(current instanceof Map<?, ?> map)) {
        return null;
      }
      current = map.get(segment);
    }
    return current;
  }

  @Bean
  AuthenticationEntryPoint authenticationEntryPoint(ObjectMapper objectMapper) {
    return (request, response, ex) -> {
      logSecurityAudit(request, HttpStatus.UNAUTHORIZED, "authentication_required");
      // RFC 6750 §3: a 401 from a protected resource MUST include a Bearer
      // WWW-Authenticate challenge. Replacing Spring's
      // BearerTokenAuthenticationEntryPoint with a problem+json body dropped
      // it; restore it alongside the JSON body. §3.1: only name an error code
      // when a (bad) token was actually presented — a request with no
      // credentials gets the bare challenge so we don't signal what was
      // expected. A failed bearer decode surfaces as OAuth2AuthenticationException
      // (e.g. InvalidBearerTokenException) carrying the RFC error code.
      String challenge = "Bearer";
      if (ex instanceof org.springframework.security.oauth2.core.OAuth2AuthenticationException oae) {
        challenge = "Bearer error=\"" + oae.getError().getErrorCode() + "\"";
      }
      response.setHeader(org.springframework.http.HttpHeaders.WWW_AUTHENTICATE, challenge);
      writeProblem(response, objectMapper, HttpStatus.UNAUTHORIZED, "Unauthorized",
        "Authentication is required to access this resource.");
    };
  }

  @Bean
  AccessDeniedHandler accessDeniedHandler(ObjectMapper objectMapper) {
    return (request, response, ex) -> {
      logSecurityAudit(request, HttpStatus.FORBIDDEN, "insufficient_authority");
      // RFC 6750 §3.1: a 403 for an authenticated-but-underscoped token
      // challenges with error="insufficient_scope".
      response.setHeader(org.springframework.http.HttpHeaders.WWW_AUTHENTICATE,
          "Bearer error=\"insufficient_scope\"");
      writeProblem(response, objectMapper, HttpStatus.FORBIDDEN, "Forbidden",
        "Access denied: the token does not include the required scope or role.");
    };
  }

  private static void logSecurityAudit(
      HttpServletRequest request,
      HttpStatus status,
      String reason) {
    SECURITY_AUDIT.info(
        "security_audit event=access_denied status={} method={} path={} reason={} remote={}",
        status.value(),
        request.getMethod(),
        request.getRequestURI(),
        reason,
        request.getRemoteAddr());
  }

  // Body via Spring's ProblemDetail serialized with the Boot ObjectMapper
  // (the idiom the auth-service already uses), instead of hand-rolled JSON.
  // The WWW-Authenticate challenge is set by the caller and stays
  // byte-controlled — only the body construction moved here.
  private static void writeProblem(
      HttpServletResponse response,
      ObjectMapper objectMapper,
      HttpStatus status, String title, String detail) throws IOException {
    ProblemDetail problem = ProblemDetail.forStatusAndDetail(status, detail);
    problem.setTitle(title);
    response.setStatus(status.value());
    response.setContentType(MediaType.APPLICATION_PROBLEM_JSON_VALUE);
    response.getWriter().write(objectMapper.writeValueAsString(problem));
  }

  @Bean
  CorsConfigurationSource corsConfigurationSource() {
    CorsConfiguration denyBrowserOrigins = new CorsConfiguration();
    denyBrowserOrigins.setAllowedOrigins(List.of());
    denyBrowserOrigins.setAllowedMethods(List.of());
    UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
    source.registerCorsConfiguration("/api/**", denyBrowserOrigins);
    return source;
  }
}
