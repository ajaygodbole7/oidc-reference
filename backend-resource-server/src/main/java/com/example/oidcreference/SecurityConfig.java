package com.example.oidcreference;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
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
            .requestMatchers("/actuator/**").permitAll()
            .requestMatchers("/api/public").permitAll()
            .requestMatchers("/api/me").authenticated()
            .requestMatchers("/api/user-data").hasAuthority("SCOPE_api.read")
            .requestMatchers("/api/admin").hasAuthority("ROLE_admin")
            .requestMatchers("/api/jobs").hasAuthority("SCOPE_service.jobs")
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
      @Value("${app.audience}") String requiredAudience) {
    NimbusJwtDecoder decoder = NimbusJwtDecoder
        .withIssuerLocation(issuerUri)
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
    OAuth2TokenValidator<Jwt> audienceValidator = new JwtClaimValidator<List<String>>(
        JwtClaimNames.AUD,
        aud -> aud != null && aud.contains(audience));
    return new DelegatingOAuth2TokenValidator<>(defaults, audienceValidator);
  }

  // Maps Keycloak's `scope` claim → SCOPE_* and `realm_access.roles` → ROLE_*.
  @Bean
  JwtAuthenticationConverter jwtAuthenticationConverter() {
    JwtGrantedAuthoritiesConverter scopes = new JwtGrantedAuthoritiesConverter();
    scopes.setAuthorityPrefix("SCOPE_");
    scopes.setAuthoritiesClaimName("scope");
    JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
    converter.setJwtGrantedAuthoritiesConverter(jwt -> {
      Collection<GrantedAuthority> all = new ArrayList<>(scopes.convert(jwt));
      Map<String, Object> realmAccess = jwt.getClaimAsMap("realm_access");
      if (realmAccess != null && realmAccess.get("roles") instanceof Collection<?> roles) {
        for (Object role : roles) {
          all.add(new SimpleGrantedAuthority("ROLE_" + role));
        }
      }
      return all;
    });
    return converter;
  }

  @Bean
  AuthenticationEntryPoint authenticationEntryPoint() {
    return (request, response, ex) -> {
      logSecurityAudit(request, HttpStatus.UNAUTHORIZED, "authentication_required");
      writeProblem(response, HttpStatus.UNAUTHORIZED, "Unauthorized",
        "Authentication is required to access this resource.");
    };
  }

  @Bean
  AccessDeniedHandler accessDeniedHandler() {
    return (request, response, ex) -> {
      logSecurityAudit(request, HttpStatus.FORBIDDEN, "insufficient_authority");
      writeProblem(response, HttpStatus.FORBIDDEN, "Forbidden",
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

  private static void writeProblem(
      HttpServletResponse response,
      HttpStatus status, String title, String detail) throws IOException {
    response.setStatus(status.value());
    response.setContentType(MediaType.APPLICATION_PROBLEM_JSON_VALUE);
    response.getWriter().write(
        "{\"type\":\"about:blank\",\"title\":\"%s\",\"status\":%d,\"detail\":\"%s\"}"
        .formatted(
            escapeJson(title),
            status.value(),
            escapeJson(detail)));
  }

  private static String escapeJson(String value) {
    return value.replace("\\", "\\\\").replace("\"", "\\\"");
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
