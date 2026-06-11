package com.example.oidcreference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.junit.jupiter.api.extension.ExtendWith;

@SpringBootTest
@AutoConfigureMockMvc
@ExtendWith(OutputCaptureExtension.class)
class ApiSecurityTest {

  // Replaces the production JwtDecoder bean before context creation, so the
  // bean factory does not try to fetch Keycloak discovery during tests.
  // The `jwt()` request post-processor bypasses real decoding entirely.
  @MockitoBean
  private JwtDecoder jwtDecoder;

  @Autowired
  private MockMvc mockMvc;

  @Test
  void publicEndpointAllowsAnonymousRequests() throws Exception {
    mockMvc.perform(get("/api/public")).andExpect(status().isOk());
  }

  @Test
  void actuatorHealthIsPermittedButOtherActuatorEndpointsRequireAuth() throws Exception {
    // A user-defined SecurityFilterChain governs the management port too, so
    // authorization for actuator is decided in SecurityConfig. /actuator/health
    // must be reachable unauthenticated for the loopback health probe — on the
    // main (8082) MockMvc context the endpoint isn't mapped, so a PERMITTED
    // request surfaces as 404 (no handler), NOT 401 (denied). metrics/prometheus
    // must NOT be blanket-permitted: they fall through to anyRequest().denyAll()
    // and return 401, so no operational data is served unauthenticated even if
    // the management port is ever published. (Regression guard for the
    // healthcheck-breaking over-removal AND the over-broad /actuator/** permit.)
    mockMvc.perform(get("/actuator/health")).andExpect(status().isNotFound());
    mockMvc.perform(get("/actuator/health/liveness")).andExpect(status().isNotFound());
    mockMvc.perform(get("/actuator/metrics")).andExpect(status().isUnauthorized());
    mockMvc.perform(get("/actuator/prometheus")).andExpect(status().isUnauthorized());
  }

  @Test
  void gatewayEchoEndpointIsAbsentWithoutGatewayTestProfile() throws Exception {
    mockMvc.perform(get("/api/_test/echo").with(jwt()))
        .andExpect(status().isNotFound());
  }

  @Test
  void protectedEndpointReturnsProblemJsonOnMissingToken() throws Exception {
    mockMvc.perform(get("/api/me"))
        .andExpect(status().isUnauthorized())
        .andExpect(content().contentType(MediaType.APPLICATION_PROBLEM_JSON));
  }

  @Test
  void missingTokenEmitsSecurityAuditEvent(CapturedOutput output) throws Exception {
    mockMvc.perform(get("/api/me"))
        .andExpect(status().isUnauthorized());

    assertThat(output).contains(
        "security_audit event=access_denied status=401 method=GET path=/api/me reason=authentication_required");
  }

  @Test
  void missingTokenChallengesWithBareBearer() throws Exception {
    // RFC 6750 §3: a 401 from a protected resource MUST carry a Bearer
    // WWW-Authenticate challenge. §3.1: with NO credentials presented, the
    // challenge must NOT name an error code (don't signal what was expected).
    mockMvc.perform(get("/api/me"))
        .andExpect(status().isUnauthorized())
        .andExpect(header().string("WWW-Authenticate", "Bearer"));
  }

  @Test
  void invalidTokenChallengesWithInvalidTokenError() throws Exception {
    // RFC 6750 §3.1: a malformed/expired bearer token yields
    // error="invalid_token" in the challenge so the caller can distinguish it
    // from a missing token.
    org.mockito.Mockito.when(jwtDecoder.decode("bad-token"))
        .thenThrow(new org.springframework.security.oauth2.jwt.BadJwtException("expired"));

    mockMvc.perform(get("/api/me").header("Authorization", "Bearer bad-token"))
        .andExpect(status().isUnauthorized())
        .andExpect(header().string("WWW-Authenticate",
            org.hamcrest.Matchers.containsString("error=\"invalid_token\"")));
  }

  @Test
  void insufficientScopeChallengesWithInsufficientScopeError() throws Exception {
    // RFC 6750 §3.1: a 403 for an authenticated-but-underscoped token MUST
    // challenge with error="insufficient_scope".
    mockMvc.perform(get("/api/user-data").with(jwt()))
        .andExpect(status().isForbidden())
        .andExpect(header().string("WWW-Authenticate",
            org.hamcrest.Matchers.containsString("error=\"insufficient_scope\"")));
  }

  @Test
  void meSucceedsWithAuthenticatedJwt() throws Exception {
    mockMvc.perform(get("/api/me")
            .with(jwt().jwt(j -> j.claim("preferred_username", "alice"))))
        .andExpect(status().isOk());
  }

  @Test
  void meRejectsServiceAccountTokenWithoutUserIdentity() throws Exception {
    mockMvc.perform(get("/api/me")
            .with(jwt().jwt(j -> j
                .claim("azp", "oidc-reference-service")
                .claim("preferred_username", "service-account-oidc-reference-service"))))
        .andExpect(status().isForbidden())
        .andExpect(content().contentType(MediaType.APPLICATION_PROBLEM_JSON));
  }

  @Test
  void userDataRequiresApiReadScope() throws Exception {
    mockMvc.perform(get("/api/user-data").with(jwt()))
        .andExpect(status().isForbidden())
        .andExpect(content().contentType(MediaType.APPLICATION_PROBLEM_JSON));

    mockMvc.perform(get("/api/user-data")
            .with(jwt().jwt(j -> j.claim("scope", "api.read"))
                       .authorities(new SimpleGrantedAuthority("SCOPE_api.read"))))
        .andExpect(status().isOk());
  }

  @Test
  void userDataReturnsClaimsDerivedProfile() throws Exception {
    // /api/user-data returns the caller's profile + entitlements derived
    // straight from the validated access token — no downstream call, no token
    // relay. Proves the Resource Server reads identity and authorization off
    // the JWT it already validated, at its own audience.
    mockMvc.perform(get("/api/user-data")
            .with(jwt()
                .jwt(j -> j
                    .subject("alice-123")
                    .claim("preferred_username", "alice")
                    .claim("email", "alice@example.com"))
                .authorities(
                    new SimpleGrantedAuthority("SCOPE_api.read"),
                    new SimpleGrantedAuthority("ROLE_user"))))
        .andExpect(status().isOk())
        .andExpect(content().contentType(MediaType.APPLICATION_JSON))
        .andExpect(jsonPath("$.subject").value("alice-123"))
        .andExpect(jsonPath("$.username").value("alice"))
        .andExpect(jsonPath("$.email").value("alice@example.com"))
        .andExpect(jsonPath("$.roles", org.hamcrest.Matchers.hasItem("user")))
        .andExpect(jsonPath("$.scopes", org.hamcrest.Matchers.hasItem("api.read")));
  }

  @Test
  void insufficientScopeEmitsSecurityAuditEvent(CapturedOutput output) throws Exception {
    mockMvc.perform(get("/api/user-data").with(jwt()))
        .andExpect(status().isForbidden());

    assertThat(output).contains(
        "security_audit event=access_denied status=403 method=GET path=/api/user-data reason=insufficient_authority");
  }

  @Test
  void adminRequiresRealmRoleAdmin() throws Exception {
    mockMvc.perform(post("/api/admin").with(jwt()))
        .andExpect(status().isForbidden());

    mockMvc.perform(post("/api/admin")
            .with(jwt().jwt(j -> j.claim("realm_access", Map.of("roles", List.of("admin"))))
                       .authorities(new SimpleGrantedAuthority("ROLE_admin"))))
        .andExpect(status().isOk());
  }

  @Test
  void jwtAuthenticationConverterMapsConfiguredRolesClaimPath() {
    Jwt jwt = Jwt.withTokenValue("test-token")
        .header("alg", "RS256")
        .claim("groups", List.of("admin", "auditor"))
        .claim("scope", "api.read")
        .build();

    var auth = new SecurityConfig()
        .jwtAuthenticationConverter(List.of("groups"))
        .convert(jwt);

    assertThat(auth.getAuthorities())
        .contains(
            new SimpleGrantedAuthority("ROLE_admin"),
            new SimpleGrantedAuthority("ROLE_auditor"),
            new SimpleGrantedAuthority("SCOPE_api.read"));
  }

  @Test
  void jobsRequiresServiceJobsScope() throws Exception {
    mockMvc.perform(post("/api/jobs").with(jwt()))
        .andExpect(status().isForbidden());

    mockMvc.perform(post("/api/jobs")
            .with(jwt().jwt(j -> j.claim("azp", "oidc-reference-service"))
                .authorities(new SimpleGrantedAuthority("SCOPE_service.jobs"))))
        .andExpect(status().isOk());
  }

  @Test
  void jobsRejectsUserTokenEvenWithServiceJobsScope() throws Exception {
    mockMvc.perform(post("/api/jobs")
            .with(jwt().jwt(j -> j
                    .claim("azp", "oidc-reference-bff")
                    .claim("preferred_username", "alice"))
                .authorities(new SimpleGrantedAuthority("SCOPE_service.jobs"))))
        .andExpect(status().isForbidden())
        .andExpect(content().contentType(MediaType.APPLICATION_PROBLEM_JSON));
  }
}
