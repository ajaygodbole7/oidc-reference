package com.example.oidcreference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
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
