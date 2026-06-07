package com.example.oidcreference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Instant;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.oauth2.jwt.Jwt;

// Proves the Resource Server's service-client identifiers are config-driven,
// not pinned to this reference's Keycloak client names. The controller is
// constructed with NON-DEFAULT identifiers; the shipped default names must
// NOT be treated as service clients under that config.
class ApiControllerTest {

  private final ApiController controller =
      new ApiController(Set.of("custom-gateway", "custom-service", "custom-jobs"), "custom-jobs");

  @Test
  void meDeniesAConfiguredServiceClient() {
    assertThatThrownBy(() -> controller.me(() -> "custom-service", jwtWithAzp("custom-service")))
        .isInstanceOf(AccessDeniedException.class);
  }

  @Test
  void meTreatsADefaultClientIdOutsideTheConfiguredAllowlistAsAUser() {
    // oidc-reference-api-gateway is the shipped default but NOT in this
    // controller's custom allowlist, so it must be treated as a normal user.
    assertThat(controller.me(() -> "oidc-reference-api-gateway",
            jwtWithAzp("oidc-reference-api-gateway")))
        .containsEntry("subject", "oidc-reference-api-gateway");
  }

  @Test
  void jobsAcceptsTheConfiguredJobsClient() {
    assertThat(controller.jobs(jwtWithAzp("custom-jobs")))
        .containsEntry("status", "job accepted");
  }

  @Test
  void jobsRejectsAClientThatIsNotTheConfiguredJobsClient() {
    assertThatThrownBy(() -> controller.jobs(jwtWithAzp("custom-gateway")))
        .isInstanceOf(AccessDeniedException.class);
  }

  @Test
  void constructorRejectsJobsClientOutsideServiceAllowlist() {
    assertThatThrownBy(() -> new ApiController(Set.of("custom-gateway"), "custom-jobs"))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("app.jobs-client-id");
  }

  private static Jwt jwtWithAzp(String azp) {
    return Jwt.withTokenValue("t")
        .header("alg", "RS256")
        .claim("azp", azp)
        .issuedAt(Instant.now())
        .expiresAt(Instant.now().plusSeconds(300))
        .build();
  }
}
