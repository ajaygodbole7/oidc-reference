package com.example.oidcreference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Duration;
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

  private static final Duration STEP_UP_MAX_AGE = Duration.ofMinutes(5);

  private final ApiController controller =
      new ApiController(
          Set.of("custom-gateway", "custom-service", "custom-jobs"), "custom-jobs", STEP_UP_MAX_AGE);

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
    assertThatThrownBy(() -> new ApiController(Set.of("custom-gateway"), "custom-jobs", STEP_UP_MAX_AGE))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("app.jobs-client-id");
  }

  // -- step-up freshness on the sensitive route ---------------------------

  @Test
  void adminAcceptsAFreshAuthTime() {
    Jwt jwt = jwtWithAuthTime(Instant.now().minusSeconds(30));
    assertThat(controller.admin(jwt)).containsEntry("status", "admin");
  }

  @Test
  void adminRejectsAStaleAuthTimeWithStepUpRequired() {
    // auth_time older than the 5-minute window: the human authenticated too
    // long ago for this sensitive action — demand a step-up.
    Jwt jwt = jwtWithAuthTime(Instant.now().minus(Duration.ofMinutes(10)));
    assertThatThrownBy(() -> controller.admin(jwt))
        .isInstanceOf(StepUpRequiredException.class);
  }

  @Test
  void adminRejectsAMissingAuthTimeWithStepUpRequired() {
    // No auth_time at all (provider/realm not emitting it) fails closed: we
    // cannot prove a recent authentication.
    Jwt jwt = jwtWithAzp("ignored");
    assertThatThrownBy(() -> controller.admin(jwt))
        .isInstanceOf(StepUpRequiredException.class);
  }

  private static Jwt jwtWithAzp(String azp) {
    return Jwt.withTokenValue("t")
        .header("alg", "RS256")
        .claim("azp", azp)
        .issuedAt(Instant.now())
        .expiresAt(Instant.now().plusSeconds(300))
        .build();
  }

  private static Jwt jwtWithAuthTime(Instant authTime) {
    return Jwt.withTokenValue("t")
        .header("alg", "RS256")
        .claim("auth_time", authTime.getEpochSecond())
        .issuedAt(Instant.now())
        .expiresAt(Instant.now().plusSeconds(300))
        .build();
  }
}
