package com.example.oidcreference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
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

  private static AppProperties props(
      Set<String> serviceClientIds, String jobsClientId, Set<String> requiredAcr) {
    return new AppProperties(
        "oidc-reference-api",
        List.of("realm_access", "roles"),
        serviceClientIds,
        jobsClientId,
        new AppProperties.StepUp(STEP_UP_MAX_AGE, requiredAcr));
  }

  private final ApiController controller =
      new ApiController(
          props(Set.of("custom-gateway", "custom-service", "custom-jobs"), "custom-jobs",
              Set.of("1")));

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
    // The cross-field invariant now lives in the AppProperties compact
    // constructor (fail-fast at binding), so building the record with a jobs
    // client outside the service allowlist is what trips it.
    assertThatThrownBy(() -> props(Set.of("custom-gateway"), "custom-jobs", Set.of("1")))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("app.jobs-client-id");
  }

  @Test
  void adminAcceptsAFreshAuthTimeWithNoAcrWhenRequiredAcrIsEmpty() {
    // The documented "IdP emits no acr" path: with required-acr EMPTY the acr
    // check is disabled, so a fresh auth_time and NO acr claim clears the gate.
    ApiController noAcr = new ApiController(
        props(Set.of("custom-gateway", "custom-jobs"), "custom-jobs", Set.of()));
    Jwt jwt = jwtWithAuthTime(Instant.now().minusSeconds(30));
    assertThat(noAcr.admin(jwt)).containsEntry("status", "admin");
  }

  // -- step-up freshness on the sensitive route ---------------------------

  @Test
  void adminAcceptsAFreshAuthTimeAndSufficientAcr() {
    // Both step-up axes satisfied: fresh interactive auth (auth_time) AND a
    // sufficient assurance level (acr "1", the controller's required-acr).
    Jwt jwt = jwtWithAuthTimeAndAcr(Instant.now().minusSeconds(30), "1");
    assertThat(controller.admin(jwt)).containsEntry("status", "admin");
  }

  @Test
  void adminRejectsAFreshAuthTimeWithMissingAcrWithStepUpRequired() {
    // Recent enough, but no acr at all: the assurance level cannot be confirmed,
    // so the sensitive action fails closed.
    Jwt jwt = jwtWithAuthTime(Instant.now().minusSeconds(30));
    assertThatThrownBy(() -> controller.admin(jwt))
        .isInstanceOf(StepUpRequiredException.class);
  }

  @Test
  void adminRejectsAnInsufficientAcrWithStepUpRequired() {
    // Recent, but acr "0" (a remembered-SSO session) is below the required "1":
    // recency alone is not enough for the sensitive action.
    Jwt jwt = jwtWithAuthTimeAndAcr(Instant.now().minusSeconds(30), "0");
    assertThatThrownBy(() -> controller.admin(jwt))
        .isInstanceOf(StepUpRequiredException.class);
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

  private static Jwt jwtWithAuthTimeAndAcr(Instant authTime, String acr) {
    return Jwt.withTokenValue("t")
        .header("alg", "RS256")
        .claim("auth_time", authTime.getEpochSecond())
        .claim("acr", acr)
        .issuedAt(Instant.now())
        .expiresAt(Instant.now().plusSeconds(300))
        .build();
  }
}
