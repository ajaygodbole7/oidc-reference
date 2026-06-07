package com.example.oidcreference;

import java.security.Principal;
import java.util.Map;
import java.util.Set;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
class ApiController {

  // Service-account client ids are this reference's deployment topology, not a
  // per-provider OIDC value — real IdPs (Okta/Auth0/Entra) assign client ids
  // you don't choose. Config-driven so the allowlist can match whatever the
  // target IdP issues; defaults are the local Keycloak client names.
  private final Set<String> serviceClients;
  private final String jobsClientId;

  ApiController(
      @Value("${app.service-client-ids}") Set<String> serviceClients,
      @Value("${app.jobs-client-id}") String jobsClientId) {
    this.serviceClients = Set.copyOf(serviceClients);
    this.jobsClientId = jobsClientId;
    if (!this.serviceClients.contains(this.jobsClientId)) {
      throw new IllegalArgumentException(
          "app.jobs-client-id must be included in app.service-client-ids");
    }
  }

  @GetMapping("/public")
  Map<String, String> publicResource() {
    return Map.of("status", "public");
  }

  // Service-account clients are identified by token claims, not by a
  // username-prefix convention. Keycloak emits a synthetic
  // preferred_username of "service-account-<client>", but a different
  // IdP could legitimately have a human user named "service-account-foo".
  // Match on azp / client_id against the configured service-account clients
  // instead — the same shape /api/jobs uses below.
  @GetMapping("/me")
  Map<String, String> me(Principal principal, @AuthenticationPrincipal Jwt jwt) {
    if (isServiceClient(jwt)) {
      throw new AccessDeniedException("User identity is required");
    }
    return Map.of("subject", principal.getName());
  }

  private boolean isServiceClient(Jwt jwt) {
    String azp = jwt.getClaimAsString("azp");
    String clientId = jwt.getClaimAsString("client_id");
    return (azp != null && serviceClients.contains(azp))
        || (clientId != null && serviceClients.contains(clientId));
  }

  @GetMapping("/user-data")
  Map<String, String> userData() {
    return Map.of("status", "user-data");
  }

  @PostMapping("/admin")
  Map<String, String> admin() {
    return Map.of("status", "admin");
  }

  @PostMapping("/jobs")
  Map<String, String> jobs(@AuthenticationPrincipal Jwt jwt) {
    String authorizedParty = jwt.getClaimAsString("azp");
    String clientId = jwt.getClaimAsString("client_id");
    if (!jobsClientId.equals(authorizedParty) && !jobsClientId.equals(clientId)) {
      throw new AccessDeniedException("Service client token is required");
    }
    return Map.of("status", "job accepted");
  }
}
