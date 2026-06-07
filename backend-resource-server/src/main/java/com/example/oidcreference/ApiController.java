package com.example.oidcreference;

import java.security.Principal;
import java.util.Map;
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
  @GetMapping("/public")
  Map<String, String> publicResource() {
    return Map.of("status", "public");
  }

  // Service-account clients are identified by token claims, not by a
  // username-prefix convention. Keycloak emits a synthetic
  // preferred_username of "service-account-<client>", but a different
  // IdP could legitimately have a human user named "service-account-foo".
  // Match on azp / client_id against the known service-account clients
  // instead — the same shape /api/jobs uses below.
  private static final java.util.Set<String> SERVICE_CLIENTS = java.util.Set.of(
      "oidc-reference-api-gateway",
      "oidc-reference-service");

  @GetMapping("/me")
  Map<String, String> me(Principal principal, @AuthenticationPrincipal Jwt jwt) {
    if (isServiceClient(jwt)) {
      throw new AccessDeniedException("User identity is required");
    }
    return Map.of("subject", principal.getName());
  }

  private static boolean isServiceClient(Jwt jwt) {
    String azp = jwt.getClaimAsString("azp");
    String clientId = jwt.getClaimAsString("client_id");
    return (azp != null && SERVICE_CLIENTS.contains(azp))
        || (clientId != null && SERVICE_CLIENTS.contains(clientId));
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
    if (!"oidc-reference-service".equals(authorizedParty)
        && !"oidc-reference-service".equals(clientId)) {
      throw new AccessDeniedException("Service client token is required");
    }
    return Map.of("status", "job accepted");
  }
}
