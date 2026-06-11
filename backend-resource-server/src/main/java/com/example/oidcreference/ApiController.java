package com.example.oidcreference;

import java.security.Principal;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
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

  // Returns the caller's profile + entitlements derived straight from the
  // access token THIS Resource Server already validated, at its own audience.
  // No downstream call, no token relay: a token minted for `oidc-reference-api`
  // must not be replayed to a different audience (RFC 9700 §2.3, least
  // privilege). Service fan-out would require token exchange (RFC 8693), which
  // is documented out of scope in architecture-decisions §F.
  @GetMapping("/user-data")
  Map<String, Object> userData(JwtAuthenticationToken authentication) {
    Jwt token = authentication.getToken();
    Map<String, Object> profile = new LinkedHashMap<>();
    profile.put("subject", token.getSubject());
    profile.put("username", token.getClaimAsString("preferred_username"));
    String email = token.getClaimAsString("email");
    if (email != null) {
      profile.put("email", email);
    }
    profile.put("roles", authorityValues(authentication, "ROLE_"));
    profile.put("scopes", authorityValues(authentication, "SCOPE_"));
    return profile;
  }

  private static List<String> authorityValues(JwtAuthenticationToken authentication, String prefix) {
    return authentication.getAuthorities().stream()
        .map(GrantedAuthority::getAuthority)
        .filter(authority -> authority.startsWith(prefix))
        .map(authority -> authority.substring(prefix.length()))
        .sorted()
        .toList();
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
