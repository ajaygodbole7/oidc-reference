package com.example.oidcreference;

import java.security.Principal;
import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.bind.annotation.ExceptionHandler;
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
  // Step-up window: the maximum age of the caller's last interactive
  // authentication (auth_time) accepted on a sensitive route. Older → an
  // RFC 9470 step-up challenge. Config-driven (app.step-up.max-age).
  private final Duration stepUpMaxAge;
  // Step-up assurance floor: the acr (LoA) values accepted on a sensitive route,
  // in ADDITION to recency. Config-driven (app.step-up.required-acr). Empty
  // disables the acr check (an IdP that emits no acr); the local realm's acr
  // mapper emits "1" for a fresh interactive auth.
  private final Set<String> requiredAcr;

  ApiController(
      @Value("${app.service-client-ids}") Set<String> serviceClients,
      @Value("${app.jobs-client-id}") String jobsClientId,
      @Value("${app.step-up.max-age}") Duration stepUpMaxAge,
      @Value("${app.step-up.required-acr:}") Set<String> requiredAcr) {
    this.serviceClients = Set.copyOf(serviceClients);
    this.jobsClientId = jobsClientId;
    this.stepUpMaxAge = stepUpMaxAge;
    // Strip blank entries: depending on the property binder, an unset
    // `app.step-up.required-acr` can bind as a single empty string rather than
    // an empty set. Filtering blanks makes an empty/blank config reliably
    // DISABLE the acr check (the documented "IdP emits no acr" path) instead of
    // rejecting every token, since no real token carries a blank acr.
    this.requiredAcr = requiredAcr.stream()
        .filter(value -> value != null && !value.isBlank())
        .collect(Collectors.toUnmodifiableSet());
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

  // Sensitive action: requires ROLE_admin (enforced in SecurityConfig) AND a
  // step-up authentication (enforced here) — both a recent interactive auth
  // (auth_time) and a sufficient assurance level (acr). The role answers "who
  // may do this"; the step-up gate answers "was the human recently present and
  // strongly enough authenticated" — the "re-authenticate before a high-value
  // action" pattern.
  @PostMapping("/admin")
  Map<String, String> admin(@AuthenticationPrincipal Jwt jwt) {
    requireStepUpAuthentication(jwt);
    return Map.of("status", "admin");
  }

  // RFC 9470 step-up gate. The token is valid and correctly authorized; only its
  // authentication strength/recency may be insufficient. Two axes, both fail
  // closed: recency (auth_time within app.step-up.max-age) and assurance (acr in
  // app.step-up.required-acr). A missing auth_time or acr is treated as "cannot
  // prove the required authentication" and is rejected. acr enforcement is
  // skipped when required-acr is empty (an IdP that emits no acr).
  private void requireStepUpAuthentication(Jwt jwt) {
    Instant authTime = jwt.getClaimAsInstant("auth_time");
    if (authTime == null || authTime.isBefore(Instant.now().minus(stepUpMaxAge))) {
      throw new StepUpRequiredException(stepUpMaxAge, requiredAcr);
    }
    if (!requiredAcr.isEmpty()) {
      String acr = jwt.getClaimAsString("acr");
      if (acr == null || !requiredAcr.contains(acr)) {
        throw new StepUpRequiredException(stepUpMaxAge, requiredAcr);
      }
    }
  }

  @ExceptionHandler(StepUpRequiredException.class)
  ResponseEntity<String> handleStepUpRequired(StepUpRequiredException ex) {
    long maxAge = ex.maxAge().toSeconds();
    // RFC 9470 §3: 401 with error="insufficient_user_authentication" and the
    // requirements the resource states — max_age (recency) and, when acr is
    // enforced, acr_values (assurance). The SPA reads this to elevate via
    // /auth/step-up (a fresh re-auth) rather than a full re-login.
    String challenge = "Bearer error=\"insufficient_user_authentication\", "
        + "error_description=\"A stronger or more recent authentication is required\", "
        + "max_age=" + maxAge;
    if (!ex.requiredAcr().isEmpty()) {
      challenge += ", acr_values=\"" + String.join(" ", ex.requiredAcr()) + "\"";
    }
    String body = ("{\"type\":\"about:blank\",\"title\":\"Unauthorized\",\"status\":401,"
        + "\"detail\":\"Step-up authentication required: re-authenticate within the last %d "
        + "seconds.\",\"error\":\"insufficient_user_authentication\"}").formatted(maxAge);
    return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
        .header(HttpHeaders.WWW_AUTHENTICATE, challenge)
        .contentType(MediaType.APPLICATION_PROBLEM_JSON)
        .body(body);
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
