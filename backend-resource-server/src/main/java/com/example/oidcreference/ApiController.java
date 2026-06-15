package com.example.oidcreference;

import com.fasterxml.jackson.annotation.JsonInclude;
import java.security.Principal;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Set;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ProblemDetail;
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

  // Consumes the validated AppProperties record. The cross-field invariant
  // (jobs-client-id ∈ service-client-ids) and the required-acr blank-strip
  // normalization both live in the record now, so this constructor just copies
  // the already-validated values into the controller's fields.
  ApiController(AppProperties properties) {
    this.serviceClients = Set.copyOf(properties.serviceClientIds());
    this.jobsClientId = properties.jobsClientId();
    this.stepUpMaxAge = properties.stepUp().maxAge();
    this.requiredAcr = Set.copyOf(properties.stepUp().requiredAcr());
  }

  @GetMapping("/public")
  StatusResponse publicResource() {
    return new StatusResponse("public");
  }

  // Service-account clients are identified by token claims, not by a
  // username-prefix convention. Keycloak emits a synthetic
  // preferred_username of "service-account-<client>", but a different
  // IdP could legitimately have a human user named "service-account-foo".
  // Match on azp / client_id against the configured service-account clients
  // instead — the same shape /api/jobs uses below.
  @GetMapping("/me")
  SubjectResponse me(Principal principal, @AuthenticationPrincipal Jwt jwt) {
    if (isServiceClient(jwt)) {
      throw new AccessDeniedException("User identity is required");
    }
    return new SubjectResponse(principal.getName());
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
  UserDataResponse userData(JwtAuthenticationToken authentication) {
    Jwt token = authentication.getToken();
    return new UserDataResponse(
        token.getSubject(),
        token.getClaimAsString("preferred_username"),
        token.getClaimAsString("email"), // null -> omitted by @JsonInclude(NON_NULL)
        authorityValues(authentication, "ROLE_"),
        authorityValues(authentication, "SCOPE_"));
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
  StatusResponse admin(@AuthenticationPrincipal Jwt jwt) {
    requireStepUpAuthentication(jwt);
    return new StatusResponse("admin");
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
  ResponseEntity<ProblemDetail> handleStepUpRequired(StepUpRequiredException ex) {
    long maxAge = ex.maxAge().toSeconds();
    // RFC 9470 §3: 401 with error="insufficient_user_authentication" and the
    // requirements the resource states — max_age (recency) and, when acr is
    // enforced, acr_values (assurance). The SPA reads this to elevate via
    // /auth/step-up (a fresh re-auth) rather than a full re-login. The
    // WWW-Authenticate challenge string is the load-bearing RFC 6750/9470
    // control and stays hand-controlled / byte-exact; only the body moves to
    // ProblemDetail (matching the auth-service's idiom).
    String challenge = "Bearer error=\"insufficient_user_authentication\", "
        + "error_description=\"A stronger or more recent authentication is required\", "
        + "max_age=" + maxAge;
    if (!ex.requiredAcr().isEmpty()) {
      // Sorted for a deterministic challenge: required-acr is a set ("any of
      // these"), so the order carries no preference (RFC 9470 acr_values is a
      // space-delimited list); sorting just keeps the header stable.
      challenge += ", acr_values=\""
          + String.join(" ", ex.requiredAcr().stream().sorted().toList()) + "\"";
    }
    ProblemDetail problem = ProblemDetail.forStatusAndDetail(
        HttpStatus.UNAUTHORIZED,
        "Step-up authentication required: re-authenticate within the last %d seconds."
            .formatted(maxAge));
    problem.setTitle("Unauthorized");
    // The RFC 9470 machine-readable error code, surfaced as a top-level
    // problem+json member (ApiSecurityTest asserts $.error).
    problem.setProperty("error", "insufficient_user_authentication");
    return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
        .header(HttpHeaders.WWW_AUTHENTICATE, challenge)
        .contentType(MediaType.APPLICATION_PROBLEM_JSON)
        .body(problem);
  }

  @PostMapping("/jobs")
  StatusResponse jobs(@AuthenticationPrincipal Jwt jwt) {
    String authorizedParty = jwt.getClaimAsString("azp");
    String clientId = jwt.getClaimAsString("client_id");
    if (!jobsClientId.equals(authorizedParty) && !jobsClientId.equals(clientId)) {
      throw new AccessDeniedException("Service client token is required");
    }
    return new StatusResponse("job accepted");
  }

  // Typed response contracts (SPEC-0001 #15): fixed-shape JSON the gateway/SPA
  // read, as records instead of ad-hoc maps so a stray field can't drift in.
  // Field names are the wire contract (snake_case not needed — all single words).
  record StatusResponse(String status) {}

  record SubjectResponse(String subject) {}

  // email is omitted when the token carries none (matches the prior conditional
  // put); subject/username/roles/scopes are always serialized.
  record UserDataResponse(
      String subject,
      String username,
      @JsonInclude(JsonInclude.Include.NON_NULL) String email,
      List<String> roles,
      List<String> scopes) {}
}
