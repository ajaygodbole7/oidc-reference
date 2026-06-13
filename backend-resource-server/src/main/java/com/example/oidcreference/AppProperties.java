package com.example.oidcreference;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import java.time.Duration;
import java.util.Set;
import java.util.stream.Collectors;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

/**
 * Typed, fail-fast model for the Resource Server's {@code app.*} configuration,
 * mirroring the auth-service's {@code AuthProperties} record. Replaces the
 * scattered {@code @Value} injections in {@code ApiController} / {@code
 * SecurityConfig} and gives validation at boot instead of a bean-construction
 * exception. Bound via {@code @ConfigurationPropertiesScan} on the
 * {@code @SpringBootApplication} class.
 *
 * <p>Leave the {@code spring.security.oauth2.*} keys out of this record — those
 * are framework keys consumed directly by {@code SecurityConfig}.
 */
@Validated
@ConfigurationProperties(prefix = "app")
public record AppProperties(
    /**
     * Audience this Resource Server pins on incoming access tokens (RFC 9068).
     * A token minted for a different audience is rejected by the decoder's
     * validator chain — the load-bearing control that blocks ID-token replay.
     */
    @NotBlank String audience,
    /**
     * Path through the access-token claims that holds the user's roles. A list
     * of path segments — single element for top-level claims, multi-element for
     * nested claims (Keycloak {@code realm_access.roles}). The default targets
     * the local Keycloak realm; swapping IdPs is a one-property change.
     */
    @NotEmpty java.util.List<@NotBlank String> rolesClaimPath,
    /**
     * Service-account client ids — this reference's deployment topology, not a
     * per-provider OIDC value (Okta/Auth0/Entra assign client ids you don't
     * choose). The allowlist denied on /api/me (user identity required).
     */
    @NotEmpty Set<@NotBlank String> serviceClientIds,
    /**
     * The single service client authorized to POST /api/jobs. Must be one of
     * {@link #serviceClientIds} (enforced fail-fast in the compact constructor).
     */
    @NotBlank String jobsClientId,
    @NotNull @Valid StepUp stepUp) {

  /**
   * Step-up gate parameters (RFC 9470) for sensitive routes: the recency window
   * on the caller's last interactive authentication and the assurance floor.
   */
  public record StepUp(
      /**
       * Maximum age of the caller's last interactive authentication (the access
       * token's {@code auth_time}) accepted on a sensitive route. Older — or
       * absent — yields an RFC 9470 step-up challenge.
       */
      @NotNull Duration maxAge,
      /**
       * Assurance floor: the access token's {@code acr} (LoA) must be one of
       * these values on a sensitive route, in ADDITION to the recency gate.
       * Empty disables the acr check (an IdP that emits no acr).
       */
      Set<String> requiredAcr) {

    // Normalize required-acr: depending on the property binder, an unset
    // `app.step-up.required-acr` can bind as a single empty string rather than
    // an empty set. Stripping blanks makes an empty/blank config reliably
    // DISABLE the acr check (the documented "IdP emits no acr" path) instead of
    // rejecting every token, since no real token carries a blank acr.
    public StepUp {
      requiredAcr = (requiredAcr == null ? Set.<String>of() : requiredAcr).stream()
          .filter(value -> value != null && !value.isBlank())
          .collect(Collectors.toUnmodifiableSet());
    }
  }

  // Cross-field invariant: the jobs client must be inside the service-account
  // allowlist, otherwise /api/jobs could never accept its own configured client.
  // Fail fast at binding rather than at first request.
  public AppProperties {
    serviceClientIds = Set.copyOf(serviceClientIds);
    if (jobsClientId != null && !serviceClientIds.contains(jobsClientId)) {
      throw new IllegalArgumentException(
          "app.jobs-client-id must be included in app.service-client-ids");
    }
  }
}
