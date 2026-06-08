package com.example.oidcreference.authservice;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import java.net.URI;
import java.time.Duration;
import java.util.List;
import java.util.Set;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;
import org.springframework.validation.annotation.Validated;

@Validated
@ConfigurationProperties(prefix = "app")
public record AuthProperties(
    @NotBlank @DefaultValue("idp") String oauthRegistrationId,
    /**
     * Public-facing base URL of this Auth Service ({@code https://app.example.com}
     * or {@code http://127.0.0.1:5173} in dev). When set, the callback / login
     * redirect_uri is computed from this value verbatim and the
     * X-Forwarded-* headers are ignored — defeating Host-header injection where
     * an attacker controlled proxy could otherwise steer the IdP to a
     * crafted redirect_uri. Leave empty to fall back to header-derived
     * resolution (the inner-loop dev convenience).
     */
    @DefaultValue("") String baseUrl,
    /**
     * Sliding pre-expiry window used to trigger refresh-token rotation before
     * the access token actually expires. Keeps the proxy from forwarding a
     * token that is about to be rejected as expired by the resource server.
     */
    @NotNull @DefaultValue("60s") Duration sessionRefreshWindow,
    /**
     * Sliding idle TTL in seconds. /auth/me and other Auth Service reads do
     * not extend it; authenticated /api traffic through the gateway does.
     */
    @NotNull @DefaultValue("1800s") Duration sessionIdleTtl,
    /**
     * Hard upper bound for a local session. Must stay below or equal to the
     * IdP SSO max session lifespan.
     */
    @NotNull @DefaultValue("28800s") Duration sessionAbsoluteTtl,
    @NotNull URI issuerUri,
    URI authorizationUri,
    URI tokenUri,
    URI jwksUri,
    URI endSessionUri,
    @NotBlank String clientId,
    @NotBlank String clientSecret,
    @NotEmpty Set<@NotBlank String> scopes,
    /**
     * Path through the ID-token claims that holds the user's roles. A list
     * of path segments — single element for top-level claims (Okta {@code
     * groups}, Auth0 {@code https://my-app/roles}), multi-element for
     * nested claims (Keycloak {@code realm_access.roles}). List-of-segments
     * (rather than a dotted string) lets URL-shaped names like
     * {@code https://my-app/roles} carry slashes safely.
     *
     * <p>The default targets Keycloak (this reference's local IdP). Swapping
     * to a different IdP is a one-property change, no code edits required.
     */
    @NotEmpty List<@NotBlank String> rolesClaimPath,
    /**
     * Base64-encoded 256-bit HMAC key used by the signed double-submit CSRF
     * helper (see SignedCsrfSupport). Default is a literal known-dev
     * sentinel — 32 zero-bytes base64-encoded — that
     * {@link SecretSentinelValidator} recognizes and refuses to ship to a
     * "prod" profile. The same literal is shared with the bff-session.lua
     * APISIX plugin so both sides can detect it.
     */
    @NotBlank @DefaultValue("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
        String cookieSigningKey,
    /**
     * If true (default), a refresh-token grant that returns no new
     * refresh_token — or returns the same one — is treated as a rotation
     * failure and surfaced to the controller as InvalidRefreshTokenException
     * (the same shape as Keycloak's invalid_grant on reuse). The session is
     * invalidated and the caller gets 409.
     *
     * <p>Set to false ONLY when paired with an authorization server that
     * doesn't rotate refresh tokens (e.g. an IdP demo with rotation
     * disabled). With the default reference setup — Keycloak + refresh
     * rotation + reuse detection — keep this true; silently reusing an
     * un-rotated refresh token would defeat the reuse-detection chain.
     */
    @NotNull @DefaultValue("true") Boolean refreshRequireRotation,
    /**
     * Client id of the API Gateway's confidential client, as the IdP issues it.
     * The {@code /internal/refresh} caller check requires the bearer's {@code
     * azp}/{@code client_id} to equal this. Deployment topology, not a
     * per-provider OIDC value — real IdPs (Okta/Auth0/Entra) assign client ids
     * you do not choose, so this must be configurable. Default is the local
     * Keycloak client name.
     */
    @NotBlank @DefaultValue("oidc-reference-api-gateway") String gatewayClientId,
    /**
     * Audience the API Gateway's Client-Credentials token must carry for
     * {@code /internal/refresh}. Enforced at the Order-1 filter and re-asserted
     * in the controller. Configurable for the same reason as
     * {@link #gatewayClientId}. Default is the local reference value.
     */
    @NotBlank @DefaultValue("oidc-reference-auth-internal") String internalAudience) {
}
