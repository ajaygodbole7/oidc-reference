# Auth Service

Spring Boot service that owns the OAuth/OIDC client role for the browser
flow. Built on Nimbus `oauth2-oidc-sdk` directly (not the Spring Security
OAuth2 Client starter); see
[`../docs/architecture/architecture-decisions.md`](../docs/architecture/architecture-decisions.md)
§A7 for why.

This directory owns the Authorization Code Flow with PKCE, the session
cookie, the custom Redis-compatible `tx:{state}` and `sess:{sid}`
repositories, ID-token validation, refresh-token rotation with reuse
detection, RP-initiated logout, OIDC Back-Channel Logout, and the
`/internal/refresh` RPC.

## Endpoints

- `/auth/login`, `/auth/callback/idp`, `/auth/logout`, `/auth/logout/continue`,
  `/auth/me` — browser-facing, cookie-authenticated.
- `/internal/refresh` — back-channel RPC, served as an OAuth Resource Server.
  Called by the API Gateway as the `oidc-reference-api-gateway` Client
  Credentials client, audience-bound to `oidc-reference-auth-internal`.

## Trust boundary

The Auth Service is the sole writer of `tx:{state}` and `sess:{sid}`. The
API Gateway reads `sess:{sid}` but never writes it. The two share only the
`sess:{sid}` JSON schema and the `/internal/refresh` contract, both in
[`../docs/specs/SPEC-0001-core-oidc-flows.md`](../docs/specs/SPEC-0001-core-oidc-flows.md)
(§7.1, §7.2).

## Specification

- [`../docs/specs/SPEC-0001-core-oidc-flows.md`](../docs/specs/SPEC-0001-core-oidc-flows.md)
  §Auth Service, §7.1 (`/internal/refresh`), §7.2 (`sess:{sid}` schema),
  §7.3 (signed CSRF).
