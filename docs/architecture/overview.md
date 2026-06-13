# Architecture Overview

A local, runnable reference for OAuth 2.1 and OpenID Connect in a browser app.
Start with the README for the flows; this page maps the components.

The shape is the Backend-for-Frontend (BFF) session pattern, in its
split implementation:

- The browser never holds an access, refresh, or ID token.
- Two services divide the BFF role. A confidential **Auth Service** owns the
  OAuth/OIDC client: Authorization Code + PKCE, the session cookie, ID-token
  validation, refresh-token rotation, and RP-initiated logout. An **API
  Gateway** owns `/api/**` routing and bearer injection.
- Both sit behind a single ingress and share a Valkey state store. Tokens live
  in the store, addressed by an opaque `HttpOnly` session cookie.

This follows IETF guidance for OAuth 2.0 for Browser-Based Apps
(draft-ietf-oauth-browser-based-apps).

For the rationale behind the split and the rejected alternatives, see
[`architecture-decisions.md`](architecture-decisions.md). For the wire
contracts, see [`../specs/SPEC-0001-core-oidc-flows.md`](../specs/SPEC-0001-core-oidc-flows.md).

## Two flows

1. **Browser login.** A top-level request for a protected URL, or an explicit
   `/auth/login` navigation, starts the Auth-Service-owned Authorization Code
   Flow with PKCE.
   - The Auth Service writes `tx:{state}`, creates `sess:{sid}` after callback,
     and issues a `302` to the saved request URL with `__Host-sid`
     (`SameSite=Lax`) and a signed `XSRF-TOKEN`.
   - On each `/api/**` request the API Gateway calls the Auth Service over the
     `/internal/resolve` RPC (authenticated with Client Credentials) to obtain
     the current access token, then forwards to the Resource Server with
     `Authorization: Bearer`. Session lookup, the idle-TTL slide, and refresh
     are all delegated to the Auth Service inside that call.
2. **Service authorization.** A machine client uses the Client Credentials
   Flow against Keycloak, then calls service-only Resource Server endpoints
   directly. Neither the Auth Service nor the API Gateway is in this path.

## Components

- **React SPA** (`frontend/`): no OAuth client library. Calls same-origin
  endpoints (`/auth/login`, `/auth/callback`, `/auth/logout`, `/auth/me`,
  `/api/*`) fronted by the ingress. Authenticates via an opaque session cookie.
- **Auth Service** (`auth-service/`): Spring Boot, Nimbus `oauth2-oidc-sdk`.
  Confidential OIDC client. Owns the OAuth flow, the session cookie, the
  custom Redis-compatible `tx:{state}` and `sess:{sid}` repositories,
  ID-token validation, refresh-token rotation with reuse detection,
  RP-initiated logout, OIDC Back-Channel Logout, and the `/internal/resolve`
  RPC (served as an OAuth Resource Server for `/internal/*`).
- **API Gateway** (`api-gateway/`): Apache APISIX in standalone mode with a
  custom Lua plugin. Owns `/api/**`. Holds only the opaque sid and never
  reads the session store; resolves each request to a current access token by
  calling `/internal/resolve` on the Auth Service. Strips inbound `Cookie` and
  hop-by-hop headers; injects `Authorization: Bearer` upstream. Enforces the
  path-pattern allowlist. Validates signed CSRF on state-changing requests.
  Delegates session lookup, the idle-TTL slide, and refresh to the Auth
  Service.
- **State store** (`valkey`): Valkey locally (Redis-compatible). Holds
  short-lived PKCE transactions (`tx:{state}`: state, verifier, nonce) and
  sessions (`sess:{sid}`: tokens, claims). The Auth Service is the sole
  component that touches the store, for both reads and writes; the API Gateway
  has no store handle and reaches session state only through `/internal/resolve`.
- **Resource Server** (`backend-resource-server/`): Spring Boot, Spring
  Security OAuth2 Resource Server. Validates Keycloak JWT access tokens
  (issuer, signature, expiration, algorithm, audience, scope, roles). Knows
  nothing of cookies or sessions and is not reachable from the browser.
- **Keycloak** (`authorization-server/`): local Authorization Server and
  Identity Provider. Hosts three confidential clients — `oidc-reference-auth`
  (Authorization Code + PKCE), `oidc-reference-api-gateway` (Client
  Credentials for the internal RPC), and `oidc-reference-service` (Client
  Credentials for service-to-service). Persists realm state to embedded H2
  via `KC_DB=dev-file`; no separate database container.

## Flow source of truth

The Mermaid sequence diagrams in [`../../README.md`](../../README.md) are the
single source of truth for the flows. Two points specific to the split shape:

1. The browser flow runs in separate Auth Service and API Gateway swimlanes
   behind one ingress. The Auth Service owns `/auth/*`; the API Gateway owns
   `/api/**`.
2. Session resolution is a back-channel RPC. On every `/api/**` request the
   API Gateway calls `/internal/resolve` on the Auth Service, authenticated as
   the `oidc-reference-api-gateway` Client Credentials client and audience-bound
   to `oidc-reference-auth-internal`. The Auth Service does the session lookup,
   the idle-TTL slide, and refresh-when-near-expiry; it holds the per-session
   refresh lock and writes any rotated tokens back to `sess:{sid}`.

## Local assumptions

- Local HTTP is permitted only for the reference environment. Production
  guidance is in [`../../SECURITY.md`](../../SECURITY.md) and
  [`../operations/production-hardening.md`](../operations/production-hardening.md):
  HTTPS, `__Host-` cookies, real secret management, state-store AUTH and TLS,
  hardened Keycloak settings, monitoring.
- No cloud IdP, hosted database, hosted cache, or remote secret manager is
  required to run the stack.
- The SPA, Auth Service, and API Gateway are served from one origin (APISIX
  in Compose, or Vite dev-server proxying two upstreams), so the session
  cookie is sent on `/auth/*` and `/api/*` without cross-origin exposure.
- The Resource Server is on an internal network in Compose; the browser
  cannot reach it directly.
