# Architecture Overview

## North Star

Build a local reference implementation of modern OAuth 2.1 and OpenID Connect
flows that is secure enough to teach from and practical enough to run locally.

The reference implements the Backend-for-Frontend (BFF) session pattern as a
**split implementation**: the browser never holds an access, refresh, or ID
token. Two cooperating services — a dedicated **Auth Service** (the confidential
OAuth/OIDC client) and a dedicated **API Gateway** (the routing and
bearer-injection role) — share a Valkey state store and sit behind a single
ingress. Tokens live in a Redis-compatible server-side state store (Valkey
locally) and are addressed by an opaque `HttpOnly` session cookie. This aligns
with current IETF guidance for OAuth 2.0 for Browser-Based Apps.

The project demonstrates two core flows:

1. Browser user login. A top-level request for a protected URL, or an
   explicit `/auth/login` navigation, starts the Auth-Service-owned
   Authorization Code Flow with PKCE. The Auth Service stores `tx:{state}`
   in the state store, creates `sess:{sid}` after callback, and issues a
   direct `302` to the saved request URL with `__Host-sid`
   (`SameSite=Lax`) and a signed `XSRF-TOKEN`. The API Gateway then reads
   `sess:{sid}` on each `/api/**` request and forwards to the Resource
   Server with `Authorization: Bearer`. Refresh is delegated back to the
   Auth Service via a back-channel `/internal/refresh` RPC authenticated
   with Client Credentials.
2. Service authorization. A machine client uses Client Credentials Flow against
   Keycloak, then calls service-only Resource Server endpoints directly.
   Neither the Auth Service nor the API Gateway is in this path.

## Planned Components

- React SPA: no OAuth client library. Calls only same-origin endpoints
  (`/auth/login`, `/auth/callback`, `/auth/logout`, `/auth/me`, `/api/*`)
  fronted by the ingress. Authenticates via an opaque session cookie.
- Auth Service: Spring Boot, confidential OIDC client. Owns the OAuth flow,
  the session cookie, custom Redis-compatible `tx:{state}` and `sess:{sid}`
  repositories, ID-token validation, refresh-token rotation with reuse
  detection, RP-initiated logout, and the back-channel `/internal/refresh`
  RPC (as an OAuth Resource Server for `/internal/*`).
- API Gateway: Apache APISIX standalone mode with a custom Lua plugin. Owns
  `/api/**`. Reader of `sess:{sid}`. Strips inbound Cookie and hop-by-hop
  headers; injects `Authorization: Bearer` on upstream calls. Enforces the
  path-pattern allowlist. Validates signed CSRF on state-changing requests.
  Delegates refresh to the Auth Service via `/internal/refresh`.
- Redis-compatible state store: Valkey locally. Stores short-lived PKCE
  transactions (state, verifier, nonce) and longer-lived sessions (tokens,
  claims). Written by the Auth Service; read by the API Gateway.
- Resource Server: Spring Boot. Validates Keycloak JWT access tokens (issuer,
  signature, expiration, algorithm, audience, scope, roles). Has no knowledge
  of cookies or sessions and is not reachable from the browser.
- Keycloak: local Authorization Server and Identity Provider. Hosts three
  confidential clients — `oidc-reference-auth` (Authorization Code + PKCE),
  `oidc-reference-api-gateway` (Client Credentials for the internal RPC),
  and `oidc-reference-service` (Client Credentials for service-to-service).
- Keycloak database: local Postgres container for reproducible infrastructure.
- Verification harness: integration tests, browser tests, and security-negative
  tests.

## Primary Build Goals

- `frontend/`: React, TypeScript, Vite, Playwright. Cookie-authenticated
  client; no in-browser OIDC client library. See `GOAL-0001`.
- `auth-service/`: Java 25, Spring Boot `4.1.0-RC1`, Nimbus oauth2-oidc-sdk
  direct, custom Redis-compatible `tx:{state}` and `sess:{sid}` repositories.
  See `GOAL-0004` (Auth Service).
- `api-gateway/`: Apache APISIX standalone mode with a custom Lua plugin
  for session lookup, bearer injection, signed CSRF, and refresh delegation.
  See `GOAL-0005` (API Gateway).
- `backend-resource-server/`: Java 25, Spring Boot `4.1.0-RC1`, Spring
  Security OAuth2 Resource Server. See `GOAL-0002`.
- `authorization-server/`: Keycloak local Authorization Server. See
  `GOAL-0003`.

Client Credentials remains a cross-goal flow: Keycloak issues the service
token and the Resource Server enforces it. Neither the Auth Service nor the
API Gateway is involved.

## Top-Level Flow

The canonical Mermaid sequence diagrams live in `../../README.md` and are the
single source of truth for the flows; do not duplicate them here. Two points
are worth flagging for the split shape:

1. On the browser-flow diagram, the previous combined-BFF swimlane is now
   split into separate Auth Service and API Gateway swimlanes behind a
   single ingress. The Auth Service owns `/auth/*`; the API Gateway owns
   `/api/**`.
2. Token refresh is a back-channel RPC: the API Gateway calls
   `/internal/refresh` on the Auth Service (authenticated as the
   `oidc-reference-api-gateway` Client Credentials client, audience-bound
   to `oidc-reference-auth-internal`). The Auth Service holds the per-session
   refresh lock and writes the rotated tokens back to `sess:{sid}`.

## Local Assumptions

- Local HTTP is permitted only for the reference environment.
- Production guidance must call out HTTPS, `__Host-` prefixed cookies, real
  secret management, state-store AUTH and TLS, hardened Keycloak settings,
  and operational monitoring.
- No cloud IdP, hosted database, hosted cache, or remote secret manager is
  required to run the reference stack.
- The SPA, the Auth Service, and the API Gateway must be served from the
  same origin (via APISIX in Compose, or via Vite dev-server proxying with
  two upstreams), so the session cookie is sent on `/auth/*` and `/api/*`
  requests without cross-origin exposure.
- The Resource Server is on an internal network in Compose; the browser
  cannot reach it directly.

## Implementation Baseline

The project intentionally targets Java 25 and Spring Boot `4.1.0-RC1`. Agents
must not downgrade to Spring Boot 4.0.x or pause to relitigate the Spring Boot
baseline unless the dependency is unavailable during implementation.

The storage model is already decided: custom Redis-compatible repositories
with exact `tx:{state}` keys for OAuth transactions and exact `sess:{sid}`
keys for post-callback sessions. The Auth Service is the sole writer; the
API Gateway is the sole reader (via a tolerant reader on the documented
JSON schema). The local Valkey image still needs to be pinned in the root
Compose task.
