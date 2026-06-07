# GOAL-0003: Authorization Server (Keycloak)

## Directory

`authorization-server/`

## Goal

Deliver a local Keycloak that is reproducible from source-controlled realm
import, exposes the documented issuer and JWKS, hosts a confidential **Auth
Service** client (Authorization Code + PKCE S256 + refresh rotation), a
confidential **API Gateway** client (Client Credentials, for the internal
`/internal/refresh` RPC), and a confidential **service** client (Client
Credentials), attaches an `oidc-audience-mapper` so issued access tokens
carry the configured API audience and the configured internal-refresh
audience as appropriate (local defaults `oidc-reference-api` and
`oidc-reference-auth-internal`), and is verified by a smoke script that
issues real tokens via `curl` and inspects the claims.

This goal scopes the **local reference IdP only**. The Auth Service, API
Gateway, and Resource Server are IdP-agnostic OIDC clients; swapping to AWS
Cognito, Azure Entra ID, Okta, Auth0, Ping, or any OIDC-compliant
authorization server is configuration on the client side (see SPEC-0001
§"Authorization Server Portability") and is out of scope of this goal.

## Purpose

Keycloak owns identities, clients, scopes, mappers, and token shape. This
directory is the reference's reproducibility guarantee: a fresh checkout
recreates the realm without manual console clicks.

## Owned Paths

- `authorization-server/`
- Realm import JSON.
- Keycloak Compose config and database service.
- Authorization-server smoke tests and scripts.
- Auth-server docs and task packets.

## Avoid Paths

- `auth-service/`, `api-gateway/`, `frontend/`, `backend-resource-server/`
- Shared root config unless explicitly coordinated.

## Required Technology

- Keycloak (image pinned in `compose.yaml`).
- Docker Compose.
- Realm import JSON (declarative; no manual console steps).
- Generated local secrets, supplied via env, gitignored.

## Required Realm

- Realm: `oidc-reference`.
- Users: `alice` (role `user`), `admin` (roles `user`, `admin`), optional
  `auditor`.
- Realm roles: `user`, `admin`, `auditor`.
- Client scopes: `openid`, `profile`, `email`, `api.audience`, `api.read`,
  `api.write`, `admin.read`, `service.jobs`, `auth.internal`.
- Protocol mappers:
  - `oidc-audience-mapper` on `api.audience`, hardcoded audience
    `oidc-reference-api`, added to access tokens.
  - `oidc-audience-mapper` on `auth.internal`, hardcoded audience
    `oidc-reference-auth-internal`, added to access tokens. Consumed by
    the API Gateway when calling `/internal/refresh` on the Auth Service.
  - `oidc-usermodel-realm-role-mapper` emitting `realm_access.roles`
    (Keycloak default; assert present).

## Required Clients

### Auth Service Client (`oidc-reference-auth`)

- Confidential.
- Standard flow enabled, PKCE `S256` required, implicit + direct grants
  disabled, service accounts disabled.
- Refresh tokens enabled, **rotation + reuse detection enabled**.
- Redirect URIs:
  - `http://127.0.0.1:5173/auth/callback/idp` in the frontend-dev case
    where Vite fronts the Auth Service.
  - `http://127.0.0.1:9080/auth/callback/idp` for APISIX-fronted local
    harnesses that drive the gateway directly.
  Registration name in the path is the generic `idp` (not the IdP brand) so
  swapping IdPs requires no URI change.
- Post-logout redirect URIs: `http://127.0.0.1:5173/` and
  `http://127.0.0.1:9080/`.
- Web origins: none.
- Default scopes: `openid`, `profile`, `email`, `roles`, `api.audience`,
  `api.read`.
- Optional scopes: `api.write`, `admin.read`.
- Secret: placeholder in realm JSON, generated locally and supplied via env.

### API Gateway Client (`oidc-reference-api-gateway` Local Default)

- Confidential.
- Client Credentials enabled, service accounts enabled.
- Browser flows (standard, implicit) disabled. Direct access grants
  disabled.
- Default scopes: `auth.internal`. Issued access tokens carry the
  configured internal-refresh audience via the `auth.internal` audience
  mapper.
- Used by the APISIX API Gateway to authenticate to the Auth Service's
  `/internal/refresh` endpoint. See SPEC-0001 §7.1.
- Secret: placeholder in realm JSON, generated locally and supplied via env.

### Service Client (`oidc-reference-service`)

- Confidential.
- Client Credentials enabled, service accounts enabled, browser + direct
  grants disabled.
- Default scopes: `api.audience`, `service.jobs`.
- Secret: placeholder in realm JSON, generated locally and supplied via env.

## Token Requirements

Tokens must support backend validation of: issuer, signature (JWKS),
expiration, audience (`oidc-reference-api`), scope, `realm_access.roles`,
user vs service-account identity.

## Acceptance Criteria

- `docker compose up -d` starts Keycloak + Postgres locally.
- Realm import succeeds with no manual console steps.
- OIDC discovery returns the documented issuer; JWKS reachable.
- Auth Service client (`oidc-reference-auth`) passes static checks
  (confidential, PKCE S256, exact redirect URI, refresh rotation).
- API Gateway client (`oidc-reference-api-gateway`) passes static checks
  (confidential, Client Credentials enabled, browser flows disabled,
  direct access grants disabled, service accounts enabled,
  `auth.internal` in default scopes).
- Service client obtains a token via `curl` Client Credentials.
- Issued service token contains `aud=oidc-reference-api` and `scope`
  includes `service.jobs`.
- Issued API-Gateway service token contains the configured
  internal-refresh audience and `scope` includes `auth.internal` (or
  `internal.refresh` if scope-based authorization is enabled).
- No committed secrets.
- Docs explain every client, scope, mapper, test user.

## Required Tests And Checks

- Container starts; realm exists.
- Discovery JSON `issuer` matches `OIDC_ISSUER`.
- JWKS endpoint returns keys.
- Realm import static checks (existing `smoke.sh`).
- Real token issuance via `curl` for service client; inspect `aud`,
  `scope`, `iss`.
- Real authorization-code-style token check optional in CI; manual
  Playwright covers the browser flow.

## Evidence For Completion

- Compose startup output.
- Discovery JSON sample.
- JWKS reachability sample.
- `smoke.sh` output including real-token claims (secrets redacted).
- Docs explaining realm design.

## Blocked Conditions

Stop and report if:

- Docker is unavailable.
- Keycloak image cannot be pulled or started.
- Realm import behavior differs from documented Keycloak behavior.
- A required Keycloak setting is unavailable in the pinned version.
- Local secret generation or exclusion cannot be made safe.
