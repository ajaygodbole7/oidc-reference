# GOAL-0005: API Gateway (APISIX — Routing + Bearer Injection)

## Directory

`api-gateway/`

## Goal

Deliver an APISIX-based API Gateway that owns `/api/**` for the reference.
It is the sole reader of `sess:{sid}` on the request path, injects
`Authorization: Bearer` against the Resource Server, enforces the
path-pattern allowlist, validates signed CSRF on state-changing requests,
and delegates token refresh to the Auth Service over the
`/internal/refresh` Client-Credentials channel. The Gateway never sees a
token in clear text from the browser and never writes to `sess:{sid}`.

## Purpose

The API Gateway is the second of the two services that replaces the
combined BFF under Frame B. It is intentionally an **APISIX** deployment
(declarative YAML routes plus a custom Lua plugin) rather than a Spring
service — this matches production OIDC reference deployments at scale, where
the routing/bearer-injection surface is a dedicated gateway, not yet
another Spring app. See `docs/architecture/architecture-decisions.md` §A6.

## Owned Paths

- `api-gateway/`
- `api-gateway/apisix.yaml` (APISIX standalone declarative config).
- `api-gateway/plugins/` (custom Lua plugins, principally `bff-session`).
- `api-gateway/tests/` (integration tests with `curl` against a local
  APISIX, Valkey, and the Auth Service).
- API-Gateway-specific docs and task packets.

## Avoid Paths

- `frontend/`, `auth-service/`, `backend-resource-server/`,
  `authorization-server/`.
- Shared root config unless explicitly coordinated.

## Required Technology

- APISIX (image pinned in `compose.yaml`), running in **standalone mode**
  with declarative `apisix.yaml`.
- Custom Lua plugins under `api-gateway/plugins/` loaded by APISIX
  (`extra_lua_path` / `plugin.attr`).
- APISIX's built-in `resty.redis` for Valkey reads.
- APISIX's built-in HTTP client (`resty.http`) for the `/internal/refresh`
  call and the Client-Credentials token fetch.
- No JVM dependency — the Gateway has no Spring Boot, no `mvnw`. Tests are
  black-box integration against a running APISIX.

## Required APISIX Components

### Declarative routes (`apisix.yaml`, standalone mode)

- `/api/**` paths in the allowlist (default: `/api/me`, `/api/user-data`,
  `/api/admin`) declared as separate routes or as a single wildcard route
  with the `bff-session` plugin enforcing the allowlist.
- Each route forwards to the `resource-server` upstream.
- Off-allowlist `/api/*` returns `404` (route does not match; no upstream
  call).
- Cache-Control: `no-store` set on all responses.

### Custom Lua plugin `bff-session`

The `bff-session` plugin runs on every `/api/**` request. It performs the
following pipeline:

1. **Browser-request classification.** Read `Sec-Fetch-Mode` and
   `Sec-Fetch-Dest` when present; fall back to `Accept`. XHR/fetch
   requests without a session yield `401` (no `Location`); top-level
   document navigations without a session yield `302
   /auth/login?return_to=<original URL>`.
2. **Session read.** Extract `__Host-sid` (or `sid` in local HTTP) from the
   `Cookie` header. `GET sess:{sid}` from Valkey via `resty.redis`.
   Tolerant reader: parse JSON, read **only** `access_token` and
   `access_token_expires_at`. Ignore other fields. Treat any parse error
   or missing required field as "no session".
3. **Refresh check.** If `access_token_expires_at` is within the no-refresh
   window (default 60s of now), call `POST /internal/refresh` against the
   Auth Service with the Gateway's cached Client-Credentials token. On
   `200`, re-read `sess:{sid}` to pick up the rotated token. Failure
   handling per SPEC-0001 §7.1 (Gateway-side response table).
4. **Signed CSRF validation.** On `POST`/`PUT`/`DELETE`/`PATCH`: extract
   `XSRF-TOKEN` cookie and `X-XSRF-TOKEN` header; verify HMAC
   (constant-time compare) using the shared signing key. Reject naive
   double-submit; see SPEC-0001 §7.3.
5. **Header shaping.** Strip inbound `Cookie` header. Strip hop-by-hop
   headers (`Connection`, `Keep-Alive`, `Proxy-Authenticate`,
   `Proxy-Authorization`, `TE`, `Trailers`, `Transfer-Encoding`,
   `Upgrade`). Inject `Authorization: Bearer <access_token>`. Preserve
   query string.
6. **Forward.** Proxy to the `resource-server` upstream.

### Client-Credentials token cache

The Gateway holds a single in-process cache entry for its
configured gateway-client service token (local default
`oidc-reference-api-gateway`). Discipline:

- Fetched lazily on first need; cached across requests.
- Refreshed **proactively** when remaining lifetime < threshold
  (default 60s). Proactive refresh serialized with an in-process lock so
  concurrent calls do not duplicate Keycloak round-trips.
- On Auth Service `/internal/refresh` returning `401` for the Gateway's
  token: invalidate, re-fetch from Keycloak, retry once. Second `401`
  returns `502` to the browser and emits a Gateway-side security audit
  event.
- On Keycloak unreachable during proactive refresh: use the still-valid
  cached token until expiry; fail closed afterward (`503` for inbound API
  requests that need refresh).

### Timeouts on `/internal/refresh`

- Connect timeout 1s.
- Read timeout 5s.
- Circuit breaking is production hardening, not shipped reference
  behavior. APISIX `api-breaker` is the primitive to add for operated
  deployments; it must not count normal 401/404/409 session outcomes as
  upstream failures.

## Security Requirements

- No tokens in the response body to the browser; the Gateway never echoes
  `access_token` back to a client.
- Inbound `Cookie` header is stripped before the upstream call; the
  Resource Server must never see a cookie.
- Hop-by-hop headers stripped per RFC 7230 §6.1.
- The Gateway is itself a confidential client; client id and secret supplied
  via env (per E2), gitignored. Local default client id:
  `oidc-reference-api-gateway`.
- The CSRF signing key is shared with the Auth Service via env. The reference
  accepts one active key; dual-key grace-window rotation is production
  hardening, not shipped behavior.
- Logging never includes the bearer token, the session cookie value,
  the CSRF token value, or the Client-Credentials secret.

## Acceptance Criteria

- `apisix.yaml` validates against APISIX standalone-config schema.
- `docker compose --profile gateway up apisix` (or equivalent) starts
  APISIX with the custom `bff-session` plugin loaded.
- Against a running stack (APISIX + Valkey + Auth Service + Resource
  Server + Keycloak), the integration test suite under `api-gateway/tests/`
  passes via `curl`.
- Off-allowlist `/api/*` requests return `404` without an upstream call.
- Allowlisted `/api/*` requests with a valid session succeed end-to-end:
  Gateway reads `sess:{sid}`, injects bearer, RS validates JWT, response
  body returned.
- No secret is committed.

## Required Tests

Integration tests with `curl` against a running APISIX+Valkey+Auth
Service+Resource Server stack:

- **XHR no-session → 401.** `curl` with `Sec-Fetch-Mode: cors` and no
  cookie against `/api/me` returns `401` (no `Location`).
- **Navigation no-session → 302.** `curl` with `Sec-Fetch-Mode: navigate`
  + `Sec-Fetch-Dest: document` and no cookie against `/api/me` returns
  `302 /auth/login?return_to=/api/me`.
- **Valid session → 200.** With a `sess:{sid}` pre-seeded in Valkey
  containing a valid `access_token` (or a Keycloak-issued real token in
  live-mode), `curl` to `/api/me` returns `200` with the RS response body.
- **Expiring session → refresh → 200.** With a `sess:{sid}` whose
  `access_token_expires_at` is within the no-refresh window, the Gateway
  calls `/internal/refresh`, the Auth Service rotates the token, the
  Gateway re-reads `sess:{sid}`, the upstream call succeeds, response
  `200`.
- **Signed-CSRF mismatch → 403.** `POST /api/admin` with an `XSRF-TOKEN`
  cookie whose HMAC has been tampered (or whose value does not match the
  header) is rejected with `403` before any upstream call.
- **Allowlist path → 200; off-allowlist → 404.** `/api/me` succeeds with
  a session; `/api/anything-else` returns `404` regardless of session.
- **Inbound Cookie stripped.** RS-side trace (or a mock RS in the test
  harness) asserts that no `Cookie` header is present on the upstream
  call; only `Authorization: Bearer` is present.
- **Tolerant reader.** A `sess:{sid}` payload with extra unknown fields
  is read successfully; a payload missing `access_token_expires_at` is
  treated as "no session".
- **Schema-contract fixture.** Load
  `schema/sess-payload.example.json` (shared with the Auth Service),
  assert the tolerant reader extracts `access_token` and
  `access_token_expires_at` correctly — catches reader-side regressions
  and serialization drift between writer and reader.

## Evidence For Completion

- `apisix.yaml` and the `bff-session` plugin source under
  `api-gateway/plugins/`.
- `api-gateway/tests/` output (`curl` transcripts, exit codes).
- Startup log showing the plugin loaded and the upstream resolved.
- Sample HTTP transcripts (redacted) for the success and the no-session
  branches.

## Blocked Conditions

Stop and report if:

- The pinned APISIX version cannot load the custom `bff-session` plugin
  in standalone mode.
- APISIX's `resty.redis` or `resty.http` is unavailable or does not
  support the operations the plugin needs.
- The Auth Service `/internal/refresh` endpoint contract diverges from
  SPEC-0001 §7.1 in a way that breaks the Gateway-side handling table.
- The configured gateway client (`oidc-reference-api-gateway` by default) or
  the `auth.internal` scope is missing.
