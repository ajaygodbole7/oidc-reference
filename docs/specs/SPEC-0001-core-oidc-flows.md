# SPEC-0001: Core OAuth 2.1 and OIDC Flows (BFF Session Pattern, Split Implementation)

## Problem

Developers need a local, inspectable reference for modern OAuth 2.1 / OIDC that
matches current IETF guidance for browser-based apps: the browser must not hold
access, refresh, or ID tokens. The reference adopts the Backend-for-Frontend
(BFF) session pattern as the recommended browser-app architecture, implements
it as a split between a dedicated Auth Service and a dedicated API Gateway,
and demonstrates Client Credentials side-by-side for service-to-service.

The canonical end-to-end flow is the Mermaid sequence diagram in the root
`README.md`. This spec is the build contract for that diagram.

## Goals

- Implement Authorization Code + PKCE driven by a confidential Auth Service,
  not by the browser. Tokens live in a Redis-compatible server-side state
  store (Valkey locally); the browser sees only an opaque `HttpOnly` session
  cookie.
- Implement Client Credentials from a service client directly to the Resource
  Server (no Auth Service or API Gateway in path).
- Use Keycloak as the local Authorization Server and Identity Provider, with
  three confidential clients (Auth Service, API Gateway, service client).
- Use Spring Boot for the Auth Service (Spring Security OAuth2 Client plus
  custom Redis-compatible repositories for OAuth transactions and sessions)
  and the Resource Server (OAuth2 Resource Server, JWT validation only). Use
  APISIX (OpenResty / nginx + Lua) for the API Gateway, with a custom
  `bff-session` Lua plugin.
- Use a Redis-compatible server-side state store for PKCE-transaction and
  session storage with exact `tx:{state}` and `sess:{sid}` keys. The local
  reference implementation is Valkey.
- Provide positive and negative tests for every authorization boundary.
- Document every realm client, scope, mapper, cookie attribute, state-store
  key, TTL, and validation rule.

## Non-Goals

- A production identity platform.
- Distributing any token to the browser.
- A public-client SPA (referenced only as a comparison footnote).
- Implicit flow or password grant for any reference client.
- Cloud-hosted infrastructure.
- Hand-implementing OAuth/OIDC protocol primitives, cookies, or session
  encoding.

### Explicitly out of scope

The following OAuth / OIDC mechanisms are each a defensible addition to a
more ambitious reference, but are deliberately not built here. This section
exists so a reader does not assume omission is oversight.

- **PAR (RFC 9126, Pushed Authorization Requests).** Recommended by
  RFC 9700 §2.1.1 to prevent authorization-request tampering. Not
  implemented: the BFF demonstrates the same defenses (PKCE, signed CSRF,
  exact-match `redirect_uri`, single-AS) through different primitives.
  Adding PAR would require Keycloak PAR enablement and additional
  Nimbus-side code; it is a self-contained future addition.

- **DPoP (RFC 9449, Demonstrating Proof of Possession).** Sender-
  constraining access tokens via per-request JWT proofs. Not implemented:
  the access token never leaves the gateway → RS hop and never reaches
  the browser, so the bearer-token exfiltration surface DPoP defends
  against is structurally smaller in a BFF. DPoP becomes interesting if
  the reference ever exposes tokens to mobile/native clients.

- **OIDC Front-Channel Logout 1.0.** Not implemented: the cookie-based
  BFF pattern keeps browser session state at the BFF, and RP-Initiated
  Logout plus the implemented Back-Channel Logout endpoint cover this
  reference's local logout contract.

- **OIDC Session Management 1.0** (`check_session_iframe`,
  `session_state`). The cookie-based BFF pattern has no direct browser-AS
  session relationship to monitor; the SPA never talks to the AS.
  Session changes are observed via `/auth/me` polling or by the next
  `/api/**` call failing 401.

- **Encrypted-at-rest session storage in Valkey.** The local reference
  stores `access_token`, `refresh_token`, `id_token` in plaintext in
  Valkey. Production derivations targeting compliance regimes (HIPAA,
  PCI, internal-platform PII rules) must wrap the state store with
  application-layer encryption (envelope encryption with a KMS-managed
  DEK is the obvious shape) or use a managed store that provides this
  natively. The `StateStore` interface is the seam.

- **HSTS / production TLS posture.** The reference runs HTTP-only on
  loopback. `Strict-Transport-Security`, OCSP stapling, certificate
  pinning, and TLS 1.3-only client policies are all production concerns
  not modeled here. The `__Host-` cookie prefix is conditionally applied
  on `X-Forwarded-Proto: https` to demonstrate the production posture
  without requiring TLS termination locally.

- **Distributed per-session refresh lock across HA Auth Service
  instances.** `InternalRefreshController.locksPerSid` is a JVM-local
  `ConcurrentHashMap`. A second `auth-service` instance breaks the
  serialization guarantee: two concurrent refresh calls on the same
  session can hit different instances, both submit the same refresh
  token, one succeeds and the other triggers Keycloak's reuse detection
  → session invalidation. The reference assumes a single instance and
  documents this; an HA derivation should swap to a Valkey-based
  distributed lock (`SET key 1 NX EX 5` with a release fence).

- **Multi-IdP mix-up defense via `iss` parameter validation.** RFC 9700
  §4.4 requires either distinct `redirect_uri` per AS or `iss` parameter
  validation per RFC 9207. The reference targets a single AS (Keycloak)
  and treats this as covered by the single-AS topology. A future
  multi-IdP derivation must add `iss` validation in the callback
  handler. Documented separately as a P1 follow-up rather than fully
  out-of-scope.

## Target Stack

- **Frontend**: React `19.2.6`, TypeScript `6.0.3`, Vite `8.0.14`. No
  in-browser OAuth/OIDC library. Same-origin fetch with
  `credentials: "include"`. The Vite dev server proxies `/auth/*` to the
  Auth Service and `/api/**` to the APISIX gateway so the cookie is
  same-origin in dev. In the full Compose stack, APISIX is the ingress
  directly — there is no separate ingress proxy in front of it.
- **Auth Service**: Java 25, Spring Boot `4.1.0-RC1`, Spring Security
  OAuth2 Client, custom Redis-compatible transaction and session
  repositories. Owns `/auth/*` and `/internal/refresh`. Acts as an OAuth
  Resource Server for `/internal/*`.
- **API Gateway**: APISIX (OpenResty / nginx + Lua), current stable. Routes
  declared in `config.yaml`. Custom Lua plugin `bff-session` performs
  tolerant `sess:{sid}` read from Valkey, bearer injection, signed-CSRF
  validation, and refresh delegation to the Auth Service.
- **Resource Server**: Java 25, Spring Boot `4.1.0-RC1`, Spring Security
  OAuth2 Resource Server. JWT validation only.
- **OIDC endpoint split**: `issuer-uri` remains the canonical
  browser-visible issuer (`http://localhost:8080/realms/oidc-reference`
  locally). Containerized backchannel calls use explicit endpoint config:
  Auth Service gets browser-facing `authorization-uri` / `end-session-uri`
  and internal `token-uri` / `jwks-uri`; Resource Server validates the
  canonical issuer while fetching keys from an internal `jwk-set-uri`.
- **Session store**: Redis-compatible server-side state store. Local
  reference: Valkey 8. Writer: Auth Service. Reader on the bearer-injection
  path: API Gateway (tolerant reader, see §7.2).
- **Authorization Server**: Keycloak.
- **Local infra**: Docker Compose.
- **Tests**: backend unit/integration, APISIX route + plugin tests,
  frontend unit (Vitest `4.1.7`), browser E2E (Playwright `1.60.0`),
  cross-service smoke.

Port allocation:

| Service | Port | Exposure |
|---|---|---|
| APISIX (browser-facing in full Compose) | `9080` | host |
| Keycloak | `8080` | host |
| Auth Service | `8081` | internal-only in full Compose |
| Resource Server | `8082` | internal-only |
| Valkey | `6379` | internal |
| Frontend dev server | `5173` | host (dev only) |

JVM runtime: virtual threads enabled on both Spring services
(`spring.threads.virtual.enabled: true`); ZGC recommended for production.
APISIX runs on its native OpenResty worker model and is unaffected by JVM
settings.

## Authorization Server Portability

The Auth Service and Resource Server must be implemented against standard
OAuth 2.1 / OIDC interfaces, not Keycloak-specific APIs. Keycloak is the
local reference Authorization Server. Provider-specific setup belongs in
provider configuration and docs, not in application code.

**Acceptance:** no Auth Service or Resource Server code branches on
Keycloak-specific issuer names, endpoints, admin APIs, or claim shapes
except through documented configuration.

## Keycloak Realm

- Realm: `oidc-reference`.
- Users: `alice`, `admin`, optional `auditor`.
- Realm roles: `user`, `admin`, `auditor`.
- Client scopes: `openid`, `profile`, `email`, `api.read`, `api.write`,
  `admin.read`, `service.jobs`, **`auth.internal`**, plus a dedicated
  **`api.audience`** scope.
- Protocol mappers (required):
  - `oidc-audience-mapper` on `api.audience` adds `oidc-reference-api` to
    `aud` for every access token that includes the scope.
  - `oidc-audience-mapper` on `auth.internal` adds the configured
    internal-refresh audience to `aud` for every access token that includes
    the scope. Local default: `oidc-reference-auth-internal`. Used by the
    configured gateway client (local default `oidc-reference-api-gateway`)
    to authenticate to the Auth Service on `/internal/*`.
  - `oidc-usermodel-realm-role-mapper` on user-bound clients emits
    `realm_access.roles` (Keycloak default; verify it is not removed).

### Auth Service Client (`oidc-reference-auth`)

- Confidential. Standard flow only. PKCE `S256` required (defense in depth
  alongside the client secret). Implicit and direct grants disabled. Service
  accounts disabled.
- Refresh tokens enabled, **rotation enabled with reuse detection**.
- Redirect URIs:
  - `http://127.0.0.1:5173/auth/callback/idp` for frontend-dev mode where
    Vite is the same-origin development proxy.
  - `http://127.0.0.1:9080/auth/callback/idp` for APISIX-fronted local
    harnesses that drive the gateway directly.
  Both use Spring's `{baseUrl}/auth/callback/{registrationId}` shape with the
  redirection endpoint base URI overridden to `/auth/callback`; registration
  name is the generic `idp`, not the IdP brand.
- Post-logout redirect URIs: `http://127.0.0.1:5173/` and
  `http://127.0.0.1:9080/`. The dev-mode same-origin pattern lands the user
  back on the active browser-facing origin.
- Web origins: none (browser never calls the AS from JavaScript).
- Default scopes: `openid`, `profile`, `email`, `roles`, `api.audience`,
  `api.read`.
- Secret: generated locally, supplied via env, gitignored.

### API Gateway Client (`oidc-reference-api-gateway` Local Default)

- Confidential. **Client Credentials only.** Service accounts enabled.
  Browser flows disabled. Direct access grants disabled. Standard flow
  disabled.
- Default scopes: `auth.internal`.
- Used by the APISIX `bff-session` plugin to obtain a service token whose
  `aud` contains the configured internal-refresh audience. The token is
  presented as the Bearer credential on `POST /internal/refresh` calls to
  the Auth Service.
- Token cache: the Gateway holds a single in-process cached token per
  worker, refreshed proactively when remaining lifetime falls below 60s.
- Secret: generated locally, supplied via env, gitignored.

### Service Client (`oidc-reference-service`)

- Confidential. Client Credentials only. Service accounts enabled. Browser
  flows and direct grants disabled.
- Default scopes: `api.audience`, `service.jobs`.
- Secret: generated locally, supplied via env, gitignored.

## Auth Service + API Gateway Endpoints

### Login Entry Conditions

The OAuth flow is triggered by either:

- **Implicit (saved-request):** any unauthenticated top-level navigation
  to a path that requires a session (e.g., a protected SPA route or, for
  direct browser nav, an `/api/**` path). The API Gateway detects the
  no-session condition on `/api/**` and, when the request is a top-level
  navigation (Fetch Metadata `Sec-Fetch-Mode: navigate` +
  `Sec-Fetch-Dest: document`, with `Accept: text/html` as fallback),
  responds with `302 /auth/login?return_to=<original-URL>`. The Auth
  Service receives `/auth/login?return_to=...`, validates `return_to`,
  persists `saved_request = return_to` in `tx:{state}`, and runs the
  OAuth round-trip. On successful callback the Auth Service returns a
  direct `302` to the saved-request URL with the session cookie set.
- **Explicit:** top-level navigation to `/auth/login?return_to=...`. A
  user-visible Sign in link in the SPA must include `return_to`; a bare
  `/auth/login` link is forbidden. `/auth/login` without `return_to` is
  invalid and fails loudly with `400 application/problem+json`.

`fetch`/XHR to `/api/**` without a session is rejected with `401` (no
`Location` header) by the API Gateway; the Gateway does not redirect XHR
because the AS login page cannot render in an XHR response. The SPA reacts
to `401` by performing a top-level navigation, which the Gateway then
treats as the implicit-entry case.

#### `return_to` validation rules

`return_to` is the browser-facing query parameter on `/auth/login`. It is
the relative URL the browser should return to after login. `saved_request`
is the server-side field persisted in `tx:{state}` after validating
`return_to`; callback replay uses `saved_request`, never `return_to`.

The Auth Service applies these rules at `/auth/login`:

- Method: `GET`.
- `return_to` is required.
- Missing `return_to`: `400 application/problem+json`.
- Empty `return_to`: `400 application/problem+json`.
- Absolute URL: `400 application/problem+json`.
- Protocol-relative URL beginning `//`: `400 application/problem+json`.
- Value not beginning `/`: `400 application/problem+json`.
- Overlong value, default max 2048 characters after decoding:
  `400 application/problem+json`.
- Encoded backslash variants (e.g., `/%5C%5Cevil.example`):
  `400 application/problem+json`.
- Valid value: persist as `saved_request` in `tx:{state}`.

Validation rule:

```text
return_to must be a same-origin relative path beginning with exactly one "/".
```

Valid examples: `/`, `/dashboard`, `/jobs/123?tab=events`,
`/settings#sessions`.

Rejected examples: `https://evil.example/`, `//evil.example/`,
`evil/path`, `javascript:alert(1)`, `/%5C%5Cevil.example`.

`return_to` is never sent to the IdP and is never read from the callback
query string. The callback redirects only to `saved_request` loaded from
`tx:{state}`.

**Acceptance Criteria:** Auth Service's `/auth/login` returns 400
problem+json when `return_to` is missing or invalid (absolute URL,
protocol-relative, no leading slash, overlong, encoded backslash).

### Auth Service Endpoints

| Path | Method | Auth | Purpose |
|---|---|---|---|
| `/auth/login` | GET | none | Explicit and implicit login entry. Requires `return_to` query parameter; validates `return_to` per §"`return_to` validation rules"; missing or invalid `return_to` → `400 application/problem+json` and no transaction is created. Persists `saved_request = return_to` plus PKCE `verifier`, `nonce`, and `created_at` in `tx:{state}` (TTL 5m). Returns `302` to the AS `/auth` endpoint with `code_challenge=S256`, `state`, and `nonce` (no `return_to` or `saved_request` forwarded to the IdP). Sets a per-transaction browser-binding cookie `oauth_tx_<short-hash(state)>` (`HttpOnly`, `SameSite=Lax`, `Path=/auth/callback/idp`, `Max-Age` = the `tx:{state}` TTL); its HMAC is stored as `tx_cookie_hash` in `tx:{state}`. Per-transaction naming lets concurrent logins (multiple browser tabs) each keep their own binding cookie. No **session** cookie is set at this step. |
| `/auth/callback/idp` | GET | none | Atomically reads and deletes `tx:{state}` from the Redis-compatible state store; exchanges code with the AS (`code` + `verifier` + configured client authentication); validates `id_token` (`iss`, `aud = oidc-reference-auth`, `nonce`, sig RS256, exp/nbf); creates a fresh `sess:{sid}` with a newly minted opaque session id; validates `saved_request` is same-origin (replaces with `/` otherwise); returns `302 {saved_request}` with `Set-Cookie __Host-sid=<opaque>; HttpOnly; Secure; SameSite=Lax; Path=/` and `Set-Cookie XSRF-TOKEN=<signed>; Secure; SameSite=Strict; Path=/` (JS-readable). No prior authenticated session existed, so session fixation is mitigated by construction. |
| `/auth/logout` | POST | session | Requires signed double-submit CSRF (§7.3). Invalidate session, delete `sess:{sid}`, clear `__Host-sid` and `XSRF-TOKEN` cookies. Builds the IdP `end_session_endpoint` URL with `id_token_hint` **server-side**, stores it under a single-use opaque handle (`logout:{handle}`, TTL 2m), and returns a **same-origin** JSON body `{"logoutUrl":"/auth/logout/continue?lc={handle}"}`. The id_token (PII) never reaches browser JS or any SPA-readable body — only the server emits the IdP redirect (from `/auth/logout/continue`). The SPA performs a real top-level navigation to the same-origin handle. If no local `sess:{sid}` exists (idled out or already deleted), `/auth/logout` still drives IdP logout: it builds the `end_session` URL with `client_id` and a `post_logout_redirect_uri` set to the configured app base URL (or the forwarded SPA origin) — never a logout request parameter, so no open redirect — attaching `id_token_hint` only when the session's `logout_hint:{sid}` index still survives. CSRF is not required on this branch (no session to protect), and the IdP SSO is terminated even when the local session is gone. |
| `/auth/logout/continue` | GET | none | Resolves the single-use `logout:{handle}` (GET-then-DEL) and `302`s to the IdP `end_session_endpoint` URL with `id_token_hint` and `Referrer-Policy: no-referrer`. Unknown/expired/missing handle → `302` to `/`. No session required (it is already deleted); the opaque handle is the capability. |
| `/auth/me` | GET | session | Return non-sensitive user claims (`sub`, `preferred_username`, `name`, `email`, `roles`). Never returns a token. Response `Cache-Control: no-store`. |
| `/backchannel-logout` | POST | signed `logout_token` (no cookie) | OIDC Back-Channel Logout 1.0 — IdP-to-Auth-Service, `application/x-www-form-urlencoded` with a `logout_token` JWT. Validates the token (IdP JWKS signature, `iss`, `aud` = this client, fresh `iat`, an `events` claim carrying the back-channel-logout event, `sub` and/or `sid` present, **no `nonce`**, `jti` replay-guarded). Resolves the IdP `sid` to the local session via the `idp_sid:{idp_sid}` index and deletes `sess:{sid}`; with only `sub`, deletes every session of that subject. `200` on success, `400` on an invalid/unverifiable token. Never reveals whether a session existed. Reachable only on the internal network. |

### API Gateway Endpoints

| Path | Method | Auth | Purpose |
|---|---|---|---|
| `/api/**` | any | session | Single wildcard handler with a path-pattern allowlist (declared in APISIX `config.yaml`; default `/api/me`, `/api/user-data`, `/api/admin`); paths outside the allowlist return 404. On no-session: top-level navigation → `302 /auth/login?return_to=<URL>`; XHR → `401`. With session: tolerant-read `sess:{sid}` (§7.2); if `access_token_expires_at` is within the refresh window, call `POST /internal/refresh` on the Auth Service (§7.1) and re-read `sess:{sid}`; proxy to Resource Server with `Authorization: Bearer <access_token>`. Strip inbound `Cookie` and hop-by-hop headers; forward query string. Validate signed CSRF (§7.3) on state-changing requests. Response `Cache-Control: no-store`. |

### Internal RPCs

| Path | Method | Auth | Purpose |
|---|---|---|---|
| `/internal/refresh` | POST | Client Credentials (Bearer JWT, `aud` contains configured internal-refresh audience; `azp`/`client_id` equals configured gateway client id) | Auth Service endpoint, called by the API Gateway. Local defaults are `oidc-reference-auth-internal` and `oidc-reference-api-gateway`. Reachable only on the internal Compose network — never via the browser-facing ingress. Performs the refresh-token grant against Keycloak under a per-session lock, validates rotation, emits the `refresh_token_rejected` audit event on `invalid_grant`, and updates `sess:{sid}`. Full contract per §7.1. |

### Session Cookie

- Name in production: `__Host-sid`. In local HTTP mode the name downgrades
  to `sid` and `Secure` is dropped (browsers reject `__Host-` without
  `Secure`).
- Attributes: `HttpOnly`, `Secure`, `SameSite=Lax`, `Path=/`, no `Domain`.
- Value: opaque, ≥128 bits of entropy. Not a token; carries no claims.
- The Auth Service sets the cookie on the `302` response from
  `/auth/callback/idp`; the browser commits the cookie and follows the
  redirect to the saved-request URL. `SameSite=Lax` permits the
  cross-site-then-same-site sequence from Keycloak's callback redirect
  through to the saved-request URL without a landing page.

### State Store Keys

Both keyspaces are logically distinct in the Redis-compatible state store;
neither is multiplexed through a framework-managed HTTP session blob.
`tx:{state}` is addressed by the OAuth `state` parameter (round-tripped
through Keycloak). `sess:{sid}` is addressed only by the opaque session
cookie and is created only after a successful callback. The Auth Service
is the sole writer of both keyspaces. The API Gateway is the sole reader
of `sess:{sid}` on the bearer-injection path.

- `tx:{state}` → `{verifier, nonce, saved_request, created_at, tx_cookie_hash}`.
  TTL 5m. Deleted on callback (success or failure).
  `tx_cookie_hash` is the HMAC of the per-transaction `oauth_tx_<short-hash(state)>`
  browser-binding cookie issued alongside the login 302; the callback derives the
  cookie name from `state`, reads that specific cookie, and rejects when its HMAC
  does not match the stored hash. The cookie is single-use, evicted on callback
  (success or failure). Defends against an attacker who exfiltrated `(code, state)`
  but does not hold the originating browser's cookie.
- `sess:{sid}` → see §7.2 for the full schema and the tolerant-reader
  contract. Sliding idle TTL (default 30m via `SESSION_IDLE_TTL`), absolute cap
  (default 8h via `SESSION_MAX_TTL`, kept ≤ the IdP SSO max). Written
  by the Auth Service's custom state-store session repository after callback; not
  stored in a framework-managed HTTP session.
- Stored in plaintext in local mode. Production guidance: encryption at
  rest, state-store AUTH, TLS, network isolation.
- Secondary indexes, written by the Auth Service alongside `sess:{sid}` and used
  only by the logout paths: `idp_sid:{idp_sid}` → local `sid` (maps an IdP
  Back-Channel Logout token's `sid` to the local session), `sub_sessions:{sub}`
  → the set of a subject's local `sid`s (subject-wide logout), and
  `logout_hint:{sid}` → the session's `id_token`, retained so a logout can supply
  `id_token_hint` to the IdP `end_session` endpoint. Each is TTL-bounded by the
  session's absolute ceiling; a stale index entry outliving a dead `sess:` key is
  harmless (the delete paths tolerate it).

### Refresh and Rotation

- The API Gateway initiates refresh when `sess:{sid}.access_token_expires_at`
  is within 60s. Refresh is delegated to the Auth Service via
  `POST /internal/refresh` (§7.1); the Gateway does not call Keycloak
  directly for refresh.
- Refresh tokens are rotated; reuse invalidates the session and emits a
  security audit log event from the Auth Service.

### Concurrency

Concurrent `/api/**` requests on a single session can both detect an
expiring access token and both call `/internal/refresh`. With rotation
(`refreshTokenMaxReuse: 0`) a second concurrent refresh against Keycloak
would fail with `invalid_grant` and destroy the session. The Auth Service
serializes the refresh window with a per-session lock so only one refresh
is in flight per session; the second caller re-reads `sess:{sid}` under
the lock and returns the already-rotated token. The in-process lock map
is bounded by session lifetime; a clustered Auth Service must replace it
with a distributed lock (e.g., Valkey `SET NX EX`).

### Session Lifecycle

- No pre-callback **session** cookie. The Auth Service sets only the
  per-transaction `oauth_tx_<short-hash(state)>` browser-binding cookie at
  `/auth/login` (scoped `Path=/auth/callback/idp`); the only pre-auth server-side state is
  `tx:{state}` (keyed by the OAuth `state` parameter). Login-CSRF and session-swapping
  are defended by `state` + PKCE + `nonce` per RFC 9700 §4.7; see decision
  B3 and the Threat Model row below.
- `sess:{sid}` is created only on successful callback, with a freshly
  generated opaque session id. Session fixation is structurally
  impossible — there is no prior session to fixate.
- On logout the session cookie and the CSRF cookie are expired
  (`Max-Age=0`) and `sess:{sid}` is deleted from the Redis-compatible
  state store before the browser is redirected to Keycloak's end-session
  endpoint.

### CSRF

Signed, session-bound double-submit token. See §7.3 for the full token
format, validation algorithm, and signing-key handling.

- The Auth Service sets `XSRF-TOKEN` as a JS-readable cookie (not
  `HttpOnly`) with `Secure`, `SameSite=Strict`, `Path=/`. The cookie value is
  `<token-value-base64>.<hmac-base64>` — the signed token.
- The SPA reads `XSRF-TOKEN` and echoes the full value as the
  `X-XSRF-TOKEN` header on every `POST`/`PUT`/`DELETE`/`PATCH`.
- Validators (Auth Service for `/auth/*`; APISIX `bff-session` plugin for
  `/api/**`) compare cookie to header for exact match, then recompute the
  HMAC over `token-value-base64 + ":" + sid` and compare in constant time.
  Mismatch or invalid signature → 403.
- The session cookie (`__Host-sid` in prod, `sid` in local) is `HttpOnly`
  and never readable by JS; it is not part of the double-submit pair.
- **Naive double-submit is explicitly rejected.** Comparing an unsigned
  cookie value to the same value echoed in a header is defeated by
  cookie injection from a sibling-subdomain XSS or `document.cookie`
  write vulnerability — the attacker can set a matching cookie+header
  pair in the victim's browser. Signing breaks the attack because the
  attacker cannot forge a valid HMAC without the server-side signing key.

## Resource Server

### Endpoints

- `GET /api/public` — no authentication.
- `GET /api/me` — authenticated user token; returns `sub`.
- `GET /api/user-data` — requires scope `api.read`.
- `POST /api/admin` — requires authority `ROLE_admin` (mapped from
  `realm_access.roles`). Scope-based admin is documented as a non-default
  alternative.
- `POST /api/jobs` — requires scope `service.jobs`.

### JWT Validation

- Issuer (from `OIDC_ISSUER_URI`).
- Signature via Keycloak JWKS.
- Expiration; not-before when present.
- Algorithm allowlist: `RS256` only.
- Access-token audience contains `oidc-reference-api` (custom
  `JwtClaimValidator`). This is separate from `id_token.aud`, which is the
  Auth Service client id (`oidc-reference-auth`) and is validated only by
  the Auth Service during callback.
- Scope and role authorities populated by a custom
  `JwtAuthenticationConverter` that lifts standard `scope` / `scp`
  claims → `SCOPE_*` and the configured role claim path
  (`app.roles-claim-path`) → `ROLE_*`.

### API Behavior

- Stateless. No sessions, no cookies. CORS denies browser origins (defense
  in depth — browser is never expected to reach the RS directly).
- Bound to an internal Compose network in the canonical stack.
- Errors as RFC 7807 `application/problem+json` via Spring `ProblemDetail`.
- Audit log for denied access and validation failures, non-secret metadata
  only. Never logs tokens, codes, cookies, or secrets.

## Frontend Behavior

- No OAuth/OIDC client library.
- Sign in is a top-level navigation to `/auth/login` (not a fetch).
- After the OAuth round-trip the Auth Service responds with a direct `302`
  to the saved-request URL with `__Host-sid` and `XSRF-TOKEN` cookies set.
  For explicit `/auth/login`, the saved request defaults to `/`. The SPA
  then loads user state from `/auth/me`.
- All API calls go to `/api/**` (same origin via the dev proxy or APISIX)
  with `credentials: "include"`.
- Logout is `POST /auth/logout` with the `X-XSRF-TOKEN` header.
- The SPA never reads, parses, stores, or logs any token. Frontend
  authorization is display-only; the Auth Service, API Gateway, and RS
  enforce all access.
- **Dev plumbing.** The Vite dev server proxies with two upstreams:
  `/auth/*` → Auth Service `http://127.0.0.1:8081`; `/api/**` → APISIX
  `http://127.0.0.1:9080`. Both legs use `changeOrigin: false` and inject
  `X-Forwarded-Host` / `-Proto` / `-Port`. The Auth Service has
  `server.forward-headers-strategy: framework` so Spring computes
  `baseUrl` as the SPA origin, the OAuth `redirect_uri` matches the
  registered URI `http://127.0.0.1:5173/auth/callback/idp`, and the
  session cookie is bound to the SPA origin so subsequent same-origin
  fetches carry it.
- **Full Compose plumbing.** APISIX is the browser-facing ingress
  directly on `:9080`; there is no separate ingress proxy. APISIX routes
  `/auth/*` to the Auth Service and `/api/**` through the `bff-session`
  plugin to the Resource Server. APISIX forwards `X-Forwarded-Host` /
  `-Proto` / `-Port` to the Auth Service for consistent
  `redirect_uri` computation across the two ingress shapes.

## Threat Model

| Threat | Mitigation |
|---|---|
| Authorization code interception | PKCE `S256` required; codes single-use; short TTL |
| PKCE downgrade | Realm enforces `S256` |
| Redirect URI manipulation | Exact match in Keycloak; no wildcards |
| Token theft via JavaScript | Access/refresh tokens never reach the browser; ID tokens never reach browser JS, storage, or SPA-readable bodies (token-isolation invariant in Acceptance Criteria); cookie is `HttpOnly` |
| XSS on SPA | No tokens to steal; CSP is recommended in production guidance |
| Login CSRF / session swapping | `state` (server-side validated against `tx:{state}`) + PKCE code-verifier (S256, required) + ID-token `nonce` validation per RFC 9700 §4.7 |
| CSRF on state-changing endpoints | **Signed, session-bound** double-submit `XSRF-TOKEN` (HMAC-SHA256 over `token-value-base64 + ":" + sid`) + `X-XSRF-TOKEN` header on POST/PUT/DELETE/PATCH. Naive double-submit explicitly rejected — see decision B4. `GET /auth/login` is intentionally cross-navigable. |
| Session fixation | Session id regenerated after login |
| Cookie scoping | `HttpOnly`, `SameSite=Lax`, `Path=/`, no `Domain`; `Secure` + `__Host-` prefix in production |
| Session-store compromise | Production: state-store AUTH, TLS, network isolation, encryption at rest |
| API Gateway as SSRF | `/api/**` allowlist only in APISIX route config; no arbitrary upstream URLs |
| Open redirect | Saved-request target is same-origin validated; Auth-Service-issued redirects use fixed or allowlisted targets |
| Access token replay | Short access-token lifetime; audience binding |
| Audience confusion | Auth Service validates `id_token.aud = oidc-reference-auth`; Auth Service `/internal/*` validates Bearer `aud` contains the configured internal-refresh audience and `azp/client_id` equals the configured gateway client id; RS validates `access_token.aud` contains the configured API audience |
| Internal-RPC compromise | `/internal/refresh` reachable only on the internal Compose network; Bearer-validated Client Credentials with audience binding; per-session lock prevents concurrent refresh races |
| CSRF signing-key compromise | 256-bit env-supplied secret, gitignored; current implementation is single-key hard cutover. Dual-key grace-window rotation is production hardening. |
| Overbroad scopes | Per-client default scopes are least-privilege |
| Role mapping drift | Single mapping path tested both ends |
| Refresh token misuse | Rotation + reuse detection |
| Client secret leakage | Generated locally, gitignored, supplied via env |
| Realm import drift | Smoke test issues a real token and inspects claims |
| Local HTTP vs production HTTPS | Production guidance documents `Secure` + `__Host-` |

## Trust Boundaries

The split-implementation form introduces inter-service trust relationships
that must be made explicit so a future contributor cannot accidentally
add a fourth service that violates them.

- **Browser ↔ stack.** The only browser-facing surfaces are APISIX on
  `:9080` (for `/auth/*` and `/api/**`) and Keycloak on `:8080` (for
  `/realms/*`). Auth Service, Resource Server, and Valkey are
  unreachable from the host except via the Compose `oidc-internal`
  network. The Gateway is the single browser security boundary;
  anything past it has already had cookie + signed-CSRF + Fetch-Metadata
  validation applied (or is the OIDC dance with Keycloak).

- **Gateway → Auth Service.** Mutual non-trust at the transport level.
  Every call to `/internal/*` carries a Client Credentials bearer token
  issued to the configured gateway client, validated by Auth Service per
  the §7.1 contract (`iss`, `sig`, `exp`, configured internal-refresh
  `aud`, configured gateway `azp`/`client_id`, `alg=RS256`). Local
  defaults are `oidc-reference-api-gateway` and
  `oidc-reference-auth-internal`. No shared secrets between services, no
  trusted-network assumption.

- **Gateway → Valkey, Auth Service → Valkey.** Shared single-tenant
  keystore. The Auth Service is the **sole writer** to `tx:*` and
  `sess:*`. The Gateway is the **sole non-Auth-Service reader** of
  `sess:*` (only the two required fields named in §7.2). No other
  service may read or write these keyspaces. Trust here is via
  infrastructure isolation: Valkey is on the internal network with no
  host port in production-shape deployments, and no AUTH is configured
  in the local reference (production must add one). A fourth reader or
  writer would introduce a confused-deputy class of bug.

- **Auth Service → Keycloak, Gateway → Keycloak.** Each service
  authenticates to Keycloak as its own confidential client. Tokens
  obtained by one service are never lent to the other. The Gateway's
  CC token (for `/internal/refresh`) and Auth Service's user-flow
  tokens (for the OIDC dance) are issued independently.

- **Tokens never reach the browser.** This is preserved verbatim from
  the combined-BFF design. The split changes *where* the OIDC client
  logic lives; it does not move tokens. `__Host-sid` is the only
  identifier the browser sees, and it is an opaque random value.

## API Gateway Architecture (APISIX)

The API Gateway is APISIX (OpenResty / nginx + Lua), current stable. It
runs on port `9080` and is the browser-facing ingress directly in the full
Compose stack — no separate ingress proxy sits in front of it. Routes are
declared in `config.yaml`; runtime configuration is reloaded without
restarting the worker processes.

**Custom plugin: `bff-session`.** A single Lua plugin attached to every
`/api/**` route does the BFF-side gateway work in one pass per request:

1. **Session lookup.** Read `__Host-sid` (or `sid` in local HTTP) and
   `GET sess:{sid}` from Valkey via the `lua-resty-redis` client. Apply
   the tolerant-reader contract (§7.2): consume only `access_token` and
   `access_token_expires_at`; treat any payload missing those fields as
   "no session" and log.
2. **No-session branching.** Distinguish top-level navigation from XHR
   using Fetch Metadata: `Sec-Fetch-Mode: navigate` +
   `Sec-Fetch-Dest: document` (with `Accept: text/html` as fallback) →
   respond `302 /auth/login?return_to=<original-URL>`; otherwise → `401`
   with no `Location` header.
3. **Refresh check.** If `access_token_expires_at` is within 60s,
   call `POST /internal/refresh` on the Auth Service (§7.1) with the
   cached configured gateway-client service token. Map response codes to
   browser-facing status per the §7.1 handling table. On 200, re-read
   `sess:{sid}` to pick up the rotated access token.
4. **Signed CSRF validation.** On state-changing methods
   (`POST`/`PUT`/`DELETE`/`PATCH`), validate the signed double-submit
   token per §7.3. Mismatch or invalid signature → 403.
5. **Path allowlist.** The allowlist is the set of route patterns
   declared in APISIX `config.yaml`; paths outside the allowlist match
   no route and APISIX returns 404 before the plugin runs.
6. **Bearer injection and hop-by-hop stripping.** Set
   `Authorization: Bearer <access_token>` on the upstream request to the
   Resource Server. Strip inbound `Cookie` and standard hop-by-hop
   headers (`Connection`, `Keep-Alive`, `Proxy-*`, `TE`, `Trailers`,
   `Transfer-Encoding`, `Upgrade`). Preserve the query string.

**Service-token cache.** The plugin holds a single in-process cached
service token per nginx worker for the configured gateway client
(`oidc-reference-api-gateway` by default). Proactive refresh when
remaining lifetime falls below 60s; serialized with a worker-local lock so
concurrent requests do not trigger duplicate Keycloak calls. Invalidated
on Auth Service 401 (per §7.1).

**Timeouts on `/internal/refresh`** per §7.1: connect 1s, read 5s.
Rolling-window circuit breaking is not implemented in the reference
gateway; APISIX's built-in `api-breaker` plugin is the production
primitive to add when operating beyond local reference scope.

**No Java, no Spring.** The Gateway is APISIX configuration plus the
`bff-session` Lua plugin module. The plugin's specification (state
contract, response codes, header handling) is the spec sections above
plus §7.1, §7.2, and §7.3.

## 7. Internal Contracts

### 7.1 `/internal/refresh` Contract

```
POST /internal/refresh
Host: auth-service  (internal network only; not reachable via Ingress)
Authorization: Bearer <api-gateway service token>
Content-Type: application/json

Request body:
{
  "sid": "<opaque session identifier>"
}

Bearer-token validation requirements (Auth Service):
  - iss     = configured Keycloak issuer
  - sig     = valid signature per JWKS
  - exp     = not expired
  - aud     contains configured internal-refresh audience
              (default "oidc-reference-auth-internal")
  - azp or client_id = configured gateway client id
              (default "oidc-reference-api-gateway")
  - alg     = RS256
  - scope   contains "internal.refresh"  (if scope-based authorization
            is enabled; otherwise audience binding alone is sufficient)

Success response:
  HTTP/1.1 200 OK
  Content-Type: application/json
  {
    "refreshed_at": "<ISO-8601 UTC>",
    "access_token_expires_at": "<ISO-8601 UTC>"
  }

Error responses:
  HTTP/1.1 401 Unauthorized
    - Bearer token invalid, expired, or wrong audience/client.
    - Body: application/problem+json with non-secret reason.

  HTTP/1.1 404 Not Found
    - No sess:{sid} exists for the given sid (session expired,
      logged out, or never existed).
    - Body: application/problem+json.

  HTTP/1.1 409 Conflict
    - Refresh rejected by Keycloak (invalid_grant) — session invalidated.
    - Auth Service emits the refresh_token_rejected audit event before returning.
    - Body: application/problem+json.

  HTTP/1.1 502 Bad Gateway
    - Keycloak unreachable or refresh-token grant failed for non-
      reuse reason.
    - Body: application/problem+json.

Auth Service preconditions and behavior:
  1. Validate the Bearer token per the requirements above.
  2. Look up sess:{sid} in Valkey. If missing, return 404.
  3. Acquire the per-session refresh lock (in-process ReentrantLock
     keyed by sid; or Valkey SET NX EX for clustered deployments).
  4. Re-read sess:{sid} under the lock (another caller may have just
     refreshed).
  5. If access_token_expires_at is still within the no-refresh window
     (> threshold seconds from now), return 200 with current expiry.
     This makes /internal/refresh idempotent under contention.
  6. Otherwise, if the refresh token is itself already past expiry, emit the
     refresh_rejected (refresh_token_expired) audit event, DEL sess:{sid},
     release lock, return 404 — a predictable session end, not a failed grant,
     so it never reaches the reuse/rejection path below.
  7. Otherwise, POST grant_type=refresh_token to Keycloak.
  8. On invalid_grant from Keycloak (refresh token expired/revoked, SSO max
     reached, or genuine reuse — RFC 6749 §5.2 does not distinguish them, and
     the RP cannot attribute the cause): emit the refresh_token_rejected /
     session_invalidated audit event, DEL sess:{sid}, release lock, return 409.
  9. On success: validate rotation (new refresh token differs from
     old), update sess:{sid} with new tokens and new
     access_token_expires_at, release lock, return 200.
  10. On other Keycloak failure: release lock, return 502.
```

**API Gateway-side handling of each `/internal/refresh` response.**

| Status | Gateway action |
|---|---|
| 200 | Re-read `sess:{sid}` to pick up the rotated access token; proceed with the original request. |
| 401 | The Gateway's own Client Credentials token failed validation at Auth Service. Invalidate the Gateway's cached service token, fetch a new one from Keycloak, retry the refresh call **once**. If the second attempt also returns 401, return `502` to the browser and emit a Gateway-side security audit event — the Gateway's identity is misconfigured or its Keycloak client has been disabled. |
| 404 | Session was logged out concurrently or expired between the Gateway's read and the refresh attempt. Return `401` to the browser, expire `__Host-sid`, and rely on the SPA to trigger a fresh login on the next top-level navigation. |
| 409 | Refresh rejected by Keycloak (`invalid_grant`) — Auth Service has invalidated `sess:{sid}` and emitted the `refresh_token_rejected` audit event (the cause may be reuse, but is not provable at the RP). Return `401` to the browser, expire `__Host-sid`, and emit a Gateway-side audit event for trace correlation. |
| 502 | Keycloak transient failure during refresh. Return `503 Service Unavailable` to the browser with `Retry-After: 1`. Do **not** expire `__Host-sid` — the session itself is still valid; refresh is temporarily unavailable. |

**Client Credentials token cache (API Gateway).**

The API Gateway holds a cached service token issued by Keycloak under
`grant_type=client_credentials`. The cache discipline:

- Single in-process cache entry per worker. No per-request Keycloak
  round-trip in steady state.
- Token is refreshed **proactively** when remaining lifetime falls below
  a configurable threshold (default 60 s). Proactive refresh is
  serialized with a worker-local lock so concurrent API requests do not
  trigger duplicate Keycloak calls.
- On Keycloak unavailability during proactive refresh: use the still-
  valid cached token until expiry. If expiry is reached and Keycloak
  is still unreachable, fail closed — return `503` for inbound API
  requests that need to call `/internal/refresh`. Inbound requests
  that do not need refresh (access token still fresh in `sess:{sid}`)
  are unaffected.
- On 401 from Auth Service for the Gateway's token (per the failure
  table above): invalidate the cache entry and re-fetch.
- The cache is **not** shared across Gateway workers or instances. Each
  worker holds its own.
- **Cache-cliff assumption.** Proactive refresh assumes client-credentials
  tokens live well over the skew (default 60 s). If an IdP issues CC tokens with
  `expires_in ≤ 60 s`, every refresh-window `/api` request misses the cache and
  serializes through a single IdP token call. Cheap mitigation: make the skew a
  fraction of `expires_in` rather than a fixed 60 s.

**Timeout and circuit-breaker on `/internal/refresh`.**

The Gateway's call to `/internal/refresh`:

- Connect timeout: 1 s.
- Read timeout: 5 s. The call may include a Keycloak round-trip inside
  Auth Service; 5 s is generous for healthy operation and tight enough
  to fail fast under contention.
- Rolling-window circuit breaking is production hardening, not shipped
  reference behavior. If added with APISIX `api-breaker`, it must
  distinguish *transport / 5xx* failures from *200 / 401 / 404 / 409*
  responses so normal session-loss conditions do not trip the breaker.

### 7.2 `sess:{sid}` Schema Contract

The Valkey value at key `sess:{sid}` is a JSON object. The Auth Service
is the sole writer. The API Gateway is the sole reader for the bearer-
injection path; it uses a **tolerant reader** that consumes only the
fields it needs.

Required fields (API Gateway depends on these):

```
{
  "access_token":             "<JWT>",                 // string
  "access_token_expires_at":  "<ISO-8601 UTC>",        // string
  ... // other fields ignored by the API Gateway
}
```

Full schema (Auth Service writes; reserved for Auth Service internal
use beyond what the Gateway needs):

```
{
  "access_token":             "<JWT>",
  "refresh_token":            "<opaque>",
  "id_token":                 "<JWT>",
  "access_token_expires_at":  "<ISO-8601 UTC>",
  "refresh_token_expires_at": "<ISO-8601 UTC>",
  "created_at":               "<ISO-8601 UTC>",
  "absolute_expires_at":      "<ISO-8601 UTC>",
  "claims": {
    "sub":                    "<subject>",
    "preferred_username":     "<string>",
    "name":                   "<string>",
    "email":                  "<string>",
    "roles":                  ["<role>", ...]
  }
}
```

`absolute_expires_at` is the hard ceiling (default 8h from `created_at`, kept
≤ the IdP's SSO max session lifespan) past
which the session MUST be evicted regardless of sliding TTL. The Auth Service
re-checks this on every `/auth/me` read and on every `/internal/refresh` —
crossing the boundary during a refresh round-trip causes an explicit DEL +
404 instead of relying on backend-dependent `EXPIRE k 0` semantics.

The signed CSRF token (§7.3) is issued to the browser as the `XSRF-TOKEN`
cookie on the same 302 that sets `__Host-sid`; it is not stored in
`sess:{sid}`. Validation is stateless: cookie and header must match, and
the HMAC must verify against `token-value-base64 + ":" + sid`. No
session-store read is required for CSRF validation.

Sliding idle TTL is enforced by the API Gateway on authenticated `/api/**`
traffic with `EXPIRE sess:{sid} min(SESSION_IDLE_TTL,
remaining_absolute_ttl)`. `/auth/me` and other Auth Service read probes do
not slide the idle window. There is no `last_touched_at` field because the
Redis-compatible TTL itself is the source of truth. A future iteration that
wants a separate watermark field can add one without breaking the tolerant
reader.

Schema contract rules:

1. The API Gateway MUST read only `access_token` and
   `access_token_expires_at`. It MUST NOT depend on any other field.
2. The Auth Service MAY add fields to the schema at any time. The Gateway
   ignores unknown fields (Jackson + cjson both default to that). Adding a
   field is a non-breaking change because of the tolerant-reader contract.
3. The Auth Service MUST NOT remove or rename existing required fields
   without a coordinated change to the Gateway's reader and to
   `schema/sess-payload.example.json` (the cross-component contract fixture).
4. The Gateway MUST log and treat as "no session" any payload it cannot
   parse or whose `access_token_expires_at` is absent.

**Contract test (mandatory).**

A shared JSON fixture is checked into the repository as the canonical
example of a `sess:{sid}` payload — suggested location
`schema/sess-payload.example.json`. Both services include this fixture
in their test suites:

- **Auth Service test.** Construct a session through the service's
  session writer, serialize, parse against the fixture's required
  fields, assert every required field is present and well-typed.
  Catches writer-side field removals, renames, or type drift.
- **API Gateway test.** Load the fixture as a JSON document, invoke
  the Gateway's tolerant reader, assert `access_token` and
  `access_token_expires_at` are extracted correctly. Catches reader-
  side regressions and JSON-library configuration drift (the two
  services must serialize/parse with compatible settings — UTC
  timestamps, no field reordering required, no special-character
  escaping divergence).

Both tests run in their respective test commands and execute under
`scripts/verify-all.sh`. Schema drift is caught by either test failing,
preventing the writer and reader from silently diverging across deploys.

### 7.3 Signed CSRF Token Contract

The CSRF token is **signed**, not naive. Defense against cookie
injection requires either an HMAC signature the server verifies on
receipt or a server-side session binding.

**Token format (HMAC variant — the reference's chosen shape):**

```
<token-value-base64> "." <hmac-base64>

where:
  token-value-base64 = base64url-encoded random 128-bit value
  hmac-base64        = base64url-encoded HMAC-SHA256(signing_key, token-value-base64 + ":" + sid)
```

**Cookie attributes for `XSRF-TOKEN`:**

- Path `/`
- `Secure` (in production; dropped in local HTTP)
- `SameSite=Strict` — the SPA only reads this cookie for echo on
  same-origin XHR/fetch; it never needs to ride a cross-site top-level
  navigation. `Strict` prevents the cookie from being attached to any
  cross-site request at all, tightening the surface beyond what the HMAC
  signature alone provides. `SameSite` governs SEND, not SET, so the
  cross-site Keycloak → callback redirect that ISSUES this cookie is
  unaffected.
- **NOT** `HttpOnly` — the SPA must read it
- No `Domain` attribute
- Value: the full signed token (`<token-value-base64>.<hmac-base64>`)

**Header on state-changing requests:**

- `X-XSRF-TOKEN: <full signed token>`

**Validation (Auth Service and API Gateway):**

1. Extract the cookie value and the header value.
2. Reject if either is missing.
3. Reject if they do not match exactly (cheap check first).
4. Split on the `.` separator.
5. Recompute HMAC-SHA256(signing_key, token-value-base64 + ":" + sid).
6. Reject if the recomputed HMAC does not match the supplied HMAC
   (constant-time comparison).
7. Accept.

**Signing key:**

- Single shared key between Auth Service and API Gateway.
- Supplied via env (gitignored), 256-bit random.
- Current implementation accepts one active key. Rotation is a hard
  cutover: existing CSRF cookies become invalid and the user must obtain
  a fresh session. Dual-key grace-window acceptance is production
  hardening, not shipped reference behavior.
- The signing key is a secret; subject to the same handling rules as
  the Keycloak client secrets (decision E2).

**Naive-double-submit rejection.** The reference explicitly rejects
plain "compare cookie value to header value" without signature
verification. The attack model: an attacker with an XSS or
`document.cookie` write vulnerability on a sibling subdomain
(`evil.example.com` against `app.example.com`) can set a cookie value
in the victim's browser; combined with the ability to issue cross-site
requests, they can craft a request whose cookie and header match,
defeating naive double-submit. Signing breaks this — the attacker
cannot forge a valid signature.

## Acceptance Criteria

- One documented command (`just up` / `scripts/up.sh`) starts Keycloak,
  Valkey, Auth Service, Resource Server, and API Gateway (APISIX) in
  Compose; the SPA runs via `just dev`.
- A dedicated authenticated end-to-end gate (`just e2e-auth` /
  `scripts/e2e-auth.sh`) drives a real Keycloak login, an authenticated
  `/api/**` call, role enforcement, RP-initiated logout through the
  same-origin `/auth/logout/continue` handle, and gateway refresh delegation
  using a real login-derived `sess:{sid}` whose `access_token_expires_at` is
  moved inside the refresh window. Refresh tests must not seed fake
  `refresh_token` material.
- Realm configuration reproducible from source-controlled JSON. No committed
  secrets; Auth Service, API Gateway, and service-client secrets generated
  locally and gitignored. CSRF signing key generated locally and gitignored.
- SPA contains no OAuth/OIDC client library and no token-handling code.
- Tokens written only to the Redis-compatible server-side state store; never
  to logs, browser storage, or response bodies.
- **Token-isolation invariant.** Access tokens and refresh tokens must never
  reach the browser. ID tokens must never reach browser JavaScript, browser
  storage, frontend code, SPA-readable JSON, SPA-visible cookies, or app
  logs. If RP-initiated logout keeps `id_token_hint`, the ID token may appear
  only in a server-generated top-level redirect from `/auth/logout/continue`
  to the IdP. Authorization codes are allowed only as normal OIDC
  front-channel callback artifacts.
- Session cookie is `HttpOnly`, `SameSite=Lax` (and `Secure` + `__Host-` in
  production guidance; downgraded to `sid` without `Secure` in local HTTP).
- Resource Server rejects invalid issuer, audience, expiration, algorithm,
  scope, role. Every check has a negative test.
- Audience checks are token-type-specific: Auth Service validates
  `id_token.aud` against `oidc-reference-auth`; Auth Service `/internal/*`
  validates Bearer `aud` contains the configured internal-refresh audience
  and `azp/client_id` equals the configured gateway client id; RS validates
  `access_token.aud` against the configured API audience.
- Client Credentials demonstrated end-to-end without Auth Service or API
  Gateway involvement (service client → Keycloak → RS).
- Every protected endpoint has positive and negative authorization tests.
- Docs explain every client, scope, mapper, cookie attribute, state-store key,
  TTL.
- Runs locally with no cloud services.
- Saved-request replay: after a successful callback the Auth Service returns
  a direct `302` to the URL the browser originally requested (not
  unconditionally `/`). The saved URL is validated as same-origin before it
  is used as the redirect target.
- Login CSRF protection: `state` is server-side validated against
  `tx:{state}`, PKCE `S256` is required, and the ID-token `nonce` matches
  the stored nonce; no authenticated session cookie is set before
  successful callback.
- XHR `fetch` to `/api/**` without a session returns `401` (no `Location`)
  from the API Gateway; top-level navigation to `/api/**` without a session
  returns `302 /auth/login?return_to=...`.
- `/auth/login` returns `400 application/problem+json` when `return_to` is
  missing or invalid (absolute URL, protocol-relative, no leading slash,
  overlong, encoded backslash).
- API Gateway `/internal/refresh` precondition: the Auth Service rejects
  any `/internal/refresh` call lacking a valid Bearer token whose `aud`
  contains the configured internal-refresh audience and whose
  `azp/client_id` equals the configured gateway client id.
- Signed CSRF token rejection on tamper: a token whose `token-value-base64`
  is modified but whose HMAC is unchanged is rejected; a token with a
  forged HMAC is rejected; only a token whose HMAC matches the recomputed
  HMAC (in constant-time comparison) is accepted.
- Client Credentials end-to-end: a real service-client `curl` call
  obtains a token from the AS and successfully reaches the Resource
  Server on `/api/jobs`, end-to-end with no Auth Service or API Gateway
  in the path.

## Test Plan

**Authorization Server**

- Realm import succeeds; OIDC discovery returns expected issuer; JWKS
  reachable.
- Auth Service client (`oidc-reference-auth`): confidential, PKCE `S256`
  required, refresh rotation enabled.
- API Gateway client (`oidc-reference-api-gateway` local default):
  confidential, Client Credentials only, service accounts enabled, browser
  flows disabled, direct access grants disabled, default scope
  `auth.internal`.
- Service client: cannot perform Authorization Code Flow.
- `smoke.sh` issues a real service token via `curl` and asserts `aud`
  contains `oidc-reference-api` and `scope` contains `service.jobs`.
- `smoke.sh` issues a real API Gateway service token via `curl` and asserts
  `aud` contains the configured internal-refresh audience.

**Auth Service**

- `/auth/login` with a valid `return_to` issues 302 to the AS with
  `code_challenge=S256`, `state`, and `nonce`. `tx:{state}` includes
  `verifier`, `nonce`, `saved_request = <validated return_to>`, and
  `created_at`. The `oauth_tx` browser-binding cookie is set (no session
  cookie). The IdP authorization redirect does not contain `return_to` or
  `saved_request`.
- `/auth/login` without `return_to` returns `400 application/problem+json`
  and creates no `tx:{state}`.
- `/auth/login` with each invalid `return_to` variant (absolute URL,
  protocol-relative `//`, no leading `/`, overlong > 2048 chars after
  decoding, encoded backslash) returns `400 application/problem+json`.
- Implicit entry via the Gateway: top-level navigation to a protected URL
  without session arrives at `/auth/login?return_to=<URL>`; the Auth
  Service validates `return_to` and persists `saved_request = return_to`.
- Callback uses only `tx:{state}.saved_request`; any callback query
  parameter that tries to override the return target is ignored.
- Callback rejects mismatched `state` (no matching `tx:{state}` record).
- Callback rejects mismatched `id_token` `nonce`.
- Callback rejects unsigned / expired / wrong-issuer / wrong-audience
  `id_token`. Wrong audience means `id_token.aud != oidc-reference-auth`;
  it is not the Resource Server audience.
- Callback responds with a direct `302` to the validated saved-request URL
  (no intermediate landing page); response sets `__Host-sid` with
  `HttpOnly`, `Secure`, `SameSite=Lax`, `Path=/` and `XSRF-TOKEN` (signed,
  JS-readable) with `Secure`, `SameSite=Strict`, `Path=/`.
- Session cookie is set only after successful callback.
- Callback creates exactly one `sess:{sid}` key in the state store after
  ID-token validation; tests assert no framework-managed HTTP session key
  is used as the source of truth for tokens or claims.
- Session id regenerated on login.
- `tx:{state}` deleted after callback success and failure.
- `sess:{sid}` respects sliding + absolute TTL.
- Logout deletes session, expires `__Host-sid` and `XSRF-TOKEN`, and
  issues Keycloak end-session redirect with `id_token_hint`.
- **`/internal/refresh` contract tests (§7.1).** Rejects requests with
  missing Bearer token (401). Rejects token with wrong `aud` (401),
  wrong `azp/client_id` (401), bad signature (401), expired (401). With
  valid Bearer and unknown `sid`, returns 404. With valid Bearer and
  valid `sid` whose access token is not yet near expiry, returns 200 with
  current expiry (idempotent under contention). With valid Bearer and
  valid `sid` whose token is near expiry, calls Keycloak refresh, updates
  `sess:{sid}`, returns 200 with new expiry. When the stored refresh token is
  already past expiry, short-circuits to 404 (refresh_token_expired) without
  calling Keycloak. On Keycloak `invalid_grant` (reuse, expiry, revocation, or
  SSO max — indistinguishable at the RP), emits the refresh_token_rejected
  audit event, deletes `sess:{sid}`, and returns 409. On Keycloak transient
  failure, returns 502. Per-session lock prevents concurrent duplicate refresh.
- **Signed CSRF tests (§7.3).** Forged signature rejected. Tampered
  `token-value-base64` with unchanged HMAC rejected. Valid token from
  another `sid` rejected. Mismatched cookie vs. header rejected. Missing
  cookie or missing header rejected. Valid same-session signed token
  accepted.

**API Gateway (APISIX `bff-session` plugin)**

- `/api/**` paths outside the allowlist return 404.
- No-session on `/api/**`: top-level navigation (Fetch Metadata
  `Sec-Fetch-Mode: navigate` + `Sec-Fetch-Dest: document`, with `Accept:
  text/html` as fallback) → `302 /auth/login?return_to=<URL>`; XHR/fetch →
  `401` with no `Location` header and no OAuth flow start.
- With session: tolerant read of `sess:{sid}` extracts only
  `access_token` and `access_token_expires_at`; payloads missing those
  fields are treated as "no session" and logged.
- Bearer injection: upstream request to RS includes `Authorization:
  Bearer <access_token>`; inbound `Cookie` is stripped; hop-by-hop
  headers are stripped; query string is preserved.
- Refresh delegation: when `access_token_expires_at` is within 60s, the
  plugin calls `POST /internal/refresh` with the cached configured gateway
  client service token. On 200 the plugin re-reads `sess:{sid}` and
  proceeds. On 401 the plugin invalidates the cached service token and
  retries once; second 401 → 502 to browser plus
  Gateway audit event. On 404 → 401 to browser plus cookie expiry. On
  409 → 401 to browser plus Gateway audit event. On 502 → 503 to browser
  with `Retry-After: 1` (session not invalidated).
- Concurrent `/api/**` requests on a single session produce one
  `/internal/refresh` call, not two (Auth Service per-session lock).
- Signed CSRF validation on state-changing `/api/**` requests:
  signature-tamper, value-tamper, missing-cookie, missing-header,
  cookie-header mismatch, and valid-token-from-another-session all
  rejected with 403.
- Client Credentials service-token cache: one Keycloak round-trip per
  worker per cache window; proactive refresh under 60s remaining;
  invalidation on Auth Service 401.

**Resource Server**

- Public endpoint succeeds without token.
- Reject missing, malformed, expired, wrong-issuer, wrong-audience,
  wrong-algorithm tokens.
- Reject user token on `/api/jobs`; reject service token on `/api/me` when
  user identity absent.
- Reject token missing required scope.
- `realm_access.roles=["admin"]` token produces `ROLE_admin` and reaches
  `/api/admin`.
- 401 / 403 bodies are `application/problem+json`.
- Tests use `@MockitoBean(JwtDecoder.class)` to swap the decoder before
  context creation; prevents eager OIDC discovery in test runs.

**Cross-service**

- Playwright: SPA login → callback → direct `302` to saved-request URL →
  `/auth/me` → `/api/me` → `/api/user-data` → logout. After login:
  `localStorage`, `sessionStorage`, `document.cookie`, and IndexedDB are
  token-free.
- Saved-request E2E: top-level nav to a protected URL → OAuth round-trip →
  lands on the originally requested URL via the direct `302` from the
  Auth Service (no landing page).
- `sess:{sid}` schema-contract test: shared fixture
  (`schema/sess-payload.example.json`) parses against the Auth Service
  writer's output and against the API Gateway's tolerant reader (§7.2).
- Client Credentials happy-path and failure tests.
- Client Credentials end-to-end gate: real `curl` against the AS for a
  service-client token, real `curl` against the RS `/api/jobs` with the
  bearer token, expects `200`. No Auth Service or API Gateway in path.
- Secret scan against the working tree.
- Cold-start from a clean checkout.

**Live conformance gates**

The live suites prove the security behaviors against real Keycloak tokens and
real Keycloak error responses, not fabricated JWTs. Each negative is a distinct
named assertion with its expected status code (and audit event where one
applies), seen to fail the right way when the guard is removed.

- `e2e-auth` — login → callback → `/auth/me` → `/api/**` → role enforcement →
  RP-initiated logout, plus the token-isolation assertion (no access / refresh /
  id token in `localStorage`, `sessionStorage`, `document.cookie`, or IndexedDB).
- **C8** (`e2e-conformance`, `e2e-c8-altids`) — internal trust identity:
  `GATEWAY_CLIENT_ID` and `INTERNAL_REFRESH_AUDIENCE` are config-driven on the
  wire, and a one-sided mismatch breaks `/internal/refresh`. The non-default run
  (`e2e-c8-altids`) threads alternate identifiers through
  `compose.portability.yml` and the APISIX render.
- **C9** (`e2e-conformance`) — session window: a non-default
  `SESSION_IDLE_TTL` / `SESSION_MAX_TTL` reaches both the Auth Service and the
  rendered gateway config; `/auth/me` does not extend the idle window, `/api`
  activity does, and the absolute ceiling is enforced.
- Back-Channel Logout (live) — a valid `logout_token` for an active session →
  the user's next `/api/**` and next `/auth/me` both `401`; a forged or
  `nonce`-bearing token → `400`, session untouched.
- Multi-tab (live) — two `/auth/login` flows from one browser context each
  complete their own callback; neither clobbers the other's
  `oauth_tx_<state>` cookie.
- `e2e-portability` — the same images against a second realm whose roles are a
  top-level `groups` claim and whose API audience differs, proving the role and
  audience paths are config-driven.

## Appendix A. Vendor Surface

This reference uses **Keycloak** as the local Authorization Server and
**APISIX** as the local API Gateway. Neither choice is load-bearing on the
BFF session pattern itself. This appendix names every file that would
change to swap one of those vendors. The split is the contract: anything
NOT listed here is pattern-level and does not change.

### A.1 Swapping the IdP (Keycloak → Auth0 / Okta / Entra ID / Ory Hydra / ...)

The Auth Service is built on `com.nimbusds.oauth2-oidc-sdk` and Spring
Security 6.x, both of which speak generic OAuth 2.1 + OIDC. Discovery
(`.well-known/openid-configuration`) and JWKS are how the code learns
about endpoints and signing keys; nothing in the Java code knows the
issuer is Keycloak.

Changes required:

| What changes | Where | Why |
|---|---|---|
| `OIDC_ISSUER_URI` env var | `compose.yaml`, `auth-service/src/main/resources/application.yml`, `backend-resource-server/src/main/resources/application.yml` | Single switch — discovery does the rest. |
| `app.roles-claim-path` | `application.yml` | Keycloak: `[realm_access, roles]`. Okta: `[groups]`. Auth0: `[https://your-app/roles]`. Entra: `[roles]`. See `docs/operations/provider-adapters.md`. |
| `app.client-id`, `app.client-secret` | Env vars | Whatever the new IdP issues for the confidential client. |
| `app.refresh-require-rotation` | `application.yml` | Keep `true` for IdPs with rotation + reuse-detection (Keycloak, Auth0). Set `false` only for IdPs that don't rotate (rare). |
| Realm seed | `authorization-server/realm/oidc-reference-realm.json` | This file is Keycloak's import format. Different IdPs use their own provisioning (Auth0 Management API, Okta API, Terraform provider, etc.) — this file is replaced wholesale by whatever provisioning method the target IdP uses. |
| `compose.yaml` keycloak service | `compose.yaml` | Remove the Keycloak service (which uses embedded H2 via `KC_DB=dev-file` — there is no separate database) if the target IdP is hosted (Auth0, Okta) or replaced with a different local container (Hydra, Dex). The realm-smoke script `authorization-server/tests/smoke.sh` is Keycloak-specific and would be deleted or rewritten. |
| `idp_token_url` in `apisix.yaml.template` | per-route plugin config | The Lua plugin field is IdP-vendor neutral; just point it at the new IdP's token endpoint. |
| RS audience name | `oidc-reference-realm.json` audience-mapper config OR the equivalent on the new IdP | The RS expects `oidc-reference-api` in `aud`; the IdP must be configured to add that value. |
| `INTERNAL_REFRESH_AUDIENCE` | Auth Service env | Audience the gateway's CC token must carry for `/internal/refresh`. Default `oidc-reference-auth-internal`; set to whatever the new IdP issues for the gateway client. |
| `GATEWAY_CLIENT_ID` | Auth Service env + APISIX render | The gateway's confidential client id — the Auth Service requires it in the caller's `azp`/`client_id`, and APISIX authenticates as it. Real IdPs assign client ids you don't choose, so this is a config knob (default `oidc-reference-api-gateway`), set in both places. |
| `RS_SERVICE_CLIENT_IDS` / `RS_JOBS_CLIENT_ID` | Resource Server env | Service-account allowlist (denied on `/api/me`) and the single client allowed to `POST /api/jobs`. Defaults are the local Keycloak client names. |

What does NOT change:

- All Java code in `auth-service/src/main/java/` and `backend-resource-server/src/main/java/`.
- All Lua code in `api-gateway/plugins/bff-session.lua`.
- All frontend code in `frontend/src/`.
- The cross-component contracts: `schema/sess-payload.example.json`,
  `schema/csrf-fixture.json`, SPEC-0001 §7.1/§7.2/§7.3.
- The BFF session shape (sliding 30m, absolute 8h, sid in HttpOnly cookie,
  signed CSRF, oauth_tx browser binding).

### A.2 Swapping the API Gateway (APISIX → Envoy / Traefik / Kong / HAProxy / NGINX + Lua)

The API Gateway is the role that owns: (a) routing `/api/**` to the
Resource Server with the allowlist, (b) reading `sess:{sid}` from the
state store and injecting a bearer for the upstream, (c) validating the
signed CSRF on state-changing requests, (d) delegating refresh to the
Auth Service via `/internal/refresh`, (e) the no-cookie XHR-vs-document
classification per the entry-conditions rules. Any gateway that satisfies
those five responsibilities and the wire contracts below is a valid
implementation.

Wire contracts the alternate gateway MUST satisfy:

1. **Session read.** `GET sess:{sid}` from Valkey (or any
   Redis-compatible store), parse JSON per `schema/sess-payload.example.json`
   §7.2 tolerant-reader rules. Treat unparseable / missing
   `access_token_expires_at` as "no session".
2. **Bearer injection.** Strip the inbound `Cookie` and `Authorization`
   headers (and the rest of HOP_BY_HOP); set `Authorization: Bearer
   <sess.access_token>`.
3. **Signed CSRF.** For state-changing methods (POST/PUT/PATCH/DELETE),
   validate the `X-XSRF-TOKEN` header against the `XSRF-TOKEN` cookie
   per §7.3 — same HMAC-SHA256 over the value, standard Base64 key,
   base64url-no-padding output, `.` separator.
4. **Refresh delegation.** When `sess.access_token_expires_at` is within
   the refresh window, `POST /internal/refresh` with a Client-Credentials
   bearer carrying the configured internal-refresh audience and
   `azp=<configured gateway client id>`. Handle the §7.1 status table.
5. **No-session response shape.** XHR → `401`. Top-level document
   navigation → `302 /auth/login?return_to=<original URL>`. Classification
   via `Sec-Fetch-Mode`/`Sec-Fetch-Dest` with `Accept` as the fallback.

Changes required for a swap:

| What changes | Where | Why |
|---|---|---|
| Gateway implementation | `api-gateway/plugins/bff-session.lua` | This file is OpenResty/APISIX-native. Envoy needs a Lua HTTP filter or a WASM filter; Traefik needs a custom middleware plugin (Yaegi or WASM); Kong needs a plugin (Lua); HAProxy needs Lua or SPOE. Each gateway has its own plugin SDK. |
| Routing config | `api-gateway/apisix.yaml.template`, `config.yaml`, `scripts/render-apisix-config.sh` | Replaced wholesale by the target gateway's config language (Envoy YAML, Traefik dynamic config, Kong declarative, etc.). |
| `compose.yaml` apisix service | `compose.yaml` | Replaced by the target gateway's container. |
| `api-gateway/tests/test-gateway-behavior.sh` | same | The shell smoke is gateway-agnostic at the HTTP layer but the `lib.sh` helpers shell into the Compose service named `apisix`. Update the service name; the assertions are gateway-independent. |

What does NOT change:

- All Java code (Auth Service, Resource Server).
- All frontend code.
- The cross-component contracts (`sess:{sid}` schema, `/internal/refresh`,
  signed CSRF, `oauth_tx` browser binding) — the new gateway must satisfy
  them.
- The state store (`Valkey` / any Redis-compatible).
- The IdP and realm config.

### A.3 Swapping the state store (Valkey → Redis Cluster / DynamoDB / ...)

Both sides talk Valkey via RESP today. To swap:

- Auth Service: replace `RedisStateStore` with an implementation of the
  `StateStore` interface (`put`, `get`, `getAndDelete`, `delete`,
  `expire`). The interface is vendor-neutral.
- API Gateway plugin: replace the `resty.redis` block in
  `bff-session.lua`'s `read_session` with the equivalent client for the
  target store. The JSON payload shape stays identical.

The `schema/sess-payload.example.json` contract stays the same — it's a
JSON-level contract that doesn't depend on the store.
