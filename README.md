# oidc-reference

A complete, runnable reference for the Backend-for-Frontend (BFF) session
pattern: browser-app OAuth 2.1 and OpenID Connect Core 1.0 with no tokens in
the browser.

The OIDC client role lives in a confidential server-side service, split into a
dedicated Auth Service (the OAuth/OIDC client) and a dedicated API Gateway
(routing and bearer injection). The browser holds only an opaque `HttpOnly`
session cookie. Tokens live in a Redis-compatible state store keyed by that
cookie.

It implements [RFC 9700](https://datatracker.ietf.org/doc/rfc9700/) (OAuth 2.0
Security BCP) and OIDC Core §3.1.3.7 for ID-token validation, across two flows:
browser login via Authorization Code + PKCE with saved-request replay, and
service-to-service via Client Credentials.

What it gives you:

- **The split shape, not a combined demo.** A separate Auth Service and API
  Gateway, the way production OIDC deployments separate the identity surface
  from the API edge.
- **The token invariant, enforced and asserted by a live test.** Access and
  refresh tokens never reach the browser; the id_token never reaches browser
  JS, storage, SPA-readable JSON, SPA-visible cookies, or app logs. Only the
  server's `/auth/logout/continue` → IdP redirect carries `id_token_hint`.
- **Every control mapped to a standard, a symbol, and a test.** The Security
  controls table ties each control to its RFC/OIDC section, the code that
  implements it, and the live gate that proves it.
- **Provider-portable by configuration.** No provider brand is baked into Java
  or Lua. `just e2e-portability` proves a token-shape swap end-to-end against a
  second realm.

## Design decisions

Each decision states what the reference does and the alternative it rejects.
Full rationale and reconsideration triggers are in
[`docs/architecture/architecture-decisions.md`](docs/architecture/architecture-decisions.md).

**BFF, not a public-client SPA running PKCE in the browser.** A server-side
BFF keeps the access, refresh, and ID tokens off the browser entirely. Browser
PKCE is valid OAuth, but:

- a token reachable by JavaScript can be used or exfiltrated by any successful XSS;
- browser refresh-token rotation is fragile under cross-origin policies;
- silent iframe renewal is no longer a dependable browser primitive.

A token-mediating backend that still hands access tokens to JavaScript is
rejected for the same XSS reason.

**Split into Auth Service + API Gateway, not one combined service.** Production
OIDC deployments at scale separate the OAuth surface from the API-gateway
surface:

- different teams own them (identity vs. platform);
- different expected load profiles, so each can scale independently;
- different operational concerns.

The "BFF" name (Sam Newman, 2015) originally meant a per-frontend API
aggregator sitting *after* auth; conflating it with the OAuth client role
obscures both. A combined BFF is also valid. This reference ships the split
because that is the shape production readers recognize.

**A server-side state store, not a framework HTTP-session blob.** The two
pieces of state have different lifetimes and addressing: a short pre-auth OAuth
transaction keyed by `state`, and a longer post-auth session keyed by `sid`.

Keeping them as separate keyspaces (`tx:{state}` and `sess:{sid}`) keys the
transaction by the OAuth `state` itself. There is no pre-auth session cookie,
and so no session-fixation class to defend against. Both keyspaces are
inspectable, the right property for a reference and for incident response.

**Standard OAuth/OIDC interfaces, not provider-specific APIs.** Application
code branches on `iss` / `aud` / scopes / claim paths / endpoints from
`.well-known/openid-configuration`, never on the provider brand. Provider
differences live in configuration:

- `app.roles-claim-path` for the claim shape;
- env vars for the issuer, client credentials, audiences, and the internal
  trust identifiers (gateway/service client ids, internal-refresh audience).

Nothing provider-facing is baked into Java or APISIX. The alternate-realm gate
`just e2e-portability` proves the token-shape swap end-to-end; SPEC-0001
Appendix A and `provider-adapters.md` §"Portability scope" enumerate every knob.

## Architecture

| Component | Role |
|---|---|
| `frontend/` | React + TypeScript SPA. Cookie-authenticated. No OIDC client library in the browser. |
| `auth-service/` | Confidential OIDC client (Nimbus `oauth2-oidc-sdk`). Owns `/auth/*`, the OAuth round-trip, session storage, and `/internal/resolve`. |
| `api-gateway/` | APISIX standalone + custom Lua plugin (`bff-session`). Owns `/api/**` allowlist, sid resolution via `/internal/resolve` (holds no session-store handle), bearer injection, and signed-CSRF validation. |
| `backend-resource-server/` | JWT validation only; never sees session cookies. |
| `authorization-server/` | Keycloak realm + Compose service. |

The vendor choices (Keycloak, APISIX, Valkey) are interchangeable;
SPEC-0001 Appendix A enumerates the files that change to swap each.
For a practical IdP swap checklist, see
[`docs/operations/provider-adapters.md`](docs/operations/provider-adapters.md).
For non-local hardening, see
[`docs/operations/production-hardening.md`](docs/operations/production-hardening.md).

### Login — Authorization Code + PKCE

Login is triggered two ways: the browser hits a protected `/api/**` URL with no
session, or the user clicks an explicit "Sign in". On the no-session `/api/**`
case the gateway bounces a top-level navigation to `/auth/login` (or returns
`401` to an XHR, so the SPA navigates itself).

The Auth Service then runs the OAuth round-trip and returns the browser to the
originally requested URL with the session and CSRF cookies attached.

```mermaid
sequenceDiagram
    autonumber
    actor U as User
    participant B as Browser (SPA)
    participant G as API Gateway
    participant A as Auth Service (BFF)
    participant K as IdP

    Note over B: Browser holds only an opaque __Host-sid cookie + a CSRF token —<br/>never an access, refresh, or id token.
    U->>B: Open a protected URL
    B->>G: GET /api/… (no session cookie)
    G-->>B: 302 → /auth/login (navigation) · 401 (XHR)
    B->>A: GET /auth/login?return_to=…
    A->>A: Start OAuth transaction — state, nonce, PKCE, browser-binding
    A-->>B: 302 → IdP /authorize (code, PKCE S256)
    B->>K: Authenticate
    K-->>B: 302 → /auth/callback?code
    B->>A: GET /auth/callback (+ transaction cookie)
    A->>K: Exchange code (+ PKCE verifier, client secret)
    K-->>A: access + refresh + id tokens
    Note over A,K: Tokens exist only server-side, from here on.
    A->>A: Validate id_token · create server-side session
    A-->>B: 302 → original URL + __Host-sid + CSRF cookie
```

### Identity and session state — `/auth/me`

The SPA holds no session state of its own. On mount it calls `/auth/me` to learn
whether a session exists and who the user is. The same endpoint is how it learns
about logout: a server-side session death — RP logout, back-channel logout, or a
rejected refresh — surfaces as `401` on the next `/auth/me` or `/api/**` call, and
the SPA returns to the anonymous state. `/auth/me` is a pure read; it never extends
the session and never returns a token.

```mermaid
sequenceDiagram
    autonumber
    participant B as Browser (SPA)
    participant A as Auth Service (BFF)
    participant V as Session Store

    Note over B: On mount, the SPA asks "who am I?" — its only window into session state.
    B->>A: GET /auth/me (sends the __Host-sid cookie)
    A->>V: Read the session record (pure read, no idle-window slide)
    alt session valid
        A-->>B: 200 claims (sub, preferred_username, name, email, roles)
        Note over B: Authenticated — render identity and roles (display only, never a token)
    else no, expired, or server-deleted session
        A-->>B: 401 (Cache-Control no-store)
        Note over B: Anonymous — render "Sign in"
    end
```

### Authenticated request — proxy and transparent refresh

Every `/api/**` call carries only the opaque session cookie. The gateway holds no
session store handle: it resolves the sid via the Auth Service's
`/internal/resolve` (authenticated with Client Credentials over an internal RPC).
The Auth Service looks up the session, slides the idle window, refreshes the
access token when it is near expiry, and returns the current token; the gateway
injects it as a bearer for the Resource Server. This is the phantom-token pattern
— only the Auth Service touches the session store (see
[`docs/architecture/phantom-token-session-resolution.md`](docs/architecture/phantom-token-session-resolution.md)).

```mermaid
sequenceDiagram
    autonumber
    participant B as Browser (SPA)
    participant G as API Gateway
    participant A as Auth Service (BFF)
    participant V as Session Store
    participant K as IdP
    participant R as Resource Server

    B->>G: GET /api/… (Cookie __Host-sid, CSRF)
    Note over G: The gateway holds no store handle — it resolves the sid via the Auth Service.
    G->>A: POST /internal/resolve (gateway service token + sid)
    A->>V: Look up session, slide the idle window
    opt access token near expiry
        A->>K: Refresh-token grant
        K-->>A: rotated access + refresh tokens
        A->>V: Update session
    end
    A-->>G: 200 access_token
    G->>R: GET /api/… + Authorization: Bearer access_token
    Note over G,R: Gateway strips the inbound cookie and injects the bearer.<br/>The browser never sends or sees a token.
    R->>R: Validate JWT (iss, sig, aud, exp, scope/roles)
    R-->>G: 200
    G-->>B: 200
```

### Logout — RP-initiated, `id_token_hint` stays server-side

```mermaid
sequenceDiagram
    autonumber
    participant B as Browser (SPA)
    participant A as Auth Service (BFF)
    participant K as IdP

    B->>A: POST /auth/logout (Cookie: __Host-sid, header: CSRF)
    A->>A: Validate CSRF · delete server-side session · stash single-use logout handle
    A-->>B: 200 { logoutUrl: "/auth/logout/continue?lc=…" } + evict cookies
    Note over B,A: The SPA receives only a same-origin handle —<br/>never the IdP URL or id_token_hint.
    B->>A: GET /auth/logout/continue?lc=… (top-level navigation)
    A->>A: Resolve single-use handle → IdP end-session URL (with id_token_hint)
    A-->>B: 302 → IdP /logout?id_token_hint (server-emitted, Referrer-Policy: no-referrer)
    B->>K: GET /logout
    K-->>B: 302 → /
```

The IdP end-session URL carries `id_token_hint` (PII), so it never reaches SPA
JavaScript: the Auth Service hands back a same-origin, single-use handle and emits
the IdP redirect itself from `/auth/logout/continue`.

Wire-level detail — exact cookie attributes, TTLs, validation rules, and the
`/internal/resolve`, `sess:{sid}`, and signed-CSRF contracts — lives in
[SPEC-0001](docs/specs/SPEC-0001-core-oidc-flows.md).

### Service-to-service — Client Credentials

Machine callers obtain a token directly from the Authorization Server and call the
Resource Server with a bearer. Neither the Auth Service nor the API Gateway is in
the path.

```mermaid
sequenceDiagram
    autonumber
    participant SC as Service Client (machine)
    participant K as IdP
    participant R as Resource Server

    Note over SC,R: Machine-to-machine — neither the Browser, Gateway, nor BFF is in the path.
    SC->>K: Client-credentials grant (client_id, client_secret)
    K-->>SC: access_token (aud, scope)
    SC->>R: POST /api/jobs + Authorization: Bearer access_token
    R->>R: Validate JWT (iss, sig, aud, exp, scope)
    R-->>SC: 200
```

### Session and CSRF cookies

- **Session cookie.** `__Host-sid` with `HttpOnly`, `Secure`,
  `SameSite=Lax`, `Path=/`, no `Domain`. In local HTTP mode the name
  downgrades to `sid` and `Secure` is dropped (browsers reject `__Host-`
  without `Secure`). `SameSite=Lax` is required for the cross-site
  Keycloak → callback redirect; the signed CSRF token provides
  state-change protection.
- **CSRF cookie.** `XSRF-TOKEN` is JS-readable and carries an
  HMAC-SHA256-signed value (`<value>.<hmac>`). The SPA echoes it as
  `X-XSRF-TOKEN` on state-changing requests. Unsigned double-submit is
  rejected: an attacker with a sibling-subdomain `document.cookie` write
  could otherwise forge a matching pair. `SameSite=Strict` (set by the
  signing party) tightens the surface further.
- **Browser-binding cookie.** `oauth_tx` is issued at `/auth/login` with
  `Path=/auth/callback/idp` and `SameSite=Lax`. Its HMAC is stored in
  `tx:{state}`; the callback rejects when the supplied cookie's HMAC
  doesn't match (defends against an attacker who exfiltrates `(code,
  state)` but is in a different user-agent).

## Security controls

| Control | Reference | Where |
|---|---|---|
| Authorization Code + PKCE S256 | OIDC Core §3.1.2 | `auth-service` |
| `state`, `nonce`, ID-token signature/iss/aud/exp | OIDC Core §3.1.3 | `JwtOidcIdTokenValidator` |
| `at_hash` when present | OIDC Core §3.1.3.7 step 7 | `JwtOidcIdTokenValidator` |
| `iss` query-param mix-up defense | [RFC 9207](https://datatracker.ietf.org/doc/rfc9207/) | `AuthController#callback` |
| Refresh rejected by the AS (`invalid_grant`) → 409 + session invalidation; realm still enables rotation + reuse detection | [RFC 9700 §4.14](https://datatracker.ietf.org/doc/rfc9700/) | `AuthorizationCodeTokenRefreshClient` + realm |
| Signed double-submit CSRF (HMAC-SHA256, base64url) | — | `SignedCsrfSupport`, `bff-session.lua` |
| `oauth_tx` browser-binding cookie | — | `OAuthTxBinding` |
| RP-initiated logout with `id_token_hint` | OIDC RP-Initiated Logout 1.0 | `AuthController#logout` |
| Step-up authentication: `auth_time` freshness gate on a sensitive route → step-up challenge | OIDC Core §3.1.2.1 (`prompt=login`), RFC 9470 | RS `ApiController#admin`, `AuthController#stepUp` (`/auth/step-up`), realm `auth_time` mapper |
| `redirect_uri` pinned via `app.base-url` (defeats Host-header injection) | — | `AuthController#baseUrl` |
| Per-session refresh lock (Java, `RefreshLock`/`InProcessRefreshLock`); `lua-resty-lock` around CC-token fetch (Lua) | — | `InProcessRefreshLock`, `InternalResolveController`, `bff-session.lua` |
| Rate-limit on `/auth/login` + `/auth/callback/idp` (APISIX `limit-req`) | — | `apisix.yaml.template` |
| Sentinel guard refusing default dev secrets | — | `SecretSentinelValidator` (Java, fail-closed at boot for the auth secret + cookie key); `render-apisix-config.sh` (`REQUIRE_NONDEV_SECRETS`, fail-closed at render for the gateway secret + CSRF key); `bff-session.lua` `warn_on_dev_sentinels` (WARN-only at gateway load) |

## What's deliberately not here

For a reference repo, what isn't shipped is part of the contract. Each
non-adoption below has a reconsideration trigger; the full rationale lives
in [`docs/architecture/architecture-decisions.md`](docs/architecture/architecture-decisions.md)
§F.

- **Sender-constrained tokens (DPoP / mTLS).** The BFF pattern removes the
  primary browser-token leakage vector, and the RS sits behind the API
  Gateway. But RS bearer tokens are not sender-constrained: any holder of a
  token with `aud=oidc-reference-api` that reaches the RS over the network can
  call it directly, so **network isolation of the Resource Server is
  load-bearing** until DPoP/mTLS is added (SECURITY.md threat-model row G-8).
  Reconsider when the RS is exposed to multi-tenant or untrusted callers.
- **Asymmetric client authentication (`private_key_jwt`, mTLS to the AS).**
  Shared-secret client auth is sufficient for the teaching baseline.
  Reconsider for FAPI / PSD2 or any compliance regime that mandates it.
- **JAR, PAR, RAR.** Exact redirect-URI matching + PKCE + state + nonce
  cover the demonstrated flow; scopes cover the authorization model.
  Reconsider for multiple authorization servers, untrusted-network
  authorization request handling, or structured per-resource grants.
- **OIDC Front-Channel Logout.** RP-initiated logout covers user-driven
  logout, and OIDC Back-Channel Logout (implemented; `POST
  /backchannel-logout`) covers IdP-driven revocation. The browser-iframe
  front-channel variant is not added.
- **OIDC Session Management.** The cookie-based BFF has no browser↔AS
  session to monitor; session changes surface via `/auth/me` polling or the
  next `/api/**` returning 401.
- **Encrypted-at-rest sessions in Valkey.** Local Valkey runs without
  AUTH/TLS/encryption. Reconsider before any non-local deployment alongside
  state-store AUTH, TLS, and network isolation.
- **Distributed refresh lock.** The Auth Service uses an in-process
  `ReentrantLock` keyed by `sid`. Clustered deployments need a state-store
  `SET NX EX` equivalent.

## Stack

- React 19 + TypeScript, Vite
- Java 25 + Spring Boot 4 (Auth Service, Resource Server)
- Nimbus `oauth2-oidc-sdk` for OIDC discovery, JWKS, ID-token validation,
  PKCE
- Spring Security 7 (JWT decoder, validator composition)
- Apache APISIX 3 standalone + custom Lua plugin
  (`lua-resty-http`, `lua-resty-lock`)
- Keycloak 26 (embedded H2 via `KC_DB=dev-file`; no separate database)
- Valkey 9 (Redis-compatible state store)
- Docker Compose

Exact versions are pinned in `frontend/package.json`, the service `pom.xml`
files, and `compose.yaml`.

## Run locally

Prerequisites: Docker Desktop or equivalent and Node 20+. Java 25 is needed
only when running the Spring modules directly or their unit tests outside
Docker.

Keycloak, Valkey, APISIX, Auth Service, and Resource Server run in Compose.
The SPA runs on the host through Vite for the frontend inner loop.

```sh
# 1. Bring the reference stack up.
just up

# 2. Start the SPA dev server.
cd frontend && npm install && npm run dev
```

- SPA: <http://127.0.0.1:5173/> — sign in as `alice` / `alice`.
- Keycloak admin console: <http://localhost:8080/> — sign in as
  `admin` / `admin` to inspect the seeded realm.

Verification:

```sh
just e2e-auth                            # canonical authenticated proof: login → API → refresh delegation → logout
./scripts/verify-all.sh                  # per-component checks + secret scan
RUN_FULL_STACK_AUTH=1 ./scripts/verify-all.sh   # also brings the stack up and runs the gateway suite
```

`just e2e-auth` is the canonical authenticated local proof. It brings the stack
up, runs `frontend/tests/e2e/reference-flow.spec.ts` for the real browser flow,
then runs the gateway refresh-delegation proof with a real login-derived
`sess:{sid}`.

It covers Keycloak login, `/auth/me`, an authenticated `/api/**` call, role
enforcement, refresh delegation, and RP-initiated logout through the same-origin
`/auth/logout/continue` handle.

## Documentation

- [`docs/specs/SPEC-0001-core-oidc-flows.md`](docs/specs/SPEC-0001-core-oidc-flows.md)
  — the build contract. Wire formats for `sess:{sid}`, `tx:{state}`,
  `/internal/resolve`, signed CSRF; threat model; trust boundaries.
  Appendix A is the vendor-swap matrix.
- [`docs/architecture/architecture-decisions.md`](docs/architecture/architecture-decisions.md)
  — rationale + rejected alternatives.
- [`SECURITY.md`](SECURITY.md) — threat model, crypto primitives, key
  handling, audit-logging surface, production-hardening list,
  vulnerability reporting.
- [`OIDC-compliance.md`](OIDC-compliance.md) — conformance matrix against
  OpenID Connect Core 1.0 + Discovery + RP-Initiated Logout.
- [`RFC9700-compliance.md`](RFC9700-compliance.md) — control-by-control
  status against RFC 9700 (OAuth 2.0 Security BCP, also OAuth 2.1 baseline).
- [`docs/reference/refresh-rotation.md`](docs/reference/refresh-rotation.md) —
  refresh-token rotation policy, the `app.refresh-require-rotation` knob, and
  per-provider rotation behavior.
- [`docs/operations/provider-adapters.md`](docs/operations/provider-adapters.md) — IdP swap walkthrough
  (Keycloak / Auth0 / Okta / Entra).
- [`AGENTS.md`](AGENTS.md) — contributor operating contract.
