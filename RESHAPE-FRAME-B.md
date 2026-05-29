# Architecture Reshape Handoff — Frame B with B2 / B3 Reversals

**Audience.** The architect executing the spec-layer reshape captured here.

**Scope.** Spec files, decision records, realm JSON, Compose, task packets,
and verification scripts. **No application code in this round.** Application
code is delivered through subsequent task packets per the project's
spec-first discipline. The architect is expected to leave Java and
TypeScript untouched.

**Status.** Locked plan of record. Five previously-open sub-questions are
resolved with defaults in §5. The two protocol-level reversals (B2, B3)
are explicit decisions, not open items.

---

## 1. Purpose

The repository's committed state implements an OIDC reference using a
combined "BFF" service for both `/auth/*` and `/api/**`, with two
security-layer choices that have not held up under review:

- **B2** — `SameSite=Strict` session cookie with an intermediate
  same-origin HTML landing page after the OAuth callback, added to
  sidestep cross-site cookie-attachment edge cases.
- **B3** — `oauth_tx` browser-binding cookie hashed into `tx:{state}`,
  added as a defense beyond `state` + PKCE + `nonce`.

This handoff specifies three concurrent reshapes:

1. **Frame B.** Split the combined BFF into a dedicated **Auth Service**
   (OAuth/OIDC client role) and a dedicated **API Gateway** (routing +
   bearer-injection role). Add a Traefik ingress in the full-Compose
   shape and a Vite dev-proxy adaptation for the frontend dev loop.
2. **B2 reversal.** Drop the intermediate landing page. Session cookie
   becomes `SameSite=Lax`. CSRF defense becomes **signed** double-submit
   (HMAC-signed or session-bound), not naive cookie-header match.
3. **B3 reversal.** Drop the `oauth_tx` cookie and the `tx_cookie_hash`
   field from `tx:{state}`. Login-CSRF defense reverts to the OIDC-
   standard combination: `state` + PKCE + `nonce`.

Sections 2 and 3 give the rationale and the target shape. Sections 6 and
7 list the file-by-file spec changes. Section 8 specifies the new
contracts the split introduces.

---

## 2. The three reshapes — rationale

### 2.1 Frame B — split the BFF into Auth Service + API Gateway

**Decision.** Replace the single `bff/` service with two services:

- **Auth Service** — owns the OAuth/OIDC client role. Endpoints under
  `/auth/*`. Writer of `tx:{state}` and `sess:{sid}` in Valkey. Holds the
  per-session refresh lock. Exposes `/internal/refresh` for the API
  Gateway over a Client-Credentials-authenticated channel.
- **API Gateway** — owns the routing and bearer-injection role. Endpoints
  under `/api/**`. Reader of `sess:{sid}`. Forwards to the Resource
  Server with `Authorization: Bearer`. Enforces the path-pattern
  allowlist. Validates the signed CSRF token on state-changing requests.
  Delegates token refresh to the Auth Service.

**Rationale.**

1. **Adoptability.** A combined BFF reference invites the dismissal
   *"nice for a toy, won't survive a real org chart."* Production OIDC
   deployments at meaningful scale almost always separate the OAuth
   surface from the API-gateway surface — different teams (identity vs.
   platform), different scaling characteristics (auth is low-frequency,
   big payload; API is high-frequency, small payload), different
   operational concerns. A reference that ships the split shape is one
   production readers recognize.
2. **Responsibility clarity.** The "BFF" name historically (Sam Newman,
   2015) referred to a per-frontend API aggregator sitting *post-auth*.
   The OAuth-community co-opted use of "BFF" for the SPA session-
   management pattern conflates two roles. Splitting makes each service
   do exactly one thing and lets the documentation name each role
   precisely.

**What the split does NOT change.** Every protocol-level OIDC decision
in the spec is preserved: Authorization Code + PKCE, ID-token
validation, refresh-token rotation with reuse detection + audit event,
audience binding via the `api.audience` scope and mapper, role mapping
via a configurable claim path, RP-initiated logout, IdP portability,
storage portability, single-wildcard `/api/**` with allowlist, RS-side
explicit validation of audience / role / algorithm, virtual threads on
every Spring service, dev cookie binding via forwarded headers. The
split is operational topology; it is not new OIDC content.

### 2.2 B2 reversal — drop the landing page; SameSite=Lax + signed double-submit CSRF

**Decision.** Replace `SameSite=Strict` + intermediate same-origin
landing page with `SameSite=Lax` on the session cookie. The Auth Service
callback responds with a direct `302` to the validated saved-request URL
(same-origin guard preserved). CSRF defense on state-changing requests
becomes **signed** (HMAC-signed or session-bound) double-submit tokens —
not naive cookie-header match.

**Rationale.**

- The threat `Strict` defends against beyond `Lax` is being-linkable-
  while-authenticated from a cross-site context — i.e., the user clicks
  a link to the app from an external page and arrives already
  authenticated. For most browser apps this is the *intended* behavior.
  It is a concern only for narrow threat models (banking, certain
  compliance regimes) where being-linkable-as-authenticated is forbidden.
- For the reference's threat model, the CSRF risks `Strict` would
  mitigate on state-changing requests are already fully covered by the
  double-submit CSRF token. `Strict` was belt-and-suspenders.
- The landing page is real engineering complexity: an HTML response that
  becomes an XSS surface needing a tight CSP, additional test
  scaffolding, and a "this exists only to work around a cookie attribute"
  step in the architecture diagram. The cost-to-benefit ratio is poor.
- `SameSite=Lax` + signed double-submit CSRF is what mainstream
  production BFF implementations (`oauth2-proxy`, Spring Cloud Gateway
  BFF samples, Auth0 / Curity reference docs) ship. Adopting it aligns
  the reference with industry practice and removes the engineering load.
- **Signed** double-submit is load-bearing. Naive double-submit (server
  compares an unsigned cookie value against the same value echoed in a
  header) is vulnerable to cookie injection: an attacker with an XSS or
  cookie-write vulnerability on a sibling subdomain can set a matching
  cookie+header pair in the victim's browser. Signing the token (HMAC
  with a server-side key, validated on receipt) or binding it to a
  server-side session record breaks that attack.

**What `SameSite=Lax` costs.** Cross-site top-level GET navigation to
the app lands the user authenticated. This is acceptable for the
reference's threat model and matches user expectation for normal web
apps.

### 2.3 B3 reversal — drop `oauth_tx`; rely on state + PKCE + nonce

**Decision.** Remove the `oauth_tx` browser-binding cookie and the
`tx_cookie_hash` field in `tx:{state}`. Login-CSRF defense reverts to
the OIDC-standard combination of `state`, PKCE code-verifier, and ID-
token `nonce`.

**Rationale.**

- `state` + PKCE + `nonce` is the explicit RFC 9700 §4.7 mitigation for
  login CSRF and the documented standard since OIDC Core. The combination
  defends:
  - **`state`** — server-side validated against the `tx:{state}` record;
    a callback with an attacker-supplied state has no matching server
    record and is rejected before token exchange.
  - **PKCE code-verifier** — prevents an attacker who has obtained a
    leaked authorization code from exchanging it (they lack the
    verifier).
  - **ID-token `nonce`** — binds the ID token to the authorization
    request, preventing token substitution.
- The attack `oauth_tx` defends against (an attacker who has out-of-band
  obtained a victim's valid `state` plus authorization code, then
  induces the victim's browser to follow a malicious callback URL with
  attacker-controlled values) requires a separate prior compromise. The
  marginal defense beyond OIDC-standard primitives is narrow.
- No mainstream production BFF implementation ships an equivalent of
  `oauth_tx`. Adopting it puts the reference on a security island and
  adds a cookie, an additional `tx:{state}` field, an extra callback
  verification step, and a related test surface — all for a defense
  already provided by OIDC-standard primitives.
- For a reference whose goal is teaching OIDC and the BFF pattern,
  shipping a non-standard cookie reads as *"this reference does
  something nobody else does"* — which is the opposite of what a
  reference should communicate.

**What stays.** Server-side `state` generation and validation, PKCE S256
(required even though the client is confidential, per C1), and ID-token
`nonce` generation and validation. All three remain mandatory.

---

## 3. Target architecture

### 3.1 Components

| Component | Role | Notes |
|---|---|---|
| Frontend | React SPA | Served by Vite in dev. No OIDC library in browser. |
| Ingress | Traefik (full Compose); Vite proxy (frontend dev) | Single hostname seen by the browser. Path-based routing: `/auth/*` → Auth Service, `/api/**` → API Gateway. TLS termination point in production. |
| Auth Service | OAuth/OIDC confidential client | Owns `/auth/login`, `/auth/callback/idp`, `/auth/me`, `/auth/logout`, `/internal/refresh`. Writer of `tx:{state}` and `sess:{sid}`. Holds per-session refresh lock. Also acts as OAuth Resource Server for `/internal/*`. |
| API Gateway | Routing + bearer injection | Owns `/api/**`. Reader of `sess:{sid}`. Strips inbound `Cookie` and hop-by-hop headers; injects `Authorization: Bearer` on upstream calls. Enforces path-pattern allowlist. Validates signed CSRF on state-changing requests. Delegates refresh to Auth Service via `/internal/refresh`. Itself a confidential client at Keycloak for the Client Credentials used on `/internal/*`. |
| Resource Server | Domain + JWT validation | Unchanged from existing spec. |
| Keycloak | Authorization Server | Local reference IdP. Three confidential clients: `oidc-reference-auth`, `oidc-reference-api-gateway`, `oidc-reference-service`. |
| Postgres | Keycloak DB | Unchanged. |
| Valkey | Shared session store | Logical keyspaces `tx:*` and `sess:*`. Written by Auth Service; read by API Gateway; refresh writes by Auth Service. |

Eight runtime components. Cold-start time for the full Compose stack will
be on the order of 30–60s on a fast machine; called out in the local-
verification harness.

### 3.2 Browser request flow (target)

```
 1. Browser → Ingress: GET /api/<protected>   (no cookie)
 2. Ingress → API Gateway
 3. API Gateway: no sess:{sid} → check Fetch Metadata
       - Sec-Fetch-Mode: navigate AND Sec-Fetch-Dest: document → step 4
       - otherwise (XHR/fetch)                                  → 401, end
 4. API Gateway → Browser: 302 /auth/login?next=/api/<protected>
 5. Browser → Ingress: GET /auth/login?next=...
 6. Ingress → Auth Service
 7. Auth Service: validate `next` is same-origin
 8. Auth Service: generate state, nonce, PKCE verifier
 9. Auth Service → Valkey: SET tx:{state} = {verifier, nonce, saved_request} TTL 5m
10. Auth Service → Browser: 302 → Keycloak /auth?code_challenge=S256&state&nonce
11. Browser → Keycloak: GET /auth
12. User authenticates at Keycloak
13. Keycloak → Browser: 302 → /auth/callback/idp?code&state
14. Browser → Ingress: GET /auth/callback/idp?code&state
15. Ingress → Auth Service
16. Auth Service → Valkey: GET tx:{state} → {verifier, nonce, saved_request}; DEL
17. Auth Service → Keycloak: POST /token (code + verifier + client_secret)
18. Keycloak → Auth Service: {access_token, refresh_token, id_token}
19. Auth Service: validate id_token
       - iss = expected issuer
       - aud = oidc-reference-auth (this client's id)
       - nonce = stored nonce
       - sig (RS256)
       - exp / nbf
20. Auth Service → Valkey: SET sess:{sid} = {tokens, claims} TTL 30m (sliding)
21. Auth Service → Browser: 302 {saved_request}
        + Set-Cookie __Host-sid=<opaque>; HttpOnly; Secure; SameSite=Lax; Path=/
        + Set-Cookie XSRF-TOKEN=<signed>; Secure; SameSite=Lax; Path=/   (JS-readable)
22. Browser → Ingress: GET /api/<protected>   (Cookie: __Host-sid, XSRF-TOKEN)
23. Ingress → API Gateway
24. API Gateway → Valkey: GET sess:{sid}
25. (optional refresh)
       API Gateway → Auth Service: POST /internal/refresh
           + Authorization: Bearer <api-gateway service token>
           + body: {"sid": "<opaque>"}
       Auth Service: validate token (iss, sig, exp, aud=auth.internal, expected client_id)
                     acquire per-session lock
                     POST /token (grant=refresh_token) → Keycloak
                     validate rotation; emit audit event on reuse
                     UPDATE sess:{sid} in Valkey
                     release lock
                     200 {refreshed_at, access_token_expires_at}
       API Gateway → Valkey: GET sess:{sid}  (re-read for fresh access_token)
26. API Gateway → Resource Server: forward request + Authorization: Bearer <access_token>
       (strip inbound Cookie; strip hop-by-hop headers; preserve query string)
27. RS: validate JWT (iss, sig, exp, aud=oidc-reference-api, scope, roles)
28. RS → API Gateway: 200 {body}
29. API Gateway → Browser: 200 {body}
```

### 3.3 Service request flow (unchanged in shape)

```
1. Service Client → Keycloak:
     POST /token (grant=client_credentials, client_id, client_secret)
2. Keycloak: authenticate client
3. Keycloak → Service Client: access_token (aud=oidc-reference-api, scope=service.jobs)
4. Service Client → Resource Server: POST /api/jobs + Authorization: Bearer
     (does NOT traverse Ingress or API Gateway; direct service-to-RS call)
5. RS: validate JWT
6. RS → Service Client: 200 {result}
```

### 3.4 Internal RPC flow (new)

```
1. API Gateway → Keycloak (once per service-token TTL, cached locally):
     POST /token (grant=client_credentials,
                  client_id=oidc-reference-api-gateway,
                  client_secret)
2. Keycloak → API Gateway:
     api-gateway-service-token
     (aud=oidc-reference-auth-internal, scope=internal.refresh)
3. API Gateway → Auth Service: POST /internal/refresh
     + Authorization: Bearer <api-gateway-service-token>
     + body: {"sid": "<opaque>"}
4. Auth Service (as OAuth Resource Server for /internal/*):
     - validate token (iss, sig, exp, aud=oidc-reference-auth-internal,
                       azp/client_id=oidc-reference-api-gateway, alg=RS256)
     - acquire per-session lock for sid
     - perform refresh against Keycloak
     - update sess:{sid} in Valkey
     - release lock
5. Auth Service → API Gateway:
     200 {refreshed_at, access_token_expires_at}   (success)
     | 401 (auth failure)
     | 404 (no such session)
     | 502 (refresh failed at Keycloak)
```

### 3.5 Logout flow

```
1. Browser → Ingress → Auth Service: POST /auth/logout
     (Cookie: __Host-sid, XSRF-TOKEN; Header: X-XSRF-TOKEN)
2. Auth Service: validate signed double-submit CSRF
     (HMAC over the token value matches the signing key)
3. Auth Service → Valkey: DEL sess:{sid}
4. Auth Service → Browser: 302 → Keycloak /logout?id_token_hint=<id_token>
     + Set-Cookie __Host-sid=; Max-Age=0
     + Set-Cookie XSRF-TOKEN=; Max-Age=0
5. Browser → Keycloak: GET /logout
6. Keycloak → Browser: 302 /  (post-logout redirect)
```

---

## 4. What is preserved (no-touch)

The following decisions are unchanged. The reshape preserves all of them.
The architect should not relitigate any item in this list.

- **A1** BFF session pattern (server-side tokens). The split changes
  *where* the BFF responsibilities live; it does not move tokens to the
  browser.
- **A3** Session store: standard Redis wire protocol, Valkey as local
  reference. Acceptance criterion: no Valkey-specific commands in app
  code.
- **A4** Keycloak as local reference AS; BFF + RS code is provider-
  agnostic. Acceptance criterion: no Keycloak-specific code paths in
  app code.
- **B1** Logically distinct keyspaces `tx:*` and `sess:*` via custom
  repositories (not Spring Session). After the split, the writer is the
  Auth Service; the reader is the API Gateway.
- **B5** Saved-request replay with same-origin guard. Default to `/`
  when `Referer` is absent or cross-origin.
- **C1** PKCE S256 required even on the confidential client.
- **C2** Refresh-token rotation with reuse detection (realm-level) plus
  per-session refresh serialization. Reuse must emit a structured audit
  event.
- **C3** XHR vs top-level navigation distinguished via Fetch Metadata
  (`Sec-Fetch-Mode: navigate` + `Sec-Fetch-Dest: document`);
  `Accept: text/html` as fallback. No custom request-header convention.
- **C4** Single wildcard `/api/**` with path-pattern allowlist (now
  lives on the API Gateway). RS defense-in-depth CORS denial.
- **C5** Explicit RS validation of audience, role claim, signing
  algorithm. Configurable role-claim path for IdP portability.
- **D1** Virtual threads on all Spring services (Auth Service, API
  Gateway, RS).
- **E2** No committed credentials; bootstrap-generated or non-functional
  demo values. The new `oidc-reference-api-gateway` Keycloak client
  secret and the CSRF signing key join the existing list of secrets
  handled via env + bootstrap.
- **E3** OAuth2 client registration name `idp` (opaque, not the IdP
  brand). Applies to the Auth Service's OAuth2 client registration.
- **F. Deliberate non-adoptions** section of the decisions doc — every
  row stands.

---

## 5. Locked defaults for the five previously-open questions

| # | Question | Default | One-line rationale |
|---|---|---|---|
| 1 | Gateway runtime | Custom Spring WebMVC with virtual threads | Stack consistency. Spring Cloud Gateway would be the only reactive component. ~300 lines of routing/proxy code in MVC is more readable than SCG's filter abstractions for the small route set. SCG noted as production-grade alternative. |
| 2 | Session-schema contract | Tolerant reader on documented JSON | API Gateway reads only the fields it needs (`access_token`, `expires_at`); ignores the rest. Schema documented in SPEC-0001. No shared jar; no deploy coupling. Versioned-reader strategy if/when schema evolves. |
| 3 | Refresh delegation | Gateway → Auth Service via `/internal/refresh` | Keeps OAuth client logic in one place. Adds ~one RPC per refresh window per session (every few minutes at default access-token TTL). Avoids duplicating client config in Gateway. |
| 4 | Internal RPC auth | Client Credentials via Keycloak | Production-shape; no new auth primitive. API Gateway becomes a third Keycloak client. Auth Service acts as OAuth Resource Server for `/internal/*` with `aud=oidc-reference-auth-internal`. Demonstrates a second internal use of Client Credentials beyond the existing service flow. mTLS noted as further hardening. |
| 5 | Ingress | Traefik in full Compose; Vite proxy in frontend dev | Two-tier story. The frontend dev loop (`npm run dev`) uses Vite proxy with two upstreams (`/auth/*` → Auth Service, `/api/**` → API Gateway). The full-stack Compose run brings up Traefik as a real ingress. Same `X-Forwarded-Host` discipline at both layers. NGINX noted as production alternative. |

---

## 6. Concrete spec-layer changes (file by file)

This section enumerates every file the architect must touch. Per the
project's spec-first discipline, no application code changes in this
round.

### 6.1 Repository layout

**Remove.** The entire `bff/` directory. The combined service goes away;
its responsibilities are split into the two new services, each created
in a subsequent code task.

**Add (skeleton-only in this round; do not populate Java).**

- `auth-service/` — Spring Boot service directory. README, `pom.xml`,
  `mvnw`, `src/main/`, `src/test/`. Java sources NOT written in this
  round; the directory is created so the spec can reference it.
- `api-gateway/` — Spring Boot service directory. Same shape.

The architect may create empty `src/main/java/` and `src/test/java/`
directories with a placeholder `.gitkeep` if the build tool requires
them; no code.

### 6.2 `README.md`

- **Intended Stack section.** Replace the BFF line with two lines:
  Auth Service (Spring Boot, OAuth/OIDC confidential client) and
  API Gateway (Spring Boot, routing + bearer injection). Add Traefik to
  local infra.
- **Architecture section, browser-flow Mermaid.** Rewrite to add three
  swimlanes: Ingress (`I`), Auth Service (`A`), API Gateway (`G`).
  Remove the old combined `F` swimlane. The sequence matches §3.2 of
  this handoff. Remove all `oauth_tx` references. Replace step 21 with
  a direct `302 {saved_request}` setting `__Host-sid` (`SameSite=Lax`)
  and `XSRF-TOKEN` (signed). Remove the landing-page step entirely. Add
  the refresh RPC inside the optional refresh block (step 25).
- **Service-flow Mermaid.** Unchanged.
- **Cookie attributes note block.** Rewrite. Remove the `Strict` +
  landing-page rationale. New text:
  > The diagrams are the production contract. The session cookie is
  > `__Host-sid` with `HttpOnly`, `Secure`, `SameSite=Lax`, `Path=/`,
  > and no `Domain`. In local HTTP mode the cookie name downgrades to
  > `sid` and `Secure` is dropped (browsers reject `__Host-` without
  > `Secure`). The CSRF cookie (`XSRF-TOKEN`) is a JS-readable, **signed**
  > token (HMAC over the value, or session-bound) that the SPA echoes
  > as the `X-XSRF-TOKEN` header on state-changing requests. Naive
  > unsigned double-submit is rejected — see decision B4.

### 6.3 `docs/specs/SPEC-0001-core-oidc-flows.md`

Substantive section changes:

- **Target Stack.** Replace the BFF line with Auth Service and API
  Gateway lines. Add Traefik. Update port allocation:
  - Traefik `8080` (browser-facing in full Compose)
  - Keycloak moves to `8088` (or keep at `8080` and front via Traefik
    path-based routing; architect's call, but the spec must be internally
    consistent).
  - Auth Service `8081` (internal-only in full Compose).
  - Resource Server `8082` (internal-only).
  - API Gateway `8083` (internal-only).
  - Valkey `6379`.
  - Frontend dev `5173`.
- **Authorization Server Portability.** Unchanged.
- **Keycloak Realm.**
  - Existing client `oidc-reference-bff` is renamed to
    `oidc-reference-auth`. All sub-fields preserved (confidential,
    standard flow + PKCE S256 + refresh rotation, redirect URI, post-
    logout URI, default scopes).
  - Add new confidential client `oidc-reference-api-gateway`:
    Client Credentials only, browser flows disabled, direct grants
    disabled, service accounts enabled, default scopes `auth.internal`.
    Secret supplied via env (per E2).
  - Add new client scope `auth.internal` with an `oidc-audience-mapper`
    adding `oidc-reference-auth-internal` to the access token. Used by
    `oidc-reference-api-gateway` to authenticate to the Auth Service.
  - Existing `oidc-reference-service` client unchanged.
  - `api.audience` scope and mapper unchanged.
- **BFF Client section.** Rename to "**Auth Service Client
  (`oidc-reference-auth`)**." Body preserved (still confidential, still
  standard flow + PKCE S256 + refresh rotation). Redirect URI stays at
  `http://127.0.0.1:5173/auth/callback/idp` for the frontend-dev case;
  add a note that in the full Compose stack the URI is the Traefik
  hostname.
- **New section: API Gateway Client (`oidc-reference-api-gateway`).**
  Confidential, Client Credentials only, default scope `auth.internal`,
  service accounts enabled, browser flows disabled.
- **Service Client section.** Unchanged.
- **BFF Endpoints section.** Rename to "**Auth Service + API Gateway
  Endpoints**." Split the endpoint table into three subsections:
  - **Auth Service endpoints.** `/auth/login`, `/auth/callback/idp`,
    `/auth/me`, `/auth/logout`.
  - **API Gateway endpoints.** `/api/**` (single wildcard handler with
    `app.proxy.allow` allowlist).
  - **Internal RPCs.** `/internal/refresh` (Auth Service, consumed by
    API Gateway). Full contract per §8.1 of this handoff.
- **Cookie attributes.**
  - `__Host-sid`: `HttpOnly`, `Secure`, `SameSite=Lax`, `Path=/`, no
    `Domain`. Was `Strict`; now `Lax`.
  - `oauth_tx`: **delete the entry entirely.**
  - `XSRF-TOKEN`: `Secure`, `SameSite=Lax`, `Path=/`, JS-readable
    (`HttpOnly=false`). **Signed token** — HMAC over the token value
    with a server-side signing key, validated on receipt. Was `Strict`;
    now `Lax`.
- **Valkey Keys.**
  - `tx:{state}` payload: `{verifier, nonce, saved_request, created_at}`.
    Remove `tx_cookie_hash`.
  - `sess:{sid}` payload schema: document precisely per §8.2 of this
    handoff. Add a "Schema contract" subsection naming the fields the
    API Gateway's tolerant reader requires (`access_token`,
    `access_token_expires_at`) and the versioning strategy.
- **Session Lifecycle.** Unchanged.
- **CSRF section.** Rewrite for signed double-submit per §8.3 of this
  handoff. Explicit rejection of naive double-submit with cookie-
  injection as the named failure mode. The signing key is shared between
  Auth Service (issuer) and API Gateway (validator), distributed via env
  (gitignored), rotated through a documented process.
- **Login Entry Conditions.** Preserved in spirit. Update:
  - API Gateway is the entry-condition detector for protected-resource
    requests; on no-session it returns 302 with `?next=<original-URL>`.
  - Auth Service receives `/auth/login?next=...`, validates `next` is
    same-origin, persists `saved_request = next` in `tx:{state}`.
  - The same Fetch Metadata signal (`Sec-Fetch-Mode: navigate` +
    `Sec-Fetch-Dest: document`) gates the implicit flow at the Gateway.
- **Resource Server section.** Unchanged.
- **Frontend Behavior.** Unchanged in spirit. Update dev-plumbing
  bullet: Vite proxy with two upstreams (`/auth/*` → Auth Service `:8081`,
  `/api/**` → API Gateway `:8083`), both honoring `X-Forwarded-Host` /
  `-Proto` / `-Port`. Note that the full Compose stack uses Traefik
  instead, which performs the same path-based routing.
- **Threat Model.**
  - Remove the row referencing `oauth_tx`.
  - Add or rewrite the Login-CSRF row: "Login-CSRF / session-swapping —
    mitigated by `state` (server-side validated against `tx:{state}`),
    PKCE code-verifier (S256, required), and ID-token `nonce`
    validation. Per RFC 9700 §4.7."
  - Update the CSRF row for state-changing requests: "Signed double-
    submit `XSRF-TOKEN` (HMAC or session-bound) + `X-XSRF-TOKEN` header.
    Naive double-submit explicitly rejected — see decision B4."
- **Acceptance Criteria.**
  - Remove any criterion referencing the landing page or `oauth_tx`.
  - Add: "API Gateway returns `401` (no `Location`) for XHR `/api/*`
    requests without session, and `302 /auth/login?next=...` for top-
    level navigation."
  - Add: "Auth Service `/internal/refresh` rejects calls without a valid
    `oidc-reference-api-gateway` Client Credentials token whose
    audience contains `oidc-reference-auth-internal`."
  - Add: "Signed CSRF token rejection on tamper — a token with a
    modified value but unchanged signature, or with a forged signature,
    is rejected."
- **Test Plan.**
  - Remove all `oauth_tx` test bullets and landing-page test bullets.
  - Add tests for `/internal/refresh` contract: auth required;
    audience-bound; refresh actually rotates the stored access token;
    per-session lock prevents concurrent duplicate refresh; refresh-
    reuse audit event is emitted when Keycloak returns `invalid_grant`.
  - Add tests for signed CSRF: forged signature rejected; tampered
    value rejected; valid token accepted.
  - Update saved-request E2E: top-level nav → OAuth → ends on saved URL
    via direct 302 (no landing page).

### 6.4 `docs/architecture/decisions/architecture-decisions.md`

- **A1.** Rewrite to clarify "BFF *pattern*, *split-implementation*."
  Add a paragraph naming why the split (adoptability + responsibility
  clarity per §2.1 of this handoff). State that the combined-BFF
  alternative is a valid implementation of the same pattern, used by
  most existing references.
- **A2.** Unchanged.
- **A3.** Unchanged.
- **A4.** Unchanged.
- **A5.** Add `auth-service/` and `api-gateway/` to the directory list;
  remove `bff/`. Note that the project is now six runtime services plus
  Keycloak's DB.
- **B1.** Unchanged in principle; add a sentence that the writer is the
  Auth Service and the reader is the API Gateway.
- **B2.** **Rewrite entirely** per §2.2. New text:
  - Choice: `SameSite=Lax` on the session cookie + signed double-submit
    CSRF on state-changing requests.
  - What was rejected: `SameSite=Strict` + intermediate landing page.
    The landing page is engineering complexity defending against a
    threat the reference's model does not require closing, and `Strict`
    is rarely shipped by production BFFs.
  - What was rejected: naive (unsigned) double-submit. Cookie injection
    from a sibling-subdomain XSS satisfies a naive check; signing or
    session-binding breaks that attack.
  - Trade-off: cross-site top-level GET to the app lands the user
    authenticated (acceptable for the threat model).
  - Spec: SPEC-0001 §Session Cookie, §CSRF.
  - Code/config: Auth Service cookie serializer; CSRF token signer.
- **B3.** **Rewrite entirely** per §2.3. New text:
  - Choice: login CSRF defense is `state` (server-side validated against
    `tx:{state}`) + PKCE code-verifier (S256) + ID-token `nonce`
    validation.
  - What was rejected: an `oauth_tx` browser-binding cookie hashed into
    `tx:{state}`. The attack it defends against requires an attacker
    to have already executed an out-of-band compromise; no mainstream
    production BFF ships this; the cookie is real complexity for an
    island defense.
  - Trade-off: none additional; the OIDC-standard combination is the
    canonical reference shape.
  - Spec: SPEC-0001 §Login Entry Conditions, §Callback verification.
  - Code/config: Auth Service callback handler.
- **B4.** Strengthen to explicit signed/session-bound double-submit.
  Cookie-injection failure mode is named in the prose.
- **B5.** Unchanged.
- **C1.** Unchanged.
- **C2.** Unchanged.
- **C3.** Unchanged.
- **C4.** Unchanged in principle; note that the allowlist now lives on
  the API Gateway.
- **C5.** Unchanged.
- **D1.** Unchanged (now applies to three Spring services).
- **E1.** Update: Traefik (full Compose) and Vite proxy (frontend dev)
  both honor `X-Forwarded-Host` and Spring `forward-headers-strategy:
  framework` on the upstream services.
- **E2.** Unchanged in principle. The CSRF signing key and the API
  Gateway's Keycloak client secret join the list of secrets handled via
  env + bootstrap.
- **E3.** Unchanged.
- **New decision: A6 — Split BFF: Auth Service + API Gateway.** Captures
  Frame B. Document the five locked defaults from §5 as a single decision
  with sub-rationale. Spec pointer to the new internal-RPC section.
- **F. Deliberate non-adoptions.** Unchanged.

### 6.5 `authorization-server/realm/oidc-reference-realm.json`

- **Rename client `oidc-reference-bff` → `oidc-reference-auth`.** All
  other fields preserved.
- **Add new client `oidc-reference-api-gateway`.** Confidential. Client
  Credentials only. Service accounts enabled. Browser flows disabled.
  Direct access grants disabled. Default scopes: `auth.internal`. Secret
  via env per E2 (use the `dev-rotate-me` placeholder pattern in the
  same shape as the other dev secrets).
- **Add new client scope `auth.internal`** with an `oidc-audience-mapper`
  adding `oidc-reference-auth-internal` to the access token.
- **`oidc-reference-service` client.** Unchanged.
- **Realm-level settings** (refresh rotation flags, brute-force
  protection, etc.). Unchanged.

### 6.6 `compose.yaml` (root)

- **Add `traefik` service.** Path-routing rules: `/auth/*` → Auth Service
  `:8081`, `/api/**` → API Gateway `:8083`. Browser-facing port `:8080`.
- **Add `auth-service` service.** Build from `auth-service/`. Depends on
  `valkey` and `keycloak` being healthy. Internal port `:8081`; not
  exposed on the host (only Traefik reaches it).
- **Add `api-gateway` service.** Build from `api-gateway/`. Depends on
  `valkey`, `auth-service`, and `resource-server` being healthy. Internal
  port `:8083`; not exposed on the host.
- **Remove `bff` service** (was at `:8081`).
- **Internal network.** Define an internal Compose network. All backend
  services (Auth Service, API Gateway, RS, Valkey, Keycloak, Postgres)
  are on it. Only Traefik is on both the host-exposed network and the
  internal network.
- **Resource Server.** No host port exposure. Only reachable from API
  Gateway (and the service client during the service flow — which goes
  out and back through Keycloak then directly to RS; in the local
  reference this means RS must be reachable to the service-client smoke
  test, which is fine because the smoke test runs inside the Compose
  network).
- **Keycloak.** May stay on `:8080` if Traefik routes `/realms/*` there,
  or move to `:8088` if Traefik takes `:8080` directly. Either is
  acceptable; the spec must be internally consistent on the issuer URL.

### 6.7 `authorization-server/tests/smoke.sh`

- Add assertion: `oidc-reference-api-gateway` client exists, is
  confidential, has Client Credentials enabled, has browser flows
  disabled, has direct access grants disabled, has service accounts
  enabled, and has `auth.internal` in default scopes.
- Add assertion: `auth.internal` client scope exists with an
  `oidc-audience-mapper` adding `oidc-reference-auth-internal`.
- The existing real-token-issuance check for `oidc-reference-service`
  is unchanged.
- Add a new real-token-issuance check for `oidc-reference-api-gateway`
  (optional — gated by an env flag so a missing API Gateway client
  secret doesn't break the smoke; document the env flag in the script
  header).

### 6.8 `docs/goals/`

- **GOAL-0004 (BFF).** Retire. Move to `tasks/done/` (the goals
  directory should not hold retired goals; the retired BFF goal becomes
  a historical record under `docs/goals/archive/GOAL-0004-bff.md` with
  a `> **SUPERSEDED**` banner pointing to GOAL-0004-auth-service.md
  and GOAL-0005-api-gateway.md).
- **GOAL-0004-auth-service.md** (new). Owned paths: `auth-service/`,
  `auth-service/src/test/`, Auth-Service-specific docs and task notes.
  Goal: deliver the Auth Service per the spec. Required endpoints, token
  validation, custom Valkey repositories, refresh logic, internal
  endpoint authentication. Required tests including the refresh-reuse
  audit event and the signed-CSRF rejection cases.
- **GOAL-0005-api-gateway.md** (new). Owned paths: `api-gateway/`,
  `api-gateway/src/test/`, API-Gateway-specific docs and task notes.
  Goal: deliver the API Gateway per the spec. Routing, allowlist,
  tolerant session reader, bearer injection, hop-by-hop stripping,
  query-string forwarding, signed CSRF validation, refresh delegation.
- **GOAL-0001 (Frontend).** Update dev-plumbing bullet to reference
  Vite proxy with two upstreams. No other change.
- **GOAL-0002 (Resource Server).** Note that the inbound caller for
  `/api/*` is now the API Gateway (not the combined BFF). Cookie-header-
  absent contract is unchanged. No behavioral change.
- **GOAL-0003 (Keycloak realm).** Add the new client and scope to the
  realm contract.

### 6.9 `RFC9700-compliance.md`

Minimal changes. The legend and structure are unchanged.

- §2.1 row "CSRF prevention." Update "Where / How": `state` + PKCE +
  `nonce` (delete the `oauth_tx` mention). Status stays `🧾`.
- §2.6 row "Cookie scoping." Update SameSite from `Strict` to `Lax`.
- CSRF row (wherever it lives). Update to mention signed double-submit.
- Architecture Notes: update the same-origin-pattern paragraph to
  mention Traefik (full Compose) and Vite proxy (frontend dev) as the
  two consistent ingress shapes.

### 6.10 `tasks/`

- **`tasks/active/TASK-0007-bff-spec-to-code-alignment.md`.** Retire.
  Move to `tasks/done/` with a `> **SUPERSEDED**` banner at the top
  pointing to TASK-0008 and TASK-0009. Body preserved as historical
  record.
- **`tasks/active/TASK-0008-auth-service-spec-to-code.md`** (new).
  Implement the Auth Service per the spec. Use the existing task-packet
  template (`docs/agents/task-template.md`). Done criteria include:
  custom `OAuth2AuthorizationRequestRepository`, custom session
  repository, refresh-with-audit, `/internal/refresh` as OAuth Resource
  Server with audience validation, signed CSRF token issuance, RP-
  initiated logout. Must pass `scripts/check-agent-task.sh`.
- **`tasks/active/TASK-0009-api-gateway-spec-to-code.md`** (new).
  Implement the API Gateway per the spec. Done criteria include:
  Fetch-Metadata-based XHR-vs-nav distinction, single wildcard
  `/api/**` handler with allowlist config, tolerant session reader,
  bearer injection, Cookie + hop-by-hop stripping, query-string
  forwarding, refresh delegation to Auth Service, signed CSRF
  validation, Client Credentials token caching for the internal RPC.
  Must pass `scripts/check-agent-task.sh`.
- **`tasks/backlog.md`.** Update to reflect the new shape. Replace the
  "BFF (GOAL-0004)" section with two sections — "Auth Service
  (GOAL-0004)" and "API Gateway (GOAL-0005)" — listing the items each
  needs. Keep the existing RFC 9700 Known Gaps section unchanged.

### 6.11 `scripts/`

- **Add `scripts/verify-auth-service.sh`** (placeholder until the
  service exists). Mirrors the existing per-service verify scripts;
  body can be a `cd auth-service && ./mvnw test` once `auth-service/`
  has a `pom.xml`.
- **Add `scripts/verify-api-gateway.sh`** (same placeholder shape for
  `api-gateway/`).
- **Update `scripts/verify-all.sh`** to call both new verify scripts in
  the existing order.
- **`scripts/verify-security.sh`.** Update grep checks:
  - Remove `require_present "oauth_tx"`.
  - Remove any landing-page-required check.
  - Add `require_present "signed"` near `XSRF-TOKEN` references (or a
    more specific pattern that catches "signed double-submit" wording in
    the spec).
  - The existing positive/negative SPA-stale-string checks stand.
- **`scripts/verify-cross-service.sh`.** Update string presence
  requirements to match the new architecture (Auth Service and API
  Gateway named; `/internal/refresh` referenced; Client Credentials for
  internal RPC mentioned). The optional live-mode Client Credentials
  E2E (service client → RS) is unchanged.

### 6.12 `AGENTS.md`

- Update the four-goal block to a five-goal block: Frontend, Auth
  Service, API Gateway, Resource Server, Keycloak realm.
- Update the directory list: remove `bff/`, add `auth-service/` and
  `api-gateway/`.
- Update the Ownership section to add Auth Service Agent and API
  Gateway Agent as separate roles (or fold both under "Backend Agent"
  with a note that the two backend services have separate ownership
  boundaries — architect's call).
- Security Rules section — no substantive change.

### 6.13 `docs/architecture/overview.md`

- Update the Planned Components list (remove BFF, add Auth Service,
  API Gateway, Traefik).
- Update the Primary Build Goals list to reference GOAL-0004 (Auth
  Service) and GOAL-0005 (API Gateway).
- Update the Top-Level Flow paragraph to mention the split (and the
  back-channel `/internal/refresh` call) without redrawing the diagrams
  here — those live in the root `README.md` per existing convention.

### 6.14 `docs/README.md`

- Update the Start Here and Goals lists to reference the new GOAL files.
- Architecture-decisions link unchanged.

### 6.15 `frontend/vite.config.ts`

This is the one borderline-code file the architect must touch — the
Vite proxy config is configuration, not application code. Update the
proxy to route `/auth/*` to Auth Service `:8081` and `/api/**` to API
Gateway `:8083` (was a single BFF upstream). Continue setting
`X-Forwarded-Host`, `X-Forwarded-Proto`, `X-Forwarded-Port` on both
proxies. `changeOrigin: false` on both.

If the architect wants to defer this to TASK-0008/0009, that is
acceptable — but the proxy config must match the spec by the time the
frontend goal exits draft.

---

## 7. New contracts to design (spec wording, not code)

These are the interfaces the architect must specify precisely in
SPEC-0001 so that the two new services can be implemented independently
without ambiguity.

### 7.1 `/internal/refresh` contract

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
  - aud     contains "oidc-reference-auth-internal"
  - azp or client_id = "oidc-reference-api-gateway"
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
    - Refresh-token reuse detected — session has been invalidated.
    - Auth Service emits the structured audit event before returning.
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
  6. Otherwise, POST grant_type=refresh_token to Keycloak.
  7. On invalid_grant from Keycloak: emit the refresh-reuse audit
     event, DEL sess:{sid}, release lock, return 409.
  8. On success: validate rotation (new refresh token differs from
     old), update sess:{sid} with new tokens and new
     access_token_expires_at, release lock, return 200.
  9. On other Keycloak failure: release lock, return 502.
```

**API Gateway-side handling of each `/internal/refresh` response.**

| Status | Gateway action |
|---|---|
| 200 | Re-read `sess:{sid}` to pick up the rotated access token; proceed with the original request. |
| 401 | The Gateway's own Client Credentials token failed validation at Auth Service. Invalidate the Gateway's cached service token, fetch a new one from Keycloak, retry the refresh call **once**. If the second attempt also returns 401, return `502` to the browser and emit a Gateway-side security audit event — the Gateway's identity is misconfigured or its Keycloak client has been disabled. |
| 404 | Session was logged out concurrently or expired between the Gateway's read and the refresh attempt. Return `401` to the browser, expire `__Host-sid`, and rely on the SPA to trigger a fresh login on the next top-level navigation. |
| 409 | Refresh-token reuse detected — Auth Service has already invalidated `sess:{sid}` and emitted the canonical reuse audit event. Return `401` to the browser, expire `__Host-sid`, and emit a Gateway-side audit event for trace correlation. |
| 502 | Keycloak transient failure during refresh. Return `503 Service Unavailable` to the browser with `Retry-After: 1`. Do **not** expire `__Host-sid` — the session itself is still valid; refresh is temporarily unavailable. |

**Client Credentials token cache (API Gateway).**

The API Gateway holds a cached service token issued by Keycloak under
`grant_type=client_credentials`. The cache discipline:

- Single in-process cache entry per process. No per-request Keycloak
  round-trip in steady state.
- Token is refreshed **proactively** when remaining lifetime falls below
  a configurable threshold (default 60 s). Proactive refresh is
  serialized with an in-process lock so concurrent API requests do not
  trigger duplicate Keycloak calls.
- On Keycloak unavailability during proactive refresh: use the still-
  valid cached token until expiry. If expiry is reached and Keycloak
  is still unreachable, fail closed — return `503` for inbound API
  requests that need to call `/internal/refresh`. Inbound requests
  that do not need refresh (access token still fresh in `sess:{sid}`)
  are unaffected.
- On 401 from Auth Service for the Gateway's token (per the failure
  table above): invalidate the cache entry and re-fetch.
- The cache is **not** shared across Gateway instances. Each replica
  holds its own.

**Timeout and circuit-breaker on `/internal/refresh`.**

The Gateway's call to `/internal/refresh`:

- Connect timeout: 1 s.
- Read timeout: 5 s. The call may include a Keycloak round-trip inside
  Auth Service; 5 s is generous for healthy operation and tight enough
  to fail fast under contention.
- Circuit breaker on the rolling failure rate (default: window of 10
  requests, threshold 50% errors). Open state returns `503` to inbound
  API requests that need refresh for 30 s; half-open admits one probe.
- The circuit breaker MUST distinguish *transport / 5xx* failures
  (count as failure) from *200 / 401 / 404 / 409* responses (count as
  success — Auth Service is healthy, the answer is just not what we
  wanted). Misclassifying 404 or 409 as failure would trip the breaker
  on normal session-loss conditions.

### 7.2 `sess:{sid}` schema contract

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
  "claims": {
    "sub":                    "<subject>",
    "preferred_username":     "<string>",
    "name":                   "<string>",
    "email":                  "<string>",
    "roles":                  ["<role>", ...]
  },
  "created_at":               "<ISO-8601 UTC>",
  "last_touched_at":          "<ISO-8601 UTC>",
  "schema_version":           1
}
```

Schema contract rules:

1. The API Gateway MUST read only `access_token` and
   `access_token_expires_at`. It MUST NOT depend on any other field.
2. The Auth Service MAY add fields to the schema in a minor version
   bump (`schema_version` increments). New fields MUST NOT change the
   meaning of existing fields.
3. The Auth Service MUST NOT remove or rename existing required fields
   without a major version change coordinated with the Gateway.
4. The Gateway MUST log and treat as "no session" any payload it cannot
   parse or whose `access_token_expires_at` is absent.

**Contract test (mandatory in TASK-0008 and TASK-0009).**

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

Both tests run in their respective `mvn test` and execute under
`scripts/verify-all.sh`. Schema drift is caught by either test failing,
preventing the writer and reader from silently diverging across deploys.

### 7.3 Signed CSRF token contract

The CSRF token is **signed**, not naive. Defense against cookie
injection requires either an HMAC signature the server verifies on
receipt or a server-side session binding.

**Token format (HMAC variant — recommended for the reference):**

```
<token-value-base64> "." <hmac-base64>

where:
  token-value-base64 = base64url-encoded random 128-bit value
  hmac-base64        = base64url-encoded HMAC-SHA256(signing_key, token-value-base64)
```

**Cookie attributes for `XSRF-TOKEN`:**

- Path `/`
- `Secure` (in production; dropped in local HTTP)
- `SameSite=Lax`
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
5. Recompute HMAC-SHA256(signing_key, token-value-base64).
6. Reject if the recomputed HMAC does not match the supplied HMAC
   (constant-time comparison).
7. Accept.

**Signing key:**

- Single shared key between Auth Service and API Gateway.
- Supplied via env (gitignored), 256-bit random.
- Rotated via documented procedure: the spec must require that both
  services accept the old key for a grace window (e.g., 24h) after
  rotation to allow rolling restarts; cookies issued with the old key
  are accepted during the grace window and re-signed on the next
  state-changing request.
- The signing key is a secret; subject to the same handling rules as
  the Keycloak client secrets (E2).

**Naive-double-submit rejection.** The spec must explicitly reject
plain "compare cookie value to header value" without signature
verification. The attack model: an attacker with an XSS or
`document.cookie` write vulnerability on a sibling subdomain
(`evil.example.com` against `app.example.com`) can set a cookie value
in the victim's browser; combined with the ability to issue cross-site
requests, they can craft a request whose cookie and header match,
defeating naive double-submit. Signing breaks this — the attacker
cannot forge a valid signature.

---

## 8. Suggested migration sequence

The architect may execute the spec changes in any order, but the
following commit sequence keeps each commit reviewable and the
repository in a consistent state at each step.

```
Commit 1: Spec layer — decisions and SPEC-0001
  - architecture-decisions.md: B2, B3 rewrites; A6 added.
  - SPEC-0001-core-oidc-flows.md: all changes per §6.3 above.
  - This commit alone makes the spec consistent with the new
    architecture; subsequent commits propagate the change.

Commit 2: Realm and smoke
  - realm JSON: rename oidc-reference-bff → oidc-reference-auth;
    add oidc-reference-api-gateway client; add auth.internal scope.
  - smoke.sh: matching assertions.

Commit 3: Compose and ingress
  - compose.yaml: add traefik, auth-service, api-gateway services;
    remove bff; internal network setup.
  - frontend/vite.config.ts: two-upstream proxy.

Commit 4: Goals and tasks
  - docs/goals/: retire GOAL-0004 (BFF); add GOAL-0004 (Auth Service)
    and GOAL-0005 (API Gateway).
  - tasks/done/TASK-0007: SUPERSEDED banner.
  - tasks/active/TASK-0008, TASK-0009: new task packets.
  - tasks/backlog.md: split BFF section into two.

Commit 5: Architecture overview and root README
  - README.md: rewritten browser-flow Mermaid; updated cookie notes;
    updated stack list.
  - docs/architecture/overview.md: updated component list.
  - docs/README.md: updated start-here / goals links.

Commit 6: Operational docs
  - RFC9700-compliance.md: row updates per §6.9.
  - verification scripts: add verify-auth-service.sh and
    verify-api-gateway.sh as placeholders; update verify-all.sh;
    update verify-security.sh and verify-cross-service.sh string checks.
  - AGENTS.md: 5-goal block; directory list update.

Commit 7: Repository layout
  - Delete bff/ directory.
  - Create auth-service/ and api-gateway/ skeletons (README, empty
    src/main/java + .gitkeep, empty src/test/java + .gitkeep, no
    pom.xml until TASK-0008 / TASK-0009 begin).
```

Each commit should pass `scripts/verify-security.sh` and
`scripts/verify-cross-service.sh` independently — those scripts are
spec-string checks, so they reflect the spec state after each commit.

---

## 9. Verification

After the reshape, the following checks must pass.

**Static (no live stack required):**

- `scripts/check-agent-task.sh tasks/active/TASK-0008-*.md` → ok.
- `scripts/check-agent-task.sh tasks/active/TASK-0009-*.md` → ok.
- `scripts/verify-security.sh` → ok. New checks include `oauth_tx`
  absence in active spec/docs (the SUPERSEDED tasks under `tasks/done/`
  are allowed to mention it as historical record); `signed` near
  `XSRF-TOKEN` references; absence of landing-page wording.
- `scripts/verify-cross-service.sh` → ok. References to Auth Service,
  API Gateway, `/internal/refresh`.
- JSON parse of realm: ok.
- Compose config parse: ok.
- All Mermaid diagrams in `README.md` render.

**Cross-document consistency:**

- Every reference to `bff/` outside `tasks/done/` is gone.
- Every reference to `oauth_tx` outside `tasks/done/` is gone.
- Every reference to `SameSite=Strict` on the session cookie is gone
  (was the prior contract; now Lax).
- The "intermediate landing page" wording is gone from all active docs.
- The `oidc-reference-bff` Keycloak client identifier is replaced with
  `oidc-reference-auth` in all active docs.
- The new client `oidc-reference-api-gateway` and scope `auth.internal`
  are documented in: realm JSON, smoke.sh, SPEC-0001, GOAL-0003,
  architecture-decisions.md.
- The port allocation table in SPEC-0001 matches the `compose.yaml`
  service ports.

**Spec-to-spec coherence:**

- The browser-flow Mermaid in `README.md` matches §3.2 of this handoff.
- The cookie attributes in the README cookie-notes block match SPEC-0001
  §"Cookie attributes."
- The `/internal/refresh` contract in SPEC-0001 matches §7.1 of this
  handoff.
- The `sess:{sid}` schema in SPEC-0001 matches §7.2 of this handoff.
- The signed-CSRF contract in SPEC-0001 matches §7.3 of this handoff.

---

## 10. Explicitly out of scope (defer to TASK-0008 / TASK-0009)

The architect MUST NOT do the following in this reshape:

- Write Java code for Auth Service or API Gateway.
- Write or modify Spring Security configuration.
- Implement the custom `OAuth2AuthorizationRequestRepository` or session
  repository (TASK-0008).
- Implement the API Gateway's tolerant session reader or proxy handler
  (TASK-0009).
- Implement the signed CSRF token generator or validator (TASK-0008,
  TASK-0009).
- Implement the `/internal/refresh` endpoint or its handler (TASK-0008).
- Set up the Traefik routing rules with full annotations (the
  `compose.yaml` block is sufficient; production-grade routing config
  belongs to a later task).
- Add observability, tracing, or metrics wiring (separate task, future).
- Implement the bootstrap-secret script (existing E2 backlog item).
- Rewrite the Resource Server (unchanged in this reshape).
- Touch the existing Service Client flow (unchanged).

If during the reshape the architect discovers a spec gap that affects
the contract between Auth Service and API Gateway, they should record
it in the active task packet's "Risks or blockers" section and surface
it for resolution, NOT silently fill it in. The spec is the contract;
code follows.

---

## 11. Open follow-ups deferred to later rounds

These items are real but explicitly NOT in scope for the reshape.
Captured here so they are not lost.

- **B2/B3 reversal cleanup in `tasks/done/TASK-0007`.** The retired
  task packet mentions `oauth_tx` and the landing page in its plan
  steps. As historical record under `tasks/done/`, it is acceptable
  for it to do so; the SUPERSEDED banner at the top is the canonical
  signal that the task's plan no longer reflects current architecture.
- **CSRF signing key rotation tooling.** The spec requires a documented
  rotation procedure (grace-window acceptance of old key). The actual
  rotation script is a backlog item.
- **Production Traefik configuration.** This reshape adds Traefik to
  `compose.yaml` at a level sufficient for the local reference shape.
  Production-grade Traefik (TLS certificates, full middleware chain,
  observability annotations) is a separate concern.
- **`/internal/introspect` endpoint.** Considered as an alternative or
  complement to direct Valkey reads from the API Gateway. Not adopted in
  this reshape; the tolerant-reader pattern (§7.2) is the chosen
  contract. Revisit if the session schema needs to be hidden from the
  Gateway.
- **mTLS between API Gateway and Auth Service.** The spec uses Client
  Credentials (§7.1). mTLS is the production-hardening alternative;
  not in scope for the reference.
- **Observability contract** (metrics, traces, structured logs across
  the now-six-service topology). Material work; separate task.
- **Deployment artifacts** (Kubernetes manifests, Helm chart, Terraform).
  Out of scope for the reference; mentioned in skeptical reviews as a
  general limitation of the project.
- **Performance characterization** of the split shape (per-request
  Valkey lookup latency added at the Gateway, internal-RPC latency
  added on refresh). Separate task.

---

## 12. Final notes for the architect

- Treat the spec, the decisions doc, and the realm JSON as the
  contract; the code in subsequent tasks must follow them.
- If you find a contradiction between this handoff and the existing
  committed state, the handoff takes precedence — the existing state
  is what we are reshaping away from.
- If you find a contradiction between this handoff and something a user
  has explicitly said in conversation (preserved in `tasks/` or commit
  messages), surface the conflict before proceeding.
- The five locked defaults in §5 are firm. If during execution you
  identify a reason one of them is wrong, stop and surface it; don't
  silently change.
- The two protocol reversals in §2.2 and §2.3 (B2 and B3) are firm.
  These are the load-bearing simplifications of the reshape; the
  reference's value depends on them being clean.
- The reshape's success criterion: a reader who has not seen the
  earlier combined-BFF state should read SPEC-0001, the decisions doc,
  and the two Mermaid diagrams in `README.md` and understand the full
  architecture without needing to read this handoff. This handoff is
  scaffolding for the reshape; it is not part of the reference's
  enduring documentation.
