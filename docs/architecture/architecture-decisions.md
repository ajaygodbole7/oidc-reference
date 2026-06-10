# Architecture Decisions

This document explains why the oidc-reference project is shaped the way it
is. It does not restate the implementation contract. Concrete values such as
cookie names, TTLs, ports, config keys, scopes, realm settings, and version
pins live in SPEC-0001.

This is one consolidated decision document, not an ADR per decision. The
purpose is to keep the rationale discoverable in one read.

## How To Read This

- Skim the headings for the system shape.
- Read A6 for the split-implementation topology.
- Read B2, B3, B4, B5, C4, and C5 for the load-bearing security choices.
- Section F lists deliberate non-adoptions and reconsideration triggers.

## Decision Categories

- Local reference, pluggable by configuration: components chosen for local
  reproducibility but designed so enterprise alternatives can replace them
  without application-code branches.
- Foundation choices: frameworks, languages, and patterns fixed by this
  reference.

## A. Topology And Stack

### A1. BFF Session Pattern, Split-Implementation

Tokens must not be in JavaScript reach. The browser holds no access token,
refresh token, or ID token. The Backend-for-Frontend is the OAuth/OIDC client,
and tokens are kept server-side.

A public-client SPA running Authorization Code + PKCE in the browser was
rejected. It is valid OAuth, but any successful XSS can use or exfiltrate
tokens reachable by JavaScript, browser refresh-token rotation is fragile, and
silent iframe renewal is no longer a dependable browser primitive. A
token-mediating backend was also rejected because it still hands access tokens
to JavaScript.

The reference implements the BFF pattern as a split: a dedicated Auth Service
owns the OAuth/OIDC client role under `/auth/*`, and a dedicated API Gateway
owns the routing and bearer-injection role under `/api/**`. The split is an
operational topology choice (see A6); it does not move tokens to the browser
and does not change any protocol-level OIDC decision. A combined-BFF
implementation of the same pattern is also valid and is the shape most
existing references ship.

The cost is two extra services and server-side session state. For a reference
whose teaching surface is the security posture and the production-shape
operational topology, that is the right trade.

Spec: SPEC-0001 Auth Service + API Gateway endpoints.

### A2. Spring Boot For Both BFF And Resource Server

OAuth and OIDC library maturity wins over framework-footprint optimization.
Alternatives considered: Quarkus, Helidon SE, Vert.x, and Node.

Spring Security provides mature OAuth2 Client, OIDC login, Resource Server,
JWT validation, and CSRF primitives. The BFF still owns custom repository code
for `tx:{state}` and `sess:{sid}`; Spring is not allowed to hide those states
inside a framework-managed HTTP session. Virtual threads reduce the historical
need to choose a reactive stack for this mostly IO-bound workload.

Trade-off: a larger framework surface and a recent JVM baseline.

Spec: SPEC-0001 Target Stack.

### A3. Redis-Compatible Server-Side State Store, Valkey Locally

The BFF stores OAuth transaction state and post-auth session state in a
Redis-compatible server-side state store. The local reference uses Valkey
because it is open source and Redis-wire-compatible.

The application contract is expressed as logical keyspaces: `tx:{state}` for
OAuth transactions and `sess:{sid}` for post-callback sessions. The BFF must
not depend on Valkey-specific commands, modules, clustering behavior, or admin
APIs. Redis-compatible alternatives should be swappable by configuration.

This is a server-side state store, not just a cache. `sess:{sid}` contains
tokens and claims and must be treated as sensitive state.

Trade-off: the reference carries custom repository code instead of using a
framework-managed session blob.

Spec: SPEC-0001 State Store Keys.

### A4. Standard OAuth 2.1 / OIDC Interfaces, Keycloak Locally

The BFF and Resource Server are implemented against standard OAuth/OIDC
interfaces, not provider-specific APIs. Keycloak is the local reference
Authorization Server and Identity Provider.

The application code must not branch on AS-specific issuer names, endpoints,
admin APIs, or claim shapes. Provider differences belong in configuration and
provider setup docs: scopes, audience mappers, role/group claim paths, logout
support, refresh-token policy, and service-client settings.

This does not mean every provider is a zero-work swap. It means the BFF and
Resource Server application code stay provider-agnostic.

Spec: SPEC-0001 Authorization Server Portability.

### A5. Five-Directory Project Layout

One ownership boundary per major component enables parallel human and agent
work:

- `frontend/` - React SPA.
- `auth-service/` - Spring Boot OAuth/OIDC confidential client. Owns
  `/auth/*` and `/internal/refresh`.
- `api-gateway/` - APISIX gateway with a custom Lua `bff-session` plugin.
  Owns `/api/**`.
- `backend-resource-server/` - Spring Boot Resource Server.
- `authorization-server/` - Keycloak realm, local database, smoke tests.

The earlier combined `bff/` directory was retired when the split-implementation
shape (A6) was adopted; its responsibilities were divided between
`auth-service/` and `api-gateway/`. Shared docs and verification scripts
remain outside those component directories.

Spec: AGENTS.md ownership table.

### A6. Split BFF Into Auth Service And API Gateway

The BFF pattern (A1) is implemented as two services, not one:

- **Auth Service** — Spring Boot OAuth/OIDC confidential client. Owns
  `/auth/login`, `/auth/callback/idp`, `/auth/me`, `/auth/logout`, and
  `/internal/refresh`. Writer of `tx:{state}` and `sess:{sid}`. Holds the
  per-session refresh lock. Acts as an OAuth Resource Server for
  `/internal/*` with audience `oidc-reference-auth-internal`.
- **API Gateway** — APISIX (OpenResty / nginx + Lua) with a custom Lua
  plugin `bff-session`. Owns `/api/**`. Reader of `sess:{sid}` (tolerant
  reader on documented JSON). Forwards to the Resource Server with
  `Authorization: Bearer`. Enforces the path-pattern allowlist. Validates
  the signed CSRF token on state-changing requests. Delegates token refresh
  to the Auth Service via `/internal/refresh`. Itself a confidential client
  at Keycloak for the Client Credentials token used on `/internal/*`.

Rationale: **adoptability and responsibility clarity.** Production OIDC
deployments at meaningful scale almost always separate the OAuth surface
from the API-gateway surface — different teams (identity vs. platform),
different scaling characteristics (auth is low-frequency, big payload; API
is high-frequency, small payload), different operational concerns. A
reference that ships the split shape is one production readers recognize.
The "BFF" name historically (Sam Newman, 2015) referred to a per-frontend
API aggregator sitting post-auth; conflating that with the OAuth client
role obscures both. The split lets each service do exactly one thing.

The split does not change any protocol-level OIDC decision: Authorization
Code + PKCE, ID-token validation, refresh-token rotation with reuse
detection, audience binding, role mapping, RP-initiated logout, IdP
portability, storage portability, single-wildcard `/api/**` with
allowlist, RS-side explicit validation, virtual threads on the Spring
services, dev cookie binding via forwarded headers. It is operational
topology, not new OIDC content.

**Locked defaults captured with this decision:**

- **Gateway runtime: APISIX.** Production-grade open-source API gateway
  (OpenResty / nginx + Lua). Declarative routes plus a custom `bff-session`
  Lua plugin that does tolerant session read from Valkey, bearer
  injection, signed-CSRF validation, and refresh delegation to the Auth
  Service. Custom Spring (WebMVC + virtual threads) and Spring Cloud
  Gateway were considered; APISIX was chosen because the production-shape
  argument that motivates the split applies to the Gateway runtime
  itself — a real ingress data plane reads more truthfully than an
  embedded Spring proxy. Spring Cloud Gateway is noted as a production
  alternative for organizations standardizing on a JVM ingress.
- **Session-schema contract.** Tolerant reader on documented JSON: the API
  Gateway reads only `access_token` and `access_token_expires_at`; ignores
  the rest. Schema documented in SPEC-0001 §7.2. No shared jar; no deploy
  coupling. Versioned-reader strategy if the schema evolves.
- **Refresh delegation.** Gateway → Auth Service via `POST
  /internal/refresh`. Keeps OAuth client logic in one place. Adds ~one RPC
  per refresh window per session.
- **Internal RPC auth.** Client Credentials via Keycloak. The API Gateway
  is a third confidential client (`oidc-reference-api-gateway` by local
  default) with Client Credentials only. The Auth Service acts as OAuth
  Resource Server for `/internal/*` with the configured internal-refresh
  audience (`oidc-reference-auth-internal` by local default). mTLS noted as
  production hardening.
- **Ingress.** APISIX is itself the ingress in the full Compose stack — no
  separate Traefik or NGINX in front of it. The frontend dev loop uses the
  Vite proxy with two upstreams (`/auth/*` → Auth Service, `/api/**` →
  APISIX). Same `X-Forwarded-Host` discipline at both layers.

Trade-off: five runtime services (Keycloak, Valkey, Auth Service, API
Gateway, Resource Server; Keycloak uses embedded H2, no separate database).
Cold-start time for the full Compose stack is on the order of 30–60s on a
fast machine. Two
secrets (Auth Service Keycloak secret, API Gateway Keycloak secret) plus
the CSRF signing key are handled via env + bootstrap (E2).

Spec: SPEC-0001 Auth Service + API Gateway Endpoints; SPEC-0001 API
Gateway Architecture (APISIX); SPEC-0001 §7.1 `/internal/refresh` contract.

### A7. Nimbus oauth2-oidc-sdk Directly, Not spring-boot-starter-oauth2-client

The Auth Service uses `com.nimbusds:oauth2-oidc-sdk` (the OAuth/OIDC client
machinery) and `com.nimbusds:nimbus-jose-jwt` (JWS/JWE/JWK) **directly**,
not the Spring Security OAuth2 Client starter. Spring Security still
provides the filter chain (security headers, JWT decoder for the
`/internal/*` Resource Server role); the OAuth flow itself bypasses
`spring-boot-starter-oauth2-client`.

**Rationale.** Both Nimbus libraries are already on the classpath as
transitive dependencies of Spring Security, so the net dependency surface
is unchanged. Two properties improve:

1. **Spec visibility.** OIDC Core §3.1.3.7 validation, PKCE construction,
   client-authentication method dispatch, and the token-endpoint
   request/response shape become visible code in this reference rather
   than framework-internal behavior. For a teaching repo, the OAuth/OIDC
   wire shape *is* the lesson.
2. **Portability.** The Nimbus helper classes
   (`AuthorizationCodeTokenExchangeClient`,
   `AuthorizationCodeTokenRefreshClient`, `JwtOidcIdTokenValidator`,
   `OidcProviderMetadata`) carry zero framework imports beyond `java.*`,
   `com.nimbusds.*`, and `jakarta.validation.*`. They lift unmodified into
   Quarkus, Micronaut, Helidon, or plain servlets — only the host's DI
   annotations and HTTP request type need to change.

**Alternatives surveyed and rejected.**
- **`spring-boot-starter-oauth2-client`.** Couples to Spring types
  (`ClientRegistration`, `OAuth2AuthorizationExchange`,
  `RestClientAuthorizationCodeTokenResponseClient`) that cannot leave the
  framework. The teaching surface degrades when the OAuth contract is
  hidden inside `OidcAuthorizationCodeAuthenticationProvider`.
- **`pac4j-oidc`.** Misadvertised as framework-agnostic; declares
  hard compile-time deps on `spring-core` and Guava.
- **`jjwt`.** Cleaner fluent API for the JWT primitive but narrower spec
  coverage; no built-in remote JWKS source. Would require pairing with a
  separate OAuth client library — Nimbus already covers both.
- **Quarkus / Micronaut OIDC client modules.** Hard-coupled to their
  framework's filter chain — defeats the portability property above.

**Trade-off.** OIDC Core §3.1.3.7 validation is explicit code in
`JwtOidcIdTokenValidator` (~60 LOC) rather than a one-line Spring
configuration. This is the right trade for a reference: explicit
validation is auditable; framework-default validation is a black box that
moves between Spring versions.

**Production-readiness deltas vs Spring's wrapping.** Nimbus's
`JWKSourceBuilder` is uniquely sophisticated — refresh-ahead caching,
rate limiting, retry, outage tolerance, force-refresh on unknown `kid`.
Spring's `NimbusJwtDecoder` wraps the same library but exposes a narrower
default configuration.

Spec: SPEC-0001 Target Stack; `JwtOidcIdTokenValidator.java` (validator
construction); `AuthorizationCodeTokenExchangeClient.java` (token-endpoint
client).

## B. Cookies, Sessions, And CSRF

### B1. Separate Transaction And Session Keyspaces

Pre-auth OAuth transaction state and post-auth session state are different
objects with different lifetimes and different addressing schemes. They use
logically distinct Redis-compatible keyspaces, not one framework-managed HTTP
session blob.

The framework default was rejected for three reasons. First, the reference
diagram and tests need visible, inspectable `tx:{state}` and `sess:{sid}`
objects. Second, keying pre-auth state by OAuth `state` eliminates the need to
mint a pre-auth session cookie, which removes the session-fixation class this
reference is trying to avoid. Third, incident response is simpler when the
operator can inspect transaction and session records independently.

Trade-off: custom transaction and session repositories are required.

Under the split-implementation shape (A6) the writer of both keyspaces is the
Auth Service; the reader of `sess:{sid}` on the bearer-injection path is the
API Gateway via a tolerant reader. The keyspaces themselves are unchanged.

Spec: SPEC-0001 State Store Keys; SPEC-0001 Session Lifecycle.

### B2. SameSite=Lax Session Cookie With Signed Double-Submit CSRF

The session cookie is `__Host-sid` with `HttpOnly`, `Secure`, `SameSite=Lax`,
`Path=/`, and no `Domain`. After a successful OAuth callback the Auth Service
returns a direct `302` to the same-origin-validated saved request URL.
State-changing requests are protected by a **signed** double-submit CSRF
token (HMAC-signed or session-bound), not naive cookie-header match.

What was rejected: `SameSite=Strict` plus an intermediate same-origin HTML
landing page. The landing page is real engineering complexity — an HTML
response that becomes an XSS surface needing a tight CSP, additional test
scaffolding, and a "this exists only to work around a cookie attribute" step
in the architecture diagram. The threat `Strict` defends against beyond `Lax`
is being-linkable-while-authenticated from a cross-site context, which is the
intended behavior for most browser apps and is a concern only for narrow
threat models (banking, certain compliance regimes). For the reference's
threat model, the CSRF risks `Strict` would mitigate on state-changing
requests are already fully covered by the signed double-submit CSRF token.
Mainstream production BFF implementations (`oauth2-proxy`, Spring Cloud
Gateway BFF samples, Auth0 / Curity reference docs) ship `SameSite=Lax`.

What was also rejected: naive (unsigned) double-submit. **Failure mode:**
cookie injection. An attacker with an XSS or `document.cookie` write
vulnerability on a sibling subdomain (`evil.example.com` against
`app.example.com`) can set a matching cookie and header pair in the victim's
browser, defeating a naive cookie-equals-header check. Signing the token
(HMAC-SHA256 over the token value with a server-side key, validated in
constant time on receipt) or binding it to a server-side session record
breaks the attack: the attacker cannot forge a valid signature.

Trade-off: cross-site top-level GET navigation to the app lands the user
authenticated. Acceptable for the reference's threat model and matches user
expectation for normal web apps.

Spec: SPEC-0001 Session Cookie; SPEC-0001 CSRF.

### B3. Login-CSRF Defense Is State + PKCE + Nonce + `oauth_tx` Browser Binding

Login-CSRF and cross-user session fixation are defended by the
OIDC-standard combination — server-side `state` validated against
`tx:{state}`, PKCE code-verifier (S256, required even on the confidential
client), and ID-token `nonce` validation — **plus** an `oauth_tx`
browser-binding cookie whose HMAC is stored in `tx:{state}` and verified
at the callback.

- **`state`** — generated server-side, persisted as the key of `tx:{state}`,
  validated on callback. A callback with an attacker-supplied state has no
  matching server record and is rejected before token exchange.
- **PKCE code-verifier** — prevents an attacker who has obtained a leaked
  authorization code from exchanging it; they lack the verifier.
- **ID-token `nonce`** — binds the ID token to the authorization request,
  preventing token substitution at the token endpoint.
- **`oauth_tx`** — `HttpOnly` cookie scoped to `Path=/auth/callback/idp`,
  issued alongside the login `302`. Its HMAC (`tx_cookie_hash`) is stored
  in `tx:{state}`. The callback computes `HMAC(supplied cookie)` and
  rejects when it does not match.

**Why the first three are not enough.** RFC 9700 §4.7's `state` defense
covers the case where the *victim* initiated the OAuth flow and the
attacker cannot predict `state`. It does **not** cover the inverse: an
attacker who runs their own login flow at the AS, captures the resulting
`(code, state)` callback URL, and induces the victim to load it (a crafted
link, a redirect from an attacker page, an open-redirect chain in another
property). The victim's browser then hits `/auth/callback/idp` with values
the *attacker* controls; `tx:{state}` exists (the attacker created it),
PKCE succeeds (the attacker generated the verifier), the ID-token `nonce`
matches (the attacker chose it). The result is a session minted from the
attacker's identity logged into the victim's browser — a session-fixation
class attack.

The `oauth_tx` cookie closes this: the victim's browser cannot present a
cookie matching the attacker's stored hash because the cookie was set on
the attacker's browser in their own flow. The callback fails closed
without ever calling the token endpoint.

**Cost.** One additional cookie (`Path=/auth/callback/idp`, so the
browser only sends it on the one path that needs it), one field in the
`tx:{state}` record, one HMAC verification at the callback. The
`SignedCsrfSupport.hmacSha256` helper is reused, so no new crypto
machinery.

The threat is real and the OIDC standards do not cover it directly;
equivalent browser-binding cookies are documented in Curity's and Auth0's
BFF reference patterns. See `OAuthTxBinding.java` for the implementation and
SPEC-0001 §"State Store Keys" for the wire shape.

Spec: SPEC-0001 §"State Store Keys" + Login Entry Conditions + Callback
verification.

### B4. Signed Double-Submit CSRF

State-changing requests use a **signed** double-submit CSRF token. The Auth
Service issues `XSRF-TOKEN` as a JS-readable cookie whose value is
`<token-value-base64>.<hmac-base64>` where the HMAC is
HMAC-SHA256(signing_key, token-value-base64). The SPA echoes the full signed
token as the `X-XSRF-TOKEN` header on every `POST`/`PUT`/`DELETE`/`PATCH`.
The Auth Service and API Gateway both validate: cookie and header present,
exact match, signature recomputed and compared in constant time. The signing
key is a 256-bit env-supplied secret shared between Auth Service (issuer)
and API Gateway (validator).

**Failure mode for naive double-submit: cookie injection.** An attacker with
an XSS or `document.cookie` write vulnerability on a sibling subdomain
(`evil.example.com` against `app.example.com`) can set a matching cookie and
header pair in the victim's browser, satisfying a naive
cookie-equals-header check from a cross-site request. Signing the token
breaks the attack — the attacker cannot forge a valid HMAC without the
server-side key. A session-bound variant (the token contains or hashes the
`sid`) is an equivalent defense; the HMAC variant is the reference's
chosen shape because it does not require a `sess:{sid}` lookup before
signature validation.

The synchronizer-token pattern was considered. It is acceptable, but it
adds another server lookup for a same-origin SPA-to-API-Gateway flow where
the Gateway already looks up `sess:{sid}`.

Trade-off: the SPA must echo the signed cookie value as a header on every
state-changing fetch; a CSRF signing key joins the secret-handling list (E2).

Spec: SPEC-0001 CSRF.

### B5. Saved-Request Replay With Same-Origin Guard

Implicit login returns the user to the URL they originally requested, not
unconditionally `/`. The default-success-page pattern was rejected because it
turns login into "authenticate, then go find the thing again."

The same-origin guard is load-bearing. Explicit login may derive the saved URL
from the Referer header, and external links can create cross-origin Referer
values. The Auth Service must validate the saved URL before navigating to it
on the callback `302`.

Trade-off: the Auth Service must persist and validate the saved URL in
transaction state.

Spec: SPEC-0001 BFF callback row.

## C. OAuth / OIDC Behavior

### C1. PKCE Required On The Confidential Client

OAuth 2.0 does not strictly require PKCE for confidential clients. This
reference requires it anyway as defense in depth against authorization-code
interception and as the posture expected by modern OAuth guidance.

Trade-off: the realm configuration is stricter than the OAuth 2.0 minimum.

Spec: SPEC-0001 BFF Client.

### C2. Refresh-Token Rotation, Reuse Detection, And Refresh Serialization

Refresh tokens are rotated on every use, and reuse invalidates the session.
The BFF must emit an audit event when refresh reuse or refresh failure causes
session invalidation.

Rotation creates a known concurrency race: two concurrent BFF requests can both
detect an expiring access token and both try to refresh. One wins; the other
can make the rotated token appear reused. The BFF serializes the refresh window
per session.

Trade-off: clustered BFF deployments require a distributed lock. The local
reference may use an in-process lock for a single BFF instance.

Spec: SPEC-0001 Refresh and Rotation; SPEC-0001 Concurrency.

### C3. XHR Versus Top-Level Navigation At The BFF Entry

Only top-level browser navigations start the OAuth flow. API fetches without a
session receive `401`; they are not redirected to the AS because an AS login
page cannot be usefully rendered inside an XHR/fetch response.

The legacy `X-Requested-With` signal was rejected because modern fetch does
not set it. The BFF prefers Fetch Metadata
(`Sec-Fetch-Mode: navigate`, `Sec-Fetch-Dest: document`) when available and
uses `Accept: text/html` only as a fallback. The SPA reacts to API `401` by
performing a top-level navigation.

Trade-off: the SPA must own the unauthenticated API-response path.

Spec: SPEC-0001 Login Entry Conditions.

### C4. Single Chokepoint Proxy With Allowlist

The API surface is proxied through a single chokepoint. The SSRF perimeter is
an explicit allowlist of upstream paths. The allowlist now lives on the API
Gateway, declared in the APISIX route configuration; the API Gateway is the
single component that decides whether an inbound `/api/**` path is forwarded
to the Resource Server.

Per-endpoint Gateway mirrors were rejected because they duplicate Resource
Server policy in the Gateway. An unrestricted proxy was rejected because it
creates an SSRF surface. The Resource Server also denies browser origins via
CORS as defense in depth, even when deployment topology keeps it unreachable
from the browser.

Trade-off: adding an RS endpoint requires updating the API Gateway allowlist.

Spec: SPEC-0001 API Gateway proxy row.

### C5. Explicit Resource Server Token Validation

The Resource Server does not trust issuer alone. It validates issuer,
signature, expiration, algorithm, audience, scope, and roles. The access-token
audience is the Resource Server audience. The ID-token audience is the BFF
client ID and is validated only by the BFF during callback.

Issuer-only trust was rejected because it permits audience confusion. Implicit
role mapping was rejected because provider role/group claims differ. Algorithm
defaults are pinned to avoid algorithm-confusion classes.

Trade-off: an explicit JWT validator chain and custom authority converter.

Spec: SPEC-0001 Resource Server; SPEC-0001 Threat Model.

## D. Runtime

### D1. Virtual Threads On Spring Services

Virtual threads are enabled on both Spring services in the reference: the
Auth Service and the Resource Server. Their workloads are IO-bound:
state-store lookups, token endpoint calls, JWKS discovery, and the Auth
Service's `/internal/refresh` Keycloak round-trip. Virtual threads scale
this workload without forcing the project into a reactive programming model.

The API Gateway is APISIX (OpenResty / nginx + Lua), not a Spring service,
so D1 does not apply to it. APISIX's own request model — nginx worker
processes with cooperative Lua coroutines per request — is the
production-shape equivalent for the Gateway's small, latency-sensitive
routing workload.

Reactive Spring was rejected for the Spring services because the servlet
OAuth2 Client surface is more mature and the workload does not justify the
programming-model cost.

Trade-off: the project requires a recent Java and Spring Boot baseline on
the two Spring services.

Spec: SPEC-0001 Target Stack.

## E. Local Development

### E1. Dev Cookie Binds To The SPA Origin Via Forwarded Headers

The reference has two ingress shapes:

- **Frontend dev loop (`npm run dev`).** Vite proxy with two upstreams:
  `/auth/*` → Auth Service (`:8081`), `/api/**` → APISIX (`:9080`). Both
  legs set `X-Forwarded-Host` / `-Proto` / `-Port` so the browser sees a
  single SPA origin.
- **Full Compose run.** APISIX is the ingress directly — there is no
  separate ingress proxy in front of it. APISIX terminates the browser
  connection, routes `/auth/*` to the Auth Service and `/api/**` through
  its own `bff-session` plugin to the Resource Server, and forwards the
  same forwarded-header set to the Auth Service.

The session cookie must bind to the SPA origin so the browser sends it on
SPA-origin `/auth/*` and `/api/**` requests. Both ingress shapes preserve
that contract by forwarding the SPA origin to the Auth Service, which uses
Spring's `forward-headers-strategy: framework` when computing its base URL.

Registering the OAuth redirect URI at an upstream origin was rejected. It
makes login appear to work, but the browser will not send the upstream-origin
cookie on SPA-origin fetches.

Trade-off: local correctness depends on proxy-header configuration on both
the Vite proxy (dev) and APISIX (full Compose), plus the Auth Service
forwarded-header strategy.

Spec: SPEC-0001 Frontend Behavior; SPEC-0001 API Gateway Architecture.

### E2. No Committed Working Secrets

The local reference should start with generated local secrets or documented
example placeholders that are not valid credentials. A realm import may contain
obvious placeholders, but a functioning secret must be generated outside git
and supplied via local configuration.

The "commit a working dev secret for one-command startup" path was rejected.
It makes demos easier but teaches the wrong habit and creates avoidable audit
noise.

Trade-off: local startup needs a bootstrap step or generated `.env` file.

Spec: SPEC-0001 acceptance criteria.

### E3. OAuth Client Registration Name Is Opaque

The OAuth client registration name appears in callback URL patterns. Naming it
after the local IdP brand would bake the provider identity into the URL
contract. The registration name is opaque so swapping providers does not change
the application URL shape.

Trade-off: local config is less brand-obvious.

Spec: SPEC-0001 BFF Client.

## F. Security Extensions And Triggers

These items capture security extensions that are either deliberately outside the
local reference or implemented with production deployment caveats.

### Sender-Constrained Tokens (DPoP Or mTLS)

Not adopted because the BFF pattern removes the primary browser-token leakage
threat, and the local RS is isolated behind the API Gateway and the
service-client boundary.

Reconsider when the Resource Server is exposed to multi-tenant or untrusted
callers, or when API-Gateway-to-RS network isolation is no longer a valid
assumption.

### Asymmetric Client Authentication

`private_key_jwt` and mTLS are not adopted for the local reference. Shared
secret client authentication is simpler and sufficient for the teaching
baseline.

Reconsider for production targets or compliance regimes such as FAPI or PSD2.

### JAR, PAR, And RAR

JAR, PAR, and Rich Authorization Requests are not adopted. Exact redirect URI
matching, PKCE, state, and nonce cover the demonstrated flow; scopes cover the
demonstrated authorization model.

Reconsider when adding multiple authorization servers, untrusted-network
authorization request handling, or structured per-resource grants.

### Back-Channel Logout

Adopted for the local reference as a standard OP-initiated session termination
signal. The Auth Service validates signed logout tokens, rejects replayed
`jti` values, deletes by `sid` when present, and only falls back to subject-wide
deletion when the logout token has no `sid`.

Production deployments must provide a trusted route from the OP to the Auth
Service; the browser-facing gateway still does not expose internal refresh or
session-store surfaces.

### URL-Form Audience

Not adopted because one logical Resource Server audience is simpler for the
single-RS reference.

Reconsider when adding a second Resource Server or binding tokens to concrete
resource URLs.

### Global CSP And Referrer-Policy Baseline

A global application CSP and Referrer-Policy baseline are deferred because
they do not change the OAuth/OIDC contract.

Reconsider before any non-local deployment.

## Locked Baseline

The Java/Spring baseline is fixed for both Spring services (Auth Service
and Resource Server): Java 25 and Spring Boot `4.1.0-RC1`. The API Gateway
runs on APISIX (current stable).
