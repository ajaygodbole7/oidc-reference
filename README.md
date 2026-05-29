# OIDC Reference

World-class local OAuth 2.1 and OpenID Connect reference project.

This repository is intentionally spec-first. Implementation work should begin by
reading `AGENTS.md`, then the documents under `docs/`.

## Architecture

The browser never holds an access, refresh, or ID token. The BFF session
pattern is implemented as two cooperating services — a dedicated **Auth
Service** (the confidential OAuth/OIDC client, owner of `/auth/*`) and a
dedicated **API Gateway** (owner of `/api/**`, bearer-injection and
allowlist enforcement) — fronted by a single ingress. Tokens live in a
Redis-compatible server-side state store (Valkey locally) and are addressed
by an opaque, `HttpOnly` session cookie. Two flows are demonstrated:
browser user login (saved-request + PKCE) and service-to-service (Client
Credentials).

### Browser flow — Authorization Code + PKCE (split BFF; saved-request replay)

Login is triggered either **implicitly** (the browser hits any protected
URL while unauthenticated) or **explicitly** (the user clicks a Sign in
link that navigates to `/auth/login`). The API Gateway detects no-session
on `/api/**` and (for top-level navigation) bounces to `/auth/login`. The
Auth Service runs the OAuth round-trip, then issues a direct `302` to the
saved request URL with the session and CSRF cookies attached.

```mermaid
sequenceDiagram
    autonumber
    actor U as User
    participant B as Browser (React SPA)
    participant G as API Gateway (APISIX standalone + Lua plugin)
    participant A as Auth Service (Spring Boot, confidential OIDC client)
    participant K as Authorization Server (Keycloak local, pluggable)
    participant V as State Store (Valkey local)
    participant R as Resource Server (Spring Boot)

    Note over U,R: Login — Authorization Code + PKCE. Triggered by protected-resource request OR explicit /auth/login.
    U->>B: Navigate to protected URL (or click "Sign in" → /auth/login)
    B->>G: GET /api/<protected>  (no cookie)
    G->>G: No sess:{sid} — check Fetch Metadata
    alt Sec-Fetch-Mode: navigate AND Sec-Fetch-Dest: document
        G-->>B: 302 /auth/login?return_to=/api/<protected>
    else XHR / fetch
        G-->>B: 401 (SPA performs top-level navigation)
    end
    B->>A: GET /auth/login?return_to=/api/<protected>
    A->>A: Validate return_to (required, same-origin relative path, reject absolute / // / missing leading slash / overlong / encoded backslash)
    A->>A: Generate state, nonce, PKCE verifier, oauth_tx browser-binding token
    A->>V: SET tx:{state} = {verifier, nonce, saved_request=return_to, tx_cookie_hash=HMAC(oauth_tx)}  (TTL 5m)
    A-->>B: 302 → Keycloak /auth?code_challenge=S256&state&nonce<br/>+ Set-Cookie oauth_tx=opaque, HttpOnly, SameSite=Lax, Path=/auth/callback/idp
    B->>K: GET /auth
    U->>K: Authenticate
    K-->>B: 302 /auth/callback/idp?code&state&iss
    B->>A: GET /auth/callback/idp?code&state&iss  (Cookie: oauth_tx)
    A->>V: GET tx:{state} → {verifier, nonce, saved_request, tx_cookie_hash}  (then DEL — single-use)
    A->>A: Validate iss param matches configured issuer (RFC 9207 mix-up defense)
    A->>A: Verify HMAC(oauth_tx cookie) equals stored tx_cookie_hash (browser binding)
    A->>K: POST /token  (code + verifier + client_secret)
    K-->>A: access_token, refresh_token, id_token
    A->>A: Validate id_token (iss, aud=oidc-reference-auth, nonce, sig, exp, at_hash when present)
    A->>V: SET sess:{sid} = {tokens, claims, xsrf_token, absolute_expires_at}  (sliding TTL 30m, absolute ceiling 12h)
    A-->>B: 302 saved_request<br/>+ Set-Cookie __Host-sid=opaque, HttpOnly, Secure, SameSite=Lax, Path=/<br/>+ Set-Cookie XSRF-TOKEN=signed, Secure, SameSite=Strict, Path=/ (JS-readable)<br/>+ Set-Cookie oauth_tx=, Max-Age=0 (single-use, evicted even on success)

    Note over B,R: Saved-request replay → authenticated API call
    B->>G: GET /api/<protected>  (Cookie: __Host-sid, XSRF-TOKEN)
    G->>V: GET sess:{sid}
    opt access_token within refresh window
        G->>A: POST /internal/refresh (Authorization Bearer gateway-service-token, body sid)
        A->>A: Acquire per-sid lock, validate Client Credentials token (aud=oidc-reference-auth-internal)
        A->>K: POST /token  (grant_type=refresh_token)
        K-->>A: rotated access_token + refresh_token
        A->>V: UPDATE sess:{sid}
        A-->>G: 200 {refreshed_at, access_token_expires_at}
        G->>V: GET sess:{sid}  (re-read for fresh access_token)
    end
    G->>R: GET /api/protected + Authorization Bearer access_token (strip inbound Cookie, strip hop-by-hop)
    R->>R: Validate JWT  (iss, sig, exp, aud, scope, roles)
    R-->>G: 200 {body}
    G-->>B: 200 {body}

    Note over B,K: Logout — RP-initiated
    B->>A: POST /auth/logout (Cookie __Host-sid, header X-XSRF-TOKEN signed)
    A->>A: Validate signed double-submit CSRF (HMAC over token value)
    A->>V: DEL sess:{sid}
    A-->>B: 302 → Keycloak /logout?id_token_hint<br/>+ Referrer-Policy no-referrer (id_token_hint carries PII)<br/>+ Set-Cookie __Host-sid=, Max-Age=0<br/>+ Set-Cookie XSRF-TOKEN=, Max-Age=0<br/>+ Set-Cookie oauth_tx=, Max-Age=0 (safety-net for aborted login mid-flow)
    B->>K: GET /logout
    K-->>B: 302 /  (post-logout redirect)
```

**XHR vs top-level navigation.** When a `fetch`/XHR to `/api/*` arrives
without a session, the API Gateway returns `401` (not a redirect — XHR
cannot render the AS login page). The SPA reacts by performing a top-level
navigation to `/auth/login` or to the originally-intended URL, which
triggers the saved-request flow above. The implicit saved-request dance
is reserved for top-level document navigations. The API Gateway distinguishes
the two using Fetch Metadata (`Sec-Fetch-Mode: navigate`,
`Sec-Fetch-Dest: document`) and uses `Accept: text/html` only as a
fallback; fetch/API requests fail fast.

### Service flow — Client Credentials (no Auth Service or API Gateway in path)

Machine-to-machine clients obtain a token directly from the
Authorization Server and call the Resource Server with a bearer token.
Neither the Auth Service nor the API Gateway is involved.

```mermaid
sequenceDiagram
    autonumber
    participant SC as Service Client (confidential, machine)
    participant K as Authorization Server (Keycloak local, pluggable)
    participant R as Resource Server (Spring Boot)

    Note over SC,R: Service-to-service — Client Credentials grant
    SC->>K: POST /token  (grant=client_credentials, client_id, client_secret)
    K->>K: Authenticate client (secret)
    K-->>SC: access_token  (aud=oidc-reference-api, scope=service.jobs)
    SC->>R: POST /api/jobs  + Authorization: Bearer <access_token>
    R->>R: Validate JWT  (iss, sig, exp, aud, scope)
    R-->>SC: 200 {result}
```

### Cookie attributes are the production contract

The diagrams are the production contract. The session cookie is `__Host-sid`
with `HttpOnly`, `Secure`, `SameSite=Lax`, `Path=/`, no `Domain`. In local
HTTP mode the cookie name downgrades to `sid` and `Secure` is dropped
(browsers reject `__Host-` without `Secure`). The CSRF cookie (`XSRF-TOKEN`)
is a JS-readable, **signed** token (HMAC over the value, or session-bound)
that the SPA echoes as the `X-XSRF-TOKEN` header on state-changing requests.
Naive unsigned double-submit is rejected — see decision B4.

## Current Status

The project is in specification and architecture setup.

Start here:

- `AGENTS.md`
- `docs/README.md`
- `docs/specs/SPEC-0001-core-oidc-flows.md`
- `RFC9700-compliance.md`
- `tasks/backlog.md`

## Intended Stack

- React + TypeScript SPA (no in-browser OIDC client).
- Java 25 + Spring Boot 4.1.0-RC1 Auth Service (OAuth/OIDC confidential
  client, Nimbus oauth2-oidc-sdk direct).
- Apache APISIX standalone mode API Gateway, with a custom Lua plugin for
  BFF session lookup, bearer injection, signed CSRF validation, and
  refresh delegation to the Auth Service.
- Redis-compatible server-side state store for session and PKCE-transaction
  storage; Valkey is the local reference implementation.
- Java 25 + Spring Boot 4.1.0-RC1 Resource Server (JWT validation).
- Keycloak local Authorization Server / Identity Provider.
- Docker Compose local infrastructure.
- No cloud dependencies.
