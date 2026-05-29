> **SUPERSEDED 2026-05-25** by GOAL-0004-auth-service.md and GOAL-0005-api-gateway.md. See `/RESHAPE-FRAME-B.md` for the architectural pivot.

# GOAL-0004: Backend-for-Frontend (BFF)

## Directory

`bff/`

## Goal

Deliver a Spring Boot BFF that is the only origin the browser talks to. It
owns the OAuth/OIDC flow as a confidential client (Authorization Code +
PKCE), stores OAuth transaction state in custom Redis-compatible
`tx:{state}` keys, stores tokens and claims in custom Redis-compatible
`sess:{sid}` keys only after successful callback, addresses the session
through an opaque `HttpOnly` session cookie, refreshes access tokens with
rotation + reuse detection, exposes `/auth/login`, `/auth/callback`,
`/auth/me`, `/auth/logout`, proxies `/api/**` to the Resource Server with a
bearer token (stripping browser cookies upstream), and never returns a token
to the browser.

## Purpose

The BFF is the architectural payload of this reference. It demonstrates the
modern browser-app pattern: tokens are server-side, sessions are
cookie-addressed, and the SPA is auth-naive.

## Owned Paths

- `bff/`
- BFF tests.
- BFF docs and task packets.

## Avoid Paths

- `frontend/`, `backend-resource-server/`, `authorization-server/`.
- Shared root config unless explicitly coordinated.

## Required Technology

- Java 25.
- Spring Boot `4.1.0-RC1`.
- Spring Security OAuth2 Client.
- Redis-compatible client for custom transaction and session repositories.
- Spring Web MVC.
- Maven.

## IdP Portability

OAuth2 client registration name is `idp` (opaque, not the IdP brand).
See SPEC-0001 §"Authorization Server Portability" for the contract.

## Required Endpoints

| Path | Method | Auth | Behavior |
|---|---|---|---|
| `/auth/login` | GET | none | 302 to the AS via Spring Security authorization-request filter (custom base URI). |
| `/auth/callback/idp` | GET | none | Spring Security exchanges code + verifier + secret, validates `id_token` (`aud` = BFF client id), creates a fresh `sess:{sid}`, validates `saved_request`, returns a same-origin landing page that sets the Strict session cookie and calls `window.location.replace(saved_request)`. |
| `/auth/me` | GET | session | Return `{sub, preferred_username, name, email, roles}`. Never returns a token. Response `Cache-Control: no-store`. |
| `/auth/logout` | POST | session | Requires double-submit CSRF. Invalidate session, delete `sess:{sid}`, clear cookies. Default response is `302` to the configured OIDC `end_session_endpoint` with `id_token_hint`; `Accept: application/json` returns `{logoutUrl}` for SPA-driven top-level navigation. |
| `/api/**` | any | session | Single wildcard handler with a path-pattern allowlist (`app.proxy.allow`; default `/api/me`, `/api/user-data`, `/api/admin`); paths outside the allowlist return 404. Resolve session → token; refresh if within 60s (per-session lock); proxy to Resource Server with `Authorization: Bearer`; strip inbound `Cookie` and hop-by-hop headers; forward query string. Response `Cache-Control: no-store`. |

## Session Cookie

- Name `sid` in local HTTP; production guidance `__Host-sid`.
- `HttpOnly`, `SameSite=Strict`, `Path=/`, no `Domain`. `Secure` in production.
- Opaque, ≥128 bits of entropy; not a token.
- The callback returns an intermediate same-origin landing page instead of
  a direct redirect. That page lets the browser commit the Strict cookie,
  then navigates to `saved_request` with
  `window.location.replace(saved_request)`.

## State Store Keys

- `tx:{state}` — TTL 5m. Separate state-store keyspace, keyed by the OAuth
  `state` parameter; not a framework-managed session attribute. Stores
  `saved_request` and `tx_cookie_hash`. (Requires a custom
  `OAuth2AuthorizationRequestRepository` in the BFF code — Spring's
  default is HttpSession-backed and would violate this contract.)
- `oauth_tx` — short-lived pre-auth transaction cookie. It is not a
  session cookie, carries no tokens or claims, and is used only to bind
  callback to the browser that initiated the flow.
- `sess:{sid}` — sliding TTL 30m, absolute cap 12h. Separate state-store
  keyspace, keyed by the opaque session id minted on successful
  callback. Holds tokens and claims. It is written by a custom state-store
  session repository, not by a framework-managed HTTP session store.

## Security Requirements

- Fresh `sess:{sid}` minted on successful callback (no prior session
  exists to fixate — see SPEC-0001 §"Session Lifecycle").
- Refresh tokens rotated on every use; reuse detection emits an audit log
  event and invalidates the session.
- Spring Security CSRF token required on `POST`/`PUT`/`DELETE` to `/api/**`.
- `/api/**` is a single wildcard handler backed by a path-pattern
  allowlist (`app.proxy.allow`). Paths outside the allowlist return 404.
  No arbitrary upstream URL pass-through.
- Logging never includes tokens, codes, cookies, or secrets.
- Per-session lock around the refresh path. Prevents the rotation-reuse
  race where two concurrent `/api/**` requests both trigger refresh and
  the second invalidates the first's rotated token. In-process lock is
  acceptable for a single BFF instance; a clustered BFF must use a
  distributed lock (Valkey `SET NX EX`).
- Saved-request handling: `tx:{state}` carries `saved_request` (the URL
  the browser originally tried to reach). After callback the BFF validates
  it as same-origin, returns a no-store landing page, and that page
  navigates to `saved_request`. Defaults to `/` for explicit `/auth/login`.
- XHR/fetch vs top-level navigation: unauthenticated `/api/*` requests
  return `401` unless they are clearly top-level document navigations.
  Prefer Fetch Metadata (`Sec-Fetch-Mode: navigate`,
  `Sec-Fetch-Dest: document`) when present; use `Accept: text/html` as a
  fallback. Do not rely on legacy nonstandard request headers.
- Login CSRF protection: callback rejects missing or mismatched `oauth_tx`
  before exchanging the authorization code; `oauth_tx` is deleted on
  callback success or failure.
- Requires a custom `OAuth2AuthorizationRequestRepository` in the BFF:
  Spring's default `HttpSessionOAuth2AuthorizationRequestRepository`
  bundles the request into the HttpSession blob and would violate the
  separate-`tx:{state}`-keyspace contract.
- Requires a custom state-store session repository for `sess:{sid}`. Tokens and
  claims must not be stored in a framework-managed HTTP session; the session
  cookie is only an opaque pointer to `sess:{sid}`.

## Acceptance Criteria

- `./mvnw test` green.
- App starts on port `8081` and reaches Keycloak + Valkey.
- Login → callback → `/auth/me` → `/api/me` end-to-end against local stack.
- Cookie has documented attributes; verified by integration test.
- Callback landing page is verified by integration test: `200 text/html`,
  `Cache-Control: no-store`, Strict session cookie, and
  `window.location.replace(...)` targeting the same-origin saved request.
- Callback creates a `sess:{sid}` key only after ID-token validation; no
  token or claim is stored in a framework-managed HTTP session.
- Refresh rotation works; reuse invalidates session.
- Logout deletes session and redirects through Keycloak end-session.
- No secret is committed.

## Required Tests

- `/auth/login` returns 302 to the AS with `code_challenge`, `state`,
  `nonce`.
- Callback rejects mismatched `state`.
- Callback rejects mismatched `nonce` in `id_token`.
- Callback rejects wrong-audience `id_token` (`aud` must be the BFF client
  id, not the Resource Server audience).
- Session id regenerated on login.
- Callback creates exactly one `sess:{sid}` key in the state store after ID-token
  validation and stores no token/claim payload in a framework-managed HTTP
  session.
- Reused refresh token invalidates session and logs an event.
- `/api/**` rejects missing/unknown cookie.
- `/api/**` strips upstream `Cookie`; only `Authorization: Bearer`
  forwarded.
- `/api/**` rejects upstream URL escape attempts.
- CSRF required on POST `/api/**`.
- Logout deletes `sess:{sid}` and issues end-session redirect.
- Concurrent `/api/*` requests on one session do not produce duplicate
  refresh calls (per-session lock).
- Top-level navigation to protected URL (no session) starts the OAuth
  flow and persists `saved_request = <that URL>`; after callback the
  landing page navigates the browser to `<that URL>`.
- Explicit `/auth/login` persists `saved_request = /`; after callback
  the landing page navigates the browser to `/`.
- Fetch/XHR to `/api/*` without session returns `401` (no `Location`, no
  OAuth flow start); document-navigation detection uses Fetch Metadata when
  present and `Accept` as fallback.
- Saved-request URL pointing to a cross-origin URL is rejected and
  replaced with `/` before being embedded in the landing page.
- Missing or mismatched `oauth_tx` on callback is rejected and no `sid`
  session cookie is issued.

## Evidence For Completion

- Test output.
- Startup logs (issuer, JWKS, Valkey reachable; no secrets).
- Sample HTTP transcripts (redacted).

## Blocked Conditions

Stop and report if:

- Spring Boot `4.1.0-RC1` or the chosen Redis-compatible client artifacts unavailable.
- Valkey image unavailable.
- Keycloak BFF client missing or misconfigured.
- Resource Server unreachable from the BFF network.
