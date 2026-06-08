# GOAL-0001: Frontend React SPA (BFF Cookie Client)

> Filename retains `pkce` for historical link stability. The SPA does **not**
> perform PKCE — the BFF does. This goal owns the cookie-authenticated SPA
> that talks only to the BFF.

## Directory

`frontend/`

## Goal

Deliver a React + TypeScript + Vite SPA that authenticates by calling BFF
endpoints (`/auth/login`, `/auth/me`, `/auth/logout`) and consumes APIs
through the BFF proxy (`/api/*`) using only the same-origin session cookie.
The SPA must contain no OAuth/OIDC client library and no token-handling
code, and Playwright must prove that after a real authenticated session no
token resides in `localStorage`, `sessionStorage`, IndexedDB, or
JS-visible cookies.

## Purpose

The frontend demonstrates the browser side of the BFF pattern: tokens are
invisible to JavaScript. Login is a navigation, not a fetch; API calls are
cookie-authenticated against the same origin; UI authorization is cosmetic.

**The SPA is OIDC-oblivious.** It talks only to same-origin, gateway-relative
paths — `/auth/me`, `/auth/login`, `/auth/logout`, `/auth/logout/continue`,
and `/api/**`. It knows nothing of Keycloak or any IdP: no issuer,
`authorize`, `token`, JWKS, or `end_session` endpoint appears in frontend
code or configuration. The confidential OIDC client role lives entirely in
the Auth Service behind the gateway.

## Owned Paths

- `frontend/`
- Frontend-specific tests under `frontend/`
- Frontend docs scoped to browser behavior
- Frontend task packets

## Avoid Paths

- `bff/`
- `backend-resource-server/`
- `authorization-server/`
- Shared root config unless explicitly coordinated

## Required Technology

- React `19.2.6`, TypeScript `6.0.3`, Vite `8.0.14`, Vitest `4.1.7`,
  Playwright `1.60.0`.
- Vite dev-server proxy with two upstreams so the cookie is same-origin in
  dev: `/auth/*` → Auth Service (`http://localhost:8081`) and `/api/**` →
  APISIX API Gateway (`http://localhost:9080`). Both upstreams honor
  `X-Forwarded-Host` / `-Proto` / `-Port`. (In the full Compose stack
  APISIX takes both paths on a single browser-facing port; the Vite proxy
  is the dev-loop equivalent.)
- **No OAuth/OIDC client library.** No `oidc-client-ts`, no `oauth4webapi`,
  no `auth0-spa-js`.

## Required User Journeys

- Visitor unauthenticated → home page shows Sign in.
- Login is triggered by either a top-level navigation to a protected URL
  (implicit, saved-request) or by clicking Sign in which navigates to
  `/auth/login?return_to=<current-route>`. A bare `/auth/login` is invalid.
- SPA reacts to a `401` from `/api/*` by performing a top-level
  navigation (it does not try to handle the AS login page in an XHR).
- Browser redirected to Keycloak, user authenticates, and the Auth Service
  callback returns a direct same-origin `302` to the validated saved request
  URL while setting the Lax session cookie.
- SPA loads user state from `/auth/me`.
- SPA calls `GET /api/me` and `GET /api/user-data`; renders results.
- SPA renders a denied response honestly (no pretending the user has
  access).
- User clicks Logout → `POST /auth/logout` with `Accept: application/json`
  and CSRF header → BFF clears the session and returns a same-origin
  `{"logoutUrl":"/auth/logout/continue?lc=<handle>"}` → SPA performs a
  top-level navigation to that same-origin handle, which the Auth Service
  resolves and redirects through OIDC end-session. The SPA never sees the
  IdP `end_session` URL or the `id_token_hint`.

## Security Requirements

- No OAuth/OIDC client library.
- No `localStorage`, `sessionStorage`, IndexedDB, or JS-readable cookie
  writes of any token, code, or claim payload.
- All `fetch` calls use `credentials: "include"` against same-origin
  `/auth/*` and `/api/*` paths only.
- CSRF token (returned by BFF on first GET, sent as header) on every
  POST/PUT/DELETE.
- Never log responses that include sensitive claims; redact email, sub.
- UI authorization is display-only; backend enforces.

## Acceptance Criteria

- `npm install` and `npm run dev` work.
- `npm run build` succeeds.
- `npm run test` (Vitest) and `npm run test:e2e` (Playwright) run green.
- Playwright proves login, callback, `/auth/me`, protected API call,
  denied state, logout.
- Playwright authenticated-session assertion confirms zero tokens in any
  browser-side storage.
- The app is configured via Vite env files (no secret values).
- Docs explain why no OIDC library is present.

## Required Tests

- Sign in link points to `/auth/login?return_to=<current-route>`
  (navigation, not fetch).
- `/auth/me` happy path renders identity.
- `/auth/me` 401 renders unauthenticated state.
- `GET /api/me` happy path.
- `GET /api/user-data` happy path.
- `GET /api/user-data` 403 renders honest denial.
- Logout button POSTs `/auth/logout` with CSRF and navigates to returned
  `logoutUrl`.
- Playwright end-to-end against live stack with Keycloak login automation.
- Playwright storage assertion: after login, `localStorage`,
  `sessionStorage`, `document.cookie`, and IndexedDB contain no tokens.
- Saved-request replay: top-level navigation to a protected URL completes the
  OAuth callback's direct 302 and ends on that same URL — not on `/`.
- XHR `401`: `fetch('/api/me')` with no session yields `401`, and the SPA
  reacts by initiating a top-level navigation.

## Evidence For Completion

- Vitest output.
- Playwright trace for full flow.
- Storage assertion output.
- Docs section on cookie + same-origin proxy design.

## Blocked Conditions

Stop and report if:

- BFF `/auth/*` or `/api/*` is unavailable.
- Vite proxy cannot reach the BFF host.
- Keycloak login automation cannot be driven from Playwright in the local
  environment.
