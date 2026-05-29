# Return-To Login Contract

This document is the implementation contract for login entry, saved-request
replay, and frontend/auth separation in the API Gateway + Auth Service
architecture.

Use it when implementing or reviewing `frontend`, `api-gateway`, and
`auth-service` changes. It is intentionally strict: loose defaults here hide
authentication bugs.

## Goal

`/goal Implement login entry so the browser starts authentication only through
the API Gateway/Auth Service using /auth/login?return_to=..., verified by unit,
integration, and E2E tests proving return_to is mandatory, validated, stored in
tx:{state} with PKCE/nonce, and replayed only from server-side transaction
state, while preserving the rule that tokens never reach the browser and the
frontend remains OIDC-oblivious. Use only same-origin Gateway paths from React,
standard OIDC parameters to the IdP, Redis-compatible server-side
transaction/session state, and provider-neutral configuration. Between
iterations, write the failing test that expresses the next contract gap, make
it pass with the smallest change, then run the focused verification gate. If
blocked, report the exact missing contract, failing test, or external
dependency needed to proceed.`

## Non-Negotiable Rules

- The frontend is not an OAuth/OIDC client.
- The frontend talks only to the API Gateway origin.
- The frontend never imports OAuth/OIDC/JWT libraries.
- The frontend never calls Keycloak, the Auth Service internal API, the
  Resource Server, discovery, JWKS, authorization, token, introspection, or
  end-session endpoints directly.
- Tokens, authorization codes, PKCE values, nonce values, and raw token claims
  never reach browser JavaScript, `localStorage`, `sessionStorage`,
  IndexedDB, or JS-readable cookies.
- Browser-visible login starts must use:

```text
/auth/login?return_to=<encoded relative path>
```

- `/auth/login` without `return_to` is invalid. It must fail loudly with
  `400 application/problem+json`.
- The callback must never accept a return URL from callback query parameters,
  browser storage, `Referer`, or frontend memory.
- The callback redirects only to `saved_request` loaded from `tx:{state}`.

## Terminology

- `return_to`: Browser-facing query parameter on `/auth/login`. It is the
  relative URL the browser should return to after login.
- `saved_request`: Server-side field persisted in `tx:{state}` after
  validating `return_to`. Callback replay uses this value.
- `tx:{state}`: Short-lived Redis-compatible transaction record keyed by the
  OAuth `state` value. It contains the PKCE verifier, OIDC nonce,
  `saved_request`, and creation timestamp.
- `sess:{sid}`: Server-side authenticated session record keyed by an opaque
  session id. The browser receives only the opaque session cookie.

## Browser Flow

1. React app starts.
2. React calls:

```text
GET /auth/me
credentials: include
```

3. If `/auth/me` returns `200`, React renders the sanitized user envelope.
4. If `/auth/me` returns `401`, React performs a top-level navigation:

```text
/auth/login?return_to=<current path + query + hash>
```

5. API Gateway forwards `/auth/login?...` to the Auth Service.
6. Auth Service validates `return_to`.
7. Auth Service creates `state`, PKCE verifier/challenge, and nonce.
8. Auth Service writes:

```json
{
  "verifier": "<pkce-code-verifier>",
  "nonce": "<oidc-nonce>",
  "saved_request": "/original/path?query=1#fragment",
  "created_at": "<instant>"
}
```

to `tx:{state}` with the configured short TTL.

9. Auth Service redirects to the configured IdP authorization endpoint using
   standard OIDC parameters only.
10. IdP redirects to `/auth/callback/idp?code=...&state=...`.
11. Auth Service atomically reads and deletes `tx:{state}`.
12. Auth Service exchanges `code + verifier` with the IdP token endpoint.
13. Auth Service validates the ID token.
14. Auth Service creates `sess:{sid}` and sets only opaque/session cookies.
15. Auth Service returns `302 <saved_request>`.
16. React calls `/auth/me` again and renders authenticated state.

## Frontend Requirements

The frontend may know only these browser-facing paths:

- `GET /auth/me`
- `GET /auth/login?return_to=...` through top-level navigation
- `POST /auth/logout`
- `/api/**`

Frontend implementation requirements:

- `fetch("/auth/me", { credentials: "include" })`.
- A `401` from `/auth/me` triggers top-level navigation to
  `/auth/login?return_to=<current route>`.
- A user-visible Sign in link must include `return_to`; a bare `/auth/login`
  link is forbidden.
- A `401` from `/api/**` does not navigate to the API URL. It triggers
  top-level navigation to `/auth/login?return_to=<current route>`.
- `return_to` is computed from:

```text
window.location.pathname + window.location.search + window.location.hash
```

- If the computed route is empty or malformed, use `/`.
- URL-encode the `return_to` value in the query string.
- Do not send `Authorization: Bearer` from the frontend.
- Do not parse JWTs.
- Do not store claims outside React memory. The `/auth/me` response is a
  sanitized display envelope, not a token.

Frontend tests must prove:

- `/auth/me` is called with `credentials: "include"`.
- `/auth/me` `401` causes top-level navigation to
  `/auth/login?return_to=...`.
- Sign in link includes `return_to`.
- API `401` causes top-level navigation to `/auth/login?return_to=...`.
- No OAuth/OIDC/JWT libraries are present in frontend dependencies.
- Frontend source does not contain IdP endpoints, discovery URLs, token
  endpoint paths, JWKS paths, or bearer-token construction.
- Browser storage contains no tokens after login.

## API Gateway Requirements

The API Gateway is the browser security boundary. The browser sees the Gateway
origin, not the Auth Service or Resource Server.

Gateway requirements:

- Browser-facing `/auth/**` routes are proxied to the Auth Service.
- Browser-facing `/api/**` routes require a valid session cookie.
- No-session top-level document navigation to protected `/api/**` returns:

```text
302 /auth/login?return_to=<original path + query>
```

- No-session XHR/fetch to `/api/**` returns `401` with no `Location` header.
- Request classification uses Fetch Metadata where available:
  `Sec-Fetch-Mode: navigate` and `Sec-Fetch-Dest: document`, with
  `Accept: text/html` as fallback.
- Gateway-generated `return_to` values must be relative paths only.
- Gateway must not generate or accept absolute external `return_to` URLs.
- Gateway must not expose the Auth Service internal `/internal/**` routes to
  the browser-facing ingress.
- Gateway injects `Authorization: Bearer <access_token>` only when proxying to
  the Resource Server, never toward the browser.

Gateway tests must prove:

- Top-level no-session navigation redirects to
  `/auth/login?return_to=...`.
- XHR/fetch no-session request returns `401`, not `302`.
- Redirect `return_to` preserves path and query.
- Absolute or protocol-relative return targets are not generated.
- Auth Service internal routes are not browser reachable.

## Auth Service Requirements

`/auth/login` is the only public login-start endpoint.

### `/auth/login`

Required behavior:

- Method: `GET`.
- Requires `return_to`.
- Missing `return_to`: `400 application/problem+json`.
- Empty `return_to`: `400 application/problem+json`.
- Absolute URL: `400 application/problem+json`.
- Protocol-relative URL beginning `//`: `400 application/problem+json`.
- Value not beginning `/`: `400 application/problem+json`.
- Overlong value, default max 2048 characters after decoding:
  `400 application/problem+json`.
- Valid value: persist as `saved_request` in `tx:{state}`.

Validation rule:

```text
return_to must be a same-origin relative path beginning with exactly one "/".
```

Recommended valid examples:

```text
/
/dashboard
/jobs/123?tab=events
/settings#sessions
```

Rejected examples:

```text
https://evil.example/
//evil.example/
evil/path
javascript:alert(1)
/%5C%5Cevil.example
```

After validation, `/auth/login` generates:

- OAuth `state`
- PKCE `code_verifier`
- PKCE `code_challenge` using S256
- OIDC `nonce`
- `created_at`

It writes all transaction fields to `tx:{state}` before redirecting to the
Authorization Server.

The redirect to the IdP must use only provider-standard parameters:

- `client_id`
- `redirect_uri`
- `response_type=code`
- `scope`
- `state`
- `nonce`
- `code_challenge`
- `code_challenge_method=S256`

Do not send `return_to` or `saved_request` to the IdP.

### `/auth/callback/idp`

Required behavior:

- Requires `code` and `state`.
- Atomically read and delete `tx:{state}`.
- If `tx:{state}` is missing or expired, return a failure response and do not
  exchange the code.
- Exchange the authorization code using the stored PKCE verifier.
- Validate ID token issuer, audience, signature algorithm, signature,
  expiration/not-before, and nonce.
- Create a new opaque session id.
- Write `sess:{sid}`.
- Set only session/CSRF cookies required by the contract.
- Redirect to stored `saved_request`.

Forbidden callback behavior:

- Do not read `return_to` on callback.
- Do not read a return URL from the callback query string.
- Do not use `Referer`.
- Do not use frontend-provided state.
- Do not default silently to `/` if `saved_request` is missing from the
  transaction record. Treat that as transaction corruption.

Auth Service tests must prove:

- Missing `return_to` returns `400 ProblemDetail`.
- Invalid `return_to` variants return `400 ProblemDetail`.
- Valid `return_to` is persisted as `saved_request` in `tx:{state}`.
- `tx:{state}` contains verifier, nonce, saved_request, and created_at.
- The IdP authorization redirect contains `state`, `nonce`, and
  `code_challenge=S256`.
- The IdP authorization redirect does not contain `return_to` or
  `saved_request`.
- Callback uses stored `saved_request`.
- Callback ignores any callback query parameter that tries to override the
  return target.
- Callback deletes `tx:{state}`.

## IdP Portability

This contract must remain provider-neutral.

`return_to` and `saved_request` are internal application state. They are not
OIDC provider features and must not require Keycloak-specific behavior.

The IdP sees only standard OAuth/OIDC parameters. A swap to Cognito, Entra ID,
Okta, Auth0, Ping, Google, or another compliant provider must not require
frontend code changes and must not require provider-specific branches in
Gateway/Auth Service code.

Provider-specific values belong in configuration:

- issuer
- authorization endpoint
- token endpoint
- JWKS URI
- end-session endpoint, if used
- client id
- client authentication method/secret
- scopes
- expected audiences
- claim mapping configuration

## RFC/OIDC Alignment

This pattern is compatible with OAuth/OIDC best practice:

- Authorization Code flow stays server-side in a confidential client.
- PKCE S256 protects the authorization code exchange.
- `state` binds callback to a server-side transaction and prevents CSRF.
- OIDC `nonce` binds the ID token to the login transaction.
- Exact registered `redirect_uri` remains provider-facing and stable.
- Browser-side code never receives tokens or authorization codes.
- Redirect replay uses server-side state, not untrusted callback parameters.

`return_to` is not an OAuth/OIDC protocol parameter. It is local application
state that is validated and stored before the Authorization Server redirect.

## TDD Sequence

Implement in this order:

1. Frontend red tests:
   - Sign in link includes `return_to`.
   - `/auth/me` `401` navigates to `/auth/login?return_to=...`.
   - API `401` navigates to `/auth/login?return_to=...`.
2. Frontend implementation.
3. Auth Service red tests:
   - `/auth/login` without `return_to` returns `400`.
   - invalid `return_to` variants return `400`.
   - valid `return_to` is stored as `saved_request` in `tx:{state}`.
4. Auth Service implementation.
5. Gateway red tests:
   - top-level no-session `/api/**` redirects with `return_to`.
   - XHR/fetch no-session `/api/**` returns `401`.
6. Gateway implementation.
7. Cross-service/E2E:
   - unauthenticated route -> login -> IdP -> callback -> saved route.
   - no tokens in browser storage.
   - frontend never calls IdP endpoints directly.

Do not skip red tests. If a test cannot be written because an interface is
unclear, stop and update this contract first.

## Review Checklist

- [ ] No bare `/auth/login` remains in frontend code or tests.
- [ ] No `next` query parameter remains in the active contract.
- [ ] `/auth/login` requires `return_to`.
- [ ] `return_to` validation rejects absolute and protocol-relative URLs.
- [ ] `saved_request` is persisted before redirecting to the IdP.
- [ ] Callback uses only `tx:{state}.saved_request`.
- [ ] IdP authorization request does not include `return_to`.
- [ ] Frontend has no OAuth/OIDC/JWT dependencies.
- [ ] Frontend sends no bearer tokens.
- [ ] Gateway is the only browser-facing application surface.
- [ ] Auth Service internal endpoints are not exposed to the browser.
- [ ] Provider-specific behavior remains configuration-only.
