# GOAL-0004: Auth Service (OAuth/OIDC Confidential Client)

## Directory

`auth-service/`

## Goal

Deliver a Spring Boot 4 service that owns the OAuth/OIDC confidential-client
role for the reference. It exposes `/auth/*` to the browser through the
ingress, is the sole writer of `tx:{state}` and `sess:{sid}` in Valkey, holds
the per-session refresh lock, and exposes `/internal/refresh` to the API
Gateway as an OAuth Resource Server bound to the
`oidc-reference-auth-internal` audience. The Auth Service never returns a
token to the browser.

## Purpose

The Auth Service is one of the two services that implement the BFF pattern
in this reference. Splitting the OAuth client surface from the routing
surface mirrors production OIDC deployments at scale (identity team vs.
platform team, different load characteristics) and makes the reference
shape recognizable to production readers. See
`docs/architecture/architecture-decisions.md` §A6.

## Owned Paths

- `auth-service/`
- `auth-service/src/main/`
- `auth-service/src/test/`
- Auth-Service-specific docs and task packets.

## Avoid Paths

- `frontend/`, `api-gateway/`, `backend-resource-server/`,
  `authorization-server/`.
- Shared root config unless explicitly coordinated.

## Required Technology

- Java 25.
- Spring Boot `4.1.0-RC1`.
- Nimbus `oauth2-oidc-sdk` for the OIDC client role (authorization-request
  building, token-endpoint client, ID-token validation).
- Spring Security 7 — only for the `/internal/*` OAuth Resource Server
  role (JWT validation with audience binding).
- Redis-compatible client for the custom `tx:{state}` authorization-request
  repository and the custom `sess:{sid}` session repository (no Spring
  Session).
- Spring Web MVC, virtual threads enabled.
- Maven.

## IdP Portability

OAuth2 client registration name is `idp` (opaque, not the IdP brand). See
SPEC-0001 §"Authorization Server Portability".

## Required Endpoints

| Path | Method | Auth | Behavior |
|---|---|---|---|
| `/auth/login` | GET | none | **Requires** a `return_to` query parameter (the saved-request URL); validates it is a same-origin relative path and rejects a missing, absolute, protocol-relative, non-`/`-leading, overlong, or backslash-encoded value with `400` (no silent default to `/`). Generates `state`, `nonce`, PKCE verifier. Writes `tx:{state} = {verifier, nonce, saved_request, created_at}` TTL 5m. 302 to Keycloak authorization endpoint with `code_challenge=S256`, `state`, `nonce`. |
| `/auth/callback/idp` | GET | none | Reads and DELs `tx:{state}` in Valkey. Exchanges `code + verifier + client_secret` at Keycloak token endpoint. Validates `id_token` (iss, aud=`oidc-reference-auth`, nonce match, RS256, exp/nbf). Writes `sess:{sid}` with sliding TTL 30m. Issues `__Host-sid` (`HttpOnly`, `Secure`, `SameSite=Lax`, `Path=/`) and signed `XSRF-TOKEN` (JS-readable, signed double-submit). Responds with a **direct 302** to the validated `saved_request` — no intermediate landing page. |
| `/auth/me` | GET | session | Returns `{sub, preferred_username, name, email, roles}` from `sess:{sid}.claims`. Never returns a token. Response `Cache-Control: no-store`. |
| `/auth/logout` | POST | session | Requires signed double-submit CSRF. DEL `sess:{sid}`. Clears `__Host-sid` and `XSRF-TOKEN`. Builds the Keycloak `end_session_endpoint` URL with `id_token_hint` **server-side** and stores it under a single-use opaque handle (`logout:{handle}`, TTL 2m). Returns a **same-origin** JSON body `{"logoutUrl":"/auth/logout/continue?lc={handle}"}`. The id_token never reaches SPA JS or any SPA-readable body. |
| `/auth/logout/continue` | GET | none | Resolves the single-use `logout:{handle}` (GET-then-DEL) and `302`s to the Keycloak `end_session_endpoint` URL with `id_token_hint` and `Referrer-Policy: no-referrer`. Unknown/expired/missing handle → `302` to `/`. No session required; the opaque handle is the capability. See SPEC-0001 §"Auth Service Endpoints". |
| `/internal/refresh` | POST | service token | Internal-network only (not reachable via ingress). OAuth Resource Server: validates bearer token (iss, sig, exp, `aud` contains `oidc-reference-auth-internal`, `azp`/`client_id`=`oidc-reference-api-gateway`, alg RS256). Acquires per-session refresh lock for `sid`. POST `grant_type=refresh_token` to Keycloak. Validates rotation. On Keycloak `invalid_grant` (refresh token expired/revoked, SSO max reached, or reuse — not distinguishable at the RP): emits the structured `refresh_token_rejected` / `session_invalidated` audit event, DEL session, returns 409. On success: updates `sess:{sid}`, returns `{refreshed_at, access_token_expires_at}`. See SPEC-0001 §7.1. |

## Session Cookie

- Name `__Host-sid` in production; `sid` in local HTTP (browsers reject
  `__Host-` without `Secure`).
- `HttpOnly`, `SameSite=Lax`, `Path=/`, no `Domain`. `Secure` in production.
- Opaque, ≥128 bits of entropy; not a token.
- No intermediate landing page — the callback emits a direct 302. See
  `docs/architecture/architecture-decisions.md` §B2 for the rationale.

## State Store Keys

- `tx:{state}` — TTL 5m. Custom `OAuth2AuthorizationRequestRepository`
  writing directly to Valkey, **not** through Spring Session. Payload
  `{verifier, nonce, saved_request, created_at, tx_cookie_hash}`.
  `tx_cookie_hash` carries the HMAC of the `oauth_tx` browser-binding
  cookie issued alongside the login 302; the callback fails closed when
  the supplied cookie's HMAC does not match the stored hash. See
  `docs/architecture/architecture-decisions.md` §B3 for the rationale and
  `OAuthTxBinding.java` for the implementation.
- `sess:{sid}` — sliding TTL 30m, absolute cap 8h (kept ≤ the IdP's SSO max
  session lifespan; Keycloak default is 10h). Custom Redis-compatible
  session repository. Holds tokens and claims. Schema per SPEC-0001 §7.2.
  The Auth Service is the sole writer; the API Gateway is a tolerant reader.

## Signed CSRF

- `XSRF-TOKEN` is **signed** double-submit: value is
  `<token-value-base64>.<hmac-base64>` where the HMAC is over the
  token-value using a server-side signing key shared with the API Gateway.
- Cookie is JS-readable (`HttpOnly=false`), `Secure`, `SameSite=Strict`,
  `Path=/`, no `Domain`. See SPEC-0001 §7.3 for the Strict-vs-Lax rationale
  (state-changing requests are same-origin XHR; the cookie never needs to
  ride a cross-site navigation, and `Strict` denies it from ever doing so).
- Validation: constant-time HMAC compare on receipt. Naive (unsigned)
  double-submit is explicitly rejected — see SPEC-0001 §7.3 and
  `docs/architecture/architecture-decisions.md` §B4 for the cookie-injection
  threat model.

## Security Requirements

- Fresh `sess:{sid}` minted on successful callback. No session is created
  before ID-token validation.
- Refresh tokens rotated on every use; an `invalid_grant` on refresh (reuse
  being one possible cause) emits a structured `refresh_token_rejected` audit
  event and invalidates the session.
- Per-session refresh lock around the `/internal/refresh` handler.
  In-process `ReentrantLock` keyed by `sid` for single-instance; Valkey
  `SET NX EX` for clustered deployments.
- Login-CSRF defense is `state` (server-side validated against
  `tx:{state}`) + PKCE code-verifier (S256, required) + ID-token `nonce`
  validation + the `oauth_tx` browser-binding cookie (HMAC stored in
  `tx:{state}.tx_cookie_hash`, verified on callback before the token
  exchange). The Tier A staff-review trail reinstates `oauth_tx` after
  the B3 reversal — see OAuthTxBinding for the implementation.
- The signing key for `XSRF-TOKEN` is supplied via env (gitignored),
  256-bit random, rotated through the documented grace-window procedure.
- Logging never includes tokens, codes, cookies, or secrets.
- Custom `OAuth2AuthorizationRequestRepository` writing to Valkey directly.
  Spring's default `HttpSessionOAuth2AuthorizationRequestRepository` would
  violate the separate-`tx:{state}`-keyspace contract.
- Custom Redis-compatible session repository for `sess:{sid}`. Tokens and
  claims must not live in a framework-managed HTTP session.

## Acceptance Criteria

- `./mvnw test` green.
- App starts on port `8081` and reaches Keycloak + Valkey.
- Login → callback → `/auth/me` end-to-end against local stack via the
  ingress (Vite proxy in dev; Traefik in full Compose).
- Cookie has documented attributes (`SameSite=Lax`, `HttpOnly`) verified by
  integration test.
- Callback returns a **direct 302** to `saved_request` (no landing page);
  verified by integration test.
- Callback creates a `sess:{sid}` key only after ID-token validation; no
  token or claim is stored in a framework-managed HTTP session.
- Refresh rotation works; an `invalid_grant` on refresh invalidates the
  session and emits the structured `refresh_token_rejected` audit event.
- `/internal/refresh` rejects calls without a valid
  `oidc-reference-api-gateway` Client Credentials token whose audience
  contains `oidc-reference-auth-internal`.
- Signed CSRF token tamper rejection: a token with a forged signature or a
  modified value is rejected; a valid token is accepted.
- Logout deletes the session and returns a same-origin
  `{"logoutUrl":"/auth/logout/continue?lc={handle}"}`; the
  `/auth/logout/continue` handle then redirects through Keycloak
  end-session with `id_token_hint`.
- No secret is committed.

## Required Tests

- `/auth/login` returns 302 to Keycloak with `code_challenge=S256`,
  `state`, `nonce`.
- `/auth/login?return_to=<same-origin path>` persists `saved_request = <that URL>`;
  a missing, cross-origin (absolute), or otherwise invalid `return_to` is
  rejected with `400` (no silent default to `/`).
- ID-token validation negatives — port the existing
  `JwtOidcIdTokenValidatorTest` from the retired `bff/`: wrong issuer,
  wrong audience (`aud != oidc-reference-auth`), wrong nonce, wrong
  algorithm (non-RS256), expired, `nbf` in future, malformed signature.
- Callback creates exactly one `sess:{sid}` key after successful ID-token
  validation and stores no token/claim payload in any framework-managed
  HTTP session.
- Callback rejects mismatched `state` (no matching `tx:{state}` record).
- An `invalid_grant` from Keycloak on refresh invalidates `sess:{sid}` and
  emits the structured `refresh_token_rejected` audit event.
- `/internal/refresh` contract:
  - Rejects unauthenticated request (`401`).
  - Rejects token with wrong audience (`401`).
  - Rejects token with wrong `azp`/`client_id` (`401`).
  - Returns `404` when `sess:{sid}` is missing.
  - Returns `409` on `invalid_grant` (refresh rejected) and emits the audit
    event.
  - Per-session refresh lock prevents two concurrent calls from issuing
    two refreshes against Keycloak.
  - Idempotent under contention: if a concurrent call already refreshed
    within the no-refresh window, returns `200` with the current expiry
    without a second Keycloak round-trip.
- Signed CSRF:
  - Forged HMAC signature rejected.
  - Tampered token-value (matching old HMAC) rejected.
  - Missing cookie or missing header rejected.
  - Valid signed token accepted.
- Saved-request E2E via direct 302: top-level navigation to a protected
  URL passes through Keycloak and ends on that URL via direct redirect
  (no landing page).
- Logout deletes `sess:{sid}` and returns the same-origin continuation
  handle; `/auth/logout/continue` resolves it (single-use) and issues the
  Keycloak end-session redirect with `id_token_hint`.

## Evidence For Completion

- Test output.
- Startup logs (issuer, JWKS, Valkey reachable; no secrets).
- Sample HTTP transcripts for `/auth/login`, callback, `/internal/refresh`
  (redacted).

## Blocked Conditions

Stop and report if:

- Spring Boot `4.1.0-RC1`, Nimbus `oauth2-oidc-sdk`, or the chosen
  Redis-compatible client artifacts are unavailable.
- Valkey image unavailable.
- Keycloak `oidc-reference-auth` or `oidc-reference-api-gateway` client
  missing or misconfigured.
- The realm-level `auth.internal` scope or the
  `oidc-reference-auth-internal` audience mapper is missing.
