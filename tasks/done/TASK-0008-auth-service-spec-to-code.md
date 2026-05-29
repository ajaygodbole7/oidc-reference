# TASK-0008: Auth Service — Spec-to-Code

## Objective

Implement the Auth Service per SPEC-0001 and GOAL-0004-auth-service:
own `/auth/login`, `/auth/callback/idp`, `/auth/me`, `/auth/logout`, and
`/internal/refresh`; be the sole writer of `tx:{state}` and `sess:{sid}`
in Valkey; issue signed double-submit CSRF tokens; validate ID tokens
with the full negative-test surface; emit the structured refresh-reuse
audit event. No application code exists yet under `auth-service/`; this
task creates it.

## Linked Spec

- `docs/specs/SPEC-0001-core-oidc-flows.md`
- `docs/goals/GOAL-0004-auth-service.md`
- `RESHAPE-FRAME-B.md` (§3.2 browser flow, §3.4 internal RPC, §7.1
  `/internal/refresh` contract, §7.3 signed CSRF contract)
- Root `README.md` (canonical sequence diagrams)

## Read First

- `AGENTS.md`
- `docs/agents/mandatory-turn-protocol.md`
- `docs/agents/execution-discipline.md`
- `docs/agents/task-template.md`
- `docs/testing/red-green-workflow.md`
- `RFC9700-compliance.md` (especially §4.7 CSRF and the Known Gaps)
- `docs/goals/archive/GOAL-0004-bff.md` (historical context — the
  combined-BFF predecessor; do not copy its landing-page or `oauth_tx`
  behavior, both are removed under B2/B3)

## Owned Paths

- `auth-service/`
- `auth-service/src/main/`
- `auth-service/src/test/`
- `auth-service/src/main/resources/application.yml`
- `auth-service/pom.xml`
- Auth-Service-specific docs and task notes

## Avoid Paths

- `api-gateway/` (separate task — TASK-0009)
- `frontend/`
- `backend-resource-server/`
- `authorization-server/realm/` (read-only inspection)
- Root `compose.yaml`, `README.md`, `docs/specs/`, `docs/goals/` (these
  are the contract — do not change them to fit the code; change the code
  to fit them)

## Required Workflow

Before coding, record in the working notes:

- Assumptions:
- Ambiguities:
- Owned paths: (mirror Owned Paths above)
- Success criteria: (mirror the Done Criteria below)

Plan:

```text
1. Scaffold auth-service/ (pom.xml with Spring Boot 4.1.0-RC1, Nimbus
   oauth2-oidc-sdk, Spring Security 7 for the /internal/* RS role,
   Redis-compatible client, virtual threads enabled, Java 25)
   -> verify: ./mvnw test boots a context with no Java sources beyond a
      smoke test.

2. Custom OAuth2AuthorizationRequestRepository writing tx:{state}
   directly to Valkey (separate from any framework HTTP session)
   -> verify: integration test asserts a Valkey key matching `tx:*`
      appears on /auth/login and is DELed after callback; no pre-callback
      session cookie is set.

3. Persist saved_request in tx:{state} on flow start; accept optional
   ?next= on /auth/login and validate same-origin; default to "/"
   -> verify: tests assert tx:{state} JSON includes saved_request derived
      from `next` (same-origin) or "/" (absent or cross-origin).

4. Port the existing JwtOidcIdTokenValidatorTest from the retired bff/
   into auth-service/src/test/ -> verify: tests cover wrong iss, wrong
   aud (must be oidc-reference-auth), wrong nonce, non-RS256 alg,
   expired, nbf-in-future, malformed signature.

5. Custom Redis-compatible session repository writing sess:{sid} only
   after successful callback and ID-token validation
   -> verify: integration test asserts exactly one `sess:*` key exists
      after a valid callback; no token/claim payload is present in any
      framework HTTP session; no `sess:*` key after a failed callback.

6. Callback returns a DIRECT 302 to the validated saved_request (no
   landing page). Set __Host-sid (SameSite=Lax, HttpOnly) and signed
   XSRF-TOKEN (HMAC, JS-readable)
   -> verify: integration test asserts `302`, `Location` is the validated
      saved-request URL, `Set-Cookie` includes `SameSite=Lax` and
      `HttpOnly` for the session cookie, and the XSRF-TOKEN value parses
      as `<value>.<hmac>` with a valid HMAC.

7. Signed CSRF token issuance and validation per RESHAPE-FRAME-B.md §7.3
   -> verify: forged-signature, tampered-value, missing-cookie, and
      missing-header cases all rejected; valid signed token accepted;
      HMAC compare is constant-time (negative-test passes regardless of
      where the mismatch falls in the byte string).

8. /internal/refresh as OAuth Resource Server (Spring Security 7) with
   audience validation. Bearer token must have iss = Keycloak issuer,
   valid signature, not expired, aud contains
   oidc-reference-auth-internal, azp/client_id = oidc-reference-api-
   gateway, alg = RS256
   -> verify: tests for each rejection produce 401 with
      application/problem+json; valid token reaches the handler.

9. Per-session refresh lock around /internal/refresh body. In-process
   ReentrantLock keyed by sid (Valkey SET NX EX noted as clustered
   alternative)
   -> verify: concurrent /internal/refresh calls for the same sid produce
      exactly one Keycloak round-trip; the second call sees the rotated
      token and returns 200 without re-calling Keycloak.

10. Refresh-with-audit: on Keycloak invalid_grant, emit the structured
    refresh-reuse audit event, DEL sess:{sid}, return 409
    -> verify: integration test triggers Keycloak invalid_grant (mock or
       contract-test fixture) and asserts the audit event payload and the
       409 response.

11. RP-initiated logout: signed CSRF required, DEL sess:{sid}, clear
    cookies, default 302 to Keycloak end_session_endpoint with
    id_token_hint; Accept: application/json returns {logoutUrl}
    -> verify: both branches tested.

12. Schema-contract fixture: write the canonical sess:{sid} payload to
    schema/sess-payload.example.json; add a test that constructs a session
    through the session writer and asserts every required field
    (access_token, access_token_expires_at, plus the full Auth-Service-
    internal fields) is present and well-typed
    -> verify: catches writer-side field removals or type drift.

13. Re-run focused gate -> verify: cd auth-service && ./mvnw test green.
```

Then, per task discipline:

1. Run the current focused tests.
2. Add the failing test for each item above before coding it.
3. Confirm the red failure.
4. Implement the smallest complete change.
5. Confirm green focused tests.
6. Run the relevant verification gate.
7. Do not change spec or diagram to make the code easier — the spec is
   the contract.

## Done Criteria

- `tx:{state}` is a distinct Valkey keyspace (`tx:*`), populated by a
  custom `OAuth2AuthorizationRequestRepository`, not by a framework HTTP
  session or by Spring Session.
- `tx:{state}` payload is `{verifier, nonce, saved_request, created_at}`
  with **no `tx_cookie_hash`** field (B3 reversal).
- No `oauth_tx` cookie is set anywhere in the Auth Service (B3 reversal).
- Login CSRF defense is `state` + PKCE S256 + ID-token `nonce`
  validation; no other login-CSRF cookie is added.
- No session cookie is set before successful callback.
- `sess:{sid}` is populated only after successful callback by the custom
  Redis-compatible session repository, with the full schema per SPEC-0001
  §"Session Schema" / RESHAPE-FRAME-B.md §7.2.
- Tokens and claims are stored only in `sess:{sid}`; no framework-managed
  HTTP session is the source of truth.
- `/auth/callback/idp` returns a **direct 302** (no landing page) with
  `__Host-sid` (`SameSite=Lax`, `HttpOnly`) and signed `XSRF-TOKEN`
  (JS-readable, HMAC-signed).
- `/internal/refresh` is an OAuth Resource Server endpoint that rejects
  any token whose audience does not include
  `oidc-reference-auth-internal` or whose `azp`/`client_id` is not
  `oidc-reference-api-gateway`.
- Refresh-with-audit: Keycloak `invalid_grant` on the refresh-token grant
  emits the structured refresh-reuse audit event, DELs `sess:{sid}`, and
  returns `409`.
- Per-session refresh lock prevents concurrent `/internal/refresh` calls
  for the same `sid` from issuing duplicate Keycloak refresh calls.
- Signed CSRF token issuance and validation per RESHAPE-FRAME-B.md §7.3:
  forged-signature and tampered-value rejection; constant-time HMAC
  compare; rotation grace window documented (implementation may be a
  follow-up).
- RP-initiated logout: signed CSRF required, session DELed, cookies
  cleared, 302 to Keycloak `end_session_endpoint` with `id_token_hint`
  (or `{logoutUrl}` JSON when `Accept: application/json`).
- All ID-token validation negatives from the retired BFF's
  `JwtOidcIdTokenValidatorTest` are ported and pass.
- `cd auth-service && ./mvnw test` green.
- This task packet passes `scripts/check-agent-task.sh`.

## Final Report

_Status_: ✅ Done — Phase B (`bb5f03d`) + Phase C follow-up (`00c6da8`).

### Assumptions

- Java code lives under the new `com.example.oidcreference.authservice`
  package; the old `bff` package retired with the directory.
- `/internal/*` is an OAuth Resource Server, not a "trusted endpoint."
  Audience = `oidc-reference-auth-internal`; `azp/client_id` =
  `oidc-reference-api-gateway`. Defensive re-assertion in the
  controller on top of the filter-chain check.
- Signed CSRF token shape `<value>.<hmac>` is computed at callback time
  by the Auth Service and stored verbatim in `sess:{sid}.xsrf_token`,
  so cookie ↔ header ↔ stored all use the same byte sequence.

### Files (under `auth-service/`)

Domain (port + reversals): `AuthServiceApplication`, `AuthProperties`,
`OAuthTransaction` (B3 — `txCookieHash` removed), `SessionRecord`,
`OidcProviderMetadata`, `JwtOidcIdTokenValidator`,
`AuthorizationCodeTokenExchangeClient`, `AuthorizationCodeTokenRefreshClient`,
`InvalidRefreshTokenException`, `IdTokenValidator` / `TokenExchangeClient` /
`TokenRefreshClient` interfaces, `StateStore` + `RedisStateStore`,
`JsonCodec`, `CryptoSupport`, `BrowserRequestClassifier`.

Controllers / new: `AuthController` (B2 — direct 302 + no landing
page; B3 — no `oauth_tx`), `SignedCsrfSupport` (HMAC-SHA256 + constant-
time compare), `InternalRefreshController` (per-sid `ReentrantLock`;
404/409/502 problem+json per §7.1), `SecurityConfig` (two filter
chains: order-1 `/internal/**` resource-server, order-2 `/auth/**`
permitAll). `application.yml` (env-driven config) + `Dockerfile`.

Tests (44 / 44 — all green):
- `JwtOidcIdTokenValidatorTest` (9): full negative coverage ported.
- `AuthControllerTest` (15): B2/B3 reversals; saved-request via
  `?next=`; cookie-name switch (`__Host-sid` ↔ `sid`); signed-CSRF
  cookie shape; logout signed-CSRF (missing / forged HMAC /
  tampered value / valid).
- `InternalRefreshControllerTest` (9): full §7.1 contract — 401 / 404 /
  200 idempotent / 200 rotated / 409 + audit / 502 + session intact /
  concurrency-collapses-to-one-refresh.
- `SignedCsrfSupportTest` (6): HMAC happy + tampered + forged + dot /
  divergence / null defenses.
- `SecurityConfigTest` (3 unit + 5 nested chain via `@Import`).

### Result

Auth Service is feature-complete against SPEC-0001 §"Auth Service
Endpoints" + §7.1. Compiles, tests pass, env-driven config works.

### Risks / follow-ups

- Cross-language HMAC contract between this service's
  `SignedCsrfSupport` and APISIX's `bff-session.lua` is documented in
  SPEC-0001 §7.3 but has no automated end-to-end parity test
  (would require either a running APISIX or a Lua-equivalent
  re-implementation in Java). The algorithm specification is
  byte-precise; producing a known-good fixture
  (`schema/csrf-fixture.json`) is a low-cost follow-up.
- `JwtDecoder` for `/internal/*` is `@ConditionalOnMissingBean` so
  tests can stub it; production startup requires `OIDC_ISSUER_URI`
  to be reachable for OIDC discovery.
