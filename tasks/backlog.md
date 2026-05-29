# Backlog

## Architecture Pivot — BFF Pattern, Split Implementation (Frame B)

The project moved from "SPA does PKCE in the browser" to the BFF session
pattern, and then (under Frame B, 2026-05-25) split the combined BFF into
an **Auth Service** (OAuth/OIDC client role; owns `/auth/*`; sole writer of
`tx:{state}` and `sess:{sid}`) and an **APISIX API Gateway** (routing +
bearer-injection role; owns `/api/**`; tolerant reader of `sess:{sid}`).
The browser holds no tokens; both services are confidential Keycloak
clients backed by a Redis-compatible server-side state store. Valkey is the
local reference implementation. See `../README.md` for the sequence
diagrams, `docs/specs/SPEC-0001-core-oidc-flows.md` for the build contract,
and `../RESHAPE-FRAME-B.md` for the reshape rationale.

## Foundation

- TASK-0001: Establish spec-first documentation foundation.
- TASK-0002: Split the project into four primary goals and subdirectories.
- TASK-0003: Make mandatory turn protocol checkable.
- TASK-0004: Frontend scaffold (cookie client, no OIDC library).
- TASK-0005: Resource Server scaffold and JWT validation.
- TASK-0006: Authorization server harness (realm import + smoke).
- TASK-0007: BFF spec-to-code alignment (SUPERSEDED 2026-05-25 by the
  Frame B reshape; see `RESHAPE-FRAME-B.md`).
- TASK-0008: Auth Service spec-to-code (Nimbus OIDC client; custom
  `tx:{state}` and `sess:{sid}` repositories; `/internal/refresh` as
  OAuth RS; signed CSRF; refresh-with-audit). Replaces the prior
  TASK-0008 (root Compose stack), which was subsumed by the reshape.
- TASK-0009: API Gateway spec-to-code (APISIX standalone + custom
  `bff-session` Lua plugin; tolerant session reader; bearer injection;
  refresh delegation; CC token cache).

## Implementation Order

This is the coding order. Do not reopen architecture choices while executing
these slices.

1. Authorization Server: finish the Keycloak realm and smoke checks from
   GOAL-0003. This produces real issuer, JWKS, BFF client, service client,
   scopes, roles, and access-token audience shape for every other service.
2. Resource Server: implement GOAL-0002 JWT validation and endpoint
   authorization against Keycloak token shape.
3. Auth Service: implement TASK-0008 against the Auth Service contract:
   custom `tx:{state}` (no `tx_cookie_hash`) and `sess:{sid}` repositories,
   direct-302 callback (no landing page), saved-request replay, refresh
   rotation with audit event, signed double-submit CSRF, `/auth/me`,
   `/auth/logout`, `/internal/refresh` as OAuth RS bound to
   `oidc-reference-auth-internal`.
4. API Gateway: implement TASK-0009 against the API Gateway contract:
   APISIX standalone `apisix.yaml`, custom `bff-session` Lua plugin
   (tolerant session reader, bearer injection, header stripping, signed
   CSRF validation, refresh delegation), CC token cache for the Gateway's
   own Keycloak client.
5. Frontend: implement GOAL-0001 as a cookie client only after `/auth/*`
   and `/api/**` are available from the Auth Service and the API Gateway.
6. Root Compose and E2E: wire the local stack (Traefik ingress, Auth
   Service, API Gateway, RS, Valkey, Keycloak) and run saved-request
   browser E2E plus Client Credentials service flow.

## Frontend (GOAL-0001)

- Remove `oidc-client-ts` and any in-browser OAuth code.
- Implement Sign in as navigation to `/auth/login`.
- Implement Vite proxy with two upstreams: `/auth/*` -> Auth Service
  (`:8081`) and `/api/**` -> APISIX API Gateway (`:9080`). Both upstreams
  honor `X-Forwarded-Host` / `-Proto` / `-Port`. (The full Compose stack
  uses Traefik on a single port; the Vite proxy is the dev-loop
  equivalent.)
- Render identity from `/auth/me`; render denials honestly.
- Playwright authenticated-session storage assertion.

## Auth Service (GOAL-0004)

- Spring Boot 4 scaffold (Java 25, virtual threads), Nimbus
  `oauth2-oidc-sdk` for the OIDC client role, Spring Security 7 only for
  the `/internal/*` OAuth Resource Server role, Redis-compatible client.
- Custom `OAuth2AuthorizationRequestRepository` writing `tx:{state}` to
  Valkey directly (no Spring Session). Payload is
  `{verifier, nonce, saved_request, created_at}` — no `tx_cookie_hash`.
- Custom Redis-compatible session repository writing `sess:{sid}` only
  after successful callback and ID-token validation.
- `/auth/login` accepts optional `?next=` (saved-request), validates
  same-origin, defaults to `/`.
- `/auth/callback/idp` returns a **direct 302** (no landing page); sets
  `__Host-sid` with `SameSite=Lax` and signed `XSRF-TOKEN`.
- `/auth/me`, `/auth/logout` controllers; RP-initiated logout via
  Keycloak `end_session_endpoint`.
- `/internal/refresh` as OAuth Resource Server with audience binding to
  `oidc-reference-auth-internal`; per-session refresh lock;
  refresh-with-audit (Keycloak `invalid_grant` -> structured refresh-
  reuse audit event + 409 + session DEL).
- Signed double-submit CSRF (HMAC over the cookie value, validated on
  receipt with constant-time compare).
- ID-token validation negatives ported from the retired BFF
  (`JwtOidcIdTokenValidatorTest`).

## API Gateway (GOAL-0005)

- APISIX standalone mode with declarative `apisix.yaml` declaring the
  `/api/**` allowlist (default: `/api/me`, `/api/user-data`,
  `/api/admin`). Off-allowlist paths return `404` without an upstream
  call.
- Custom Lua plugin `bff-session` attached to each `/api/**` route.
- Tolerant session reader: read `sess:{sid}` from Valkey via
  `resty.redis`; consume only `access_token` and
  `access_token_expires_at`.
- Browser-request classification: `Sec-Fetch-Mode` + `Sec-Fetch-Dest`
  primary, `Accept` fallback. XHR no-session -> `401`; navigation
  no-session -> `302 /auth/login?next=...`.
- Signed CSRF validation on POST/PUT/DELETE/PATCH (constant-time HMAC
  compare; naive double-submit explicitly rejected).
- Header shaping: strip inbound `Cookie` and hop-by-hop headers; inject
  `Authorization: Bearer <access_token>`; preserve query string.
- Refresh delegation to Auth Service `/internal/refresh` over Client
  Credentials. Handles 200/401/404/409/502 per RESHAPE-FRAME-B.md §7.1
  Gateway-side response table.
- Client-Credentials token cache: single in-process entry; proactive
  refresh; serialized refresh under contention; cache invalidation on
  401 with single retry.
- Circuit breaker on `/internal/refresh` distinguishing 5xx/transport
  failures (count as failure) from 4xx responses.
- Integration tests via `curl` against an ephemeral APISIX + Valkey +
  mock Auth Service stack.

## Resource Server (GOAL-0002)

- `JwtDecoder` with audience validator and `RS256` allowlist.
- `JwtAuthenticationConverter` mapping `realm_access.roles` to `ROLE_*`.
- `application/problem+json` 401/403 handlers.
- Security audit logging for denied access and validation failures.
- Positive and negative tests for every endpoint and every rejection.

## Authorization Server (GOAL-0003)

- Rename the prior `oidc-reference-bff` client to `oidc-reference-auth`
  (confidential, standard flow + PKCE S256 + refresh rotation).
- Add confidential `oidc-reference-api-gateway` client (Client
  Credentials only; service accounts enabled; browser flows disabled;
  default scope `auth.internal`).
- Add `api.audience` client scope with `oidc-audience-mapper`
  (`oidc-reference-api`).
- Add `auth.internal` client scope with `oidc-audience-mapper`
  (`oidc-reference-auth-internal`).
- Verify `realm_access.roles` mapper is present.
- Enable refresh-token rotation with reuse detection.
- `smoke.sh`: real `curl` token issuance check for both the service
  client and the API Gateway client; assert `aud` and `scope` claims for
  each.

## Cross-Goal Verification

- Browser E2E via Playwright with Keycloak login automation.
- Cross-service integration test (Auth Service + API Gateway + RS, with
  the `/internal/refresh` RPC under Client Credentials).
- Schema-contract test for `sess:{sid}` from both sides — Auth Service
  (writer) and API Gateway (tolerant reader) — against the shared
  `schema/sess-payload.example.json` fixture.
- Local cold-start verification (`scripts/verify-all.sh`).
- Secret scan.

## RFC 9700 Known Gaps

- Sender-constrained access tokens (DPoP or mTLS).
- Asymmetric client authentication (`private_key_jwt` or mTLS).
- Explicit `Referrer-Policy: no-referrer` and baseline CSP.
- Audit event on refresh-token reuse.
- URL-form audience if multiple Resource Servers are added.
- Optional JAR/PAR demonstration.
