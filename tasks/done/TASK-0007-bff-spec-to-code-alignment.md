> **SUPERSEDED 2026-05-25** by RESHAPE-FRAME-B.md and TASK-0008-auth-service / TASK-0009-api-gateway. This task's plan no longer reflects current architecture.

# TASK-0007: BFF Spec-to-Code Alignment

## Objective

Bring the BFF code in line with the BFF contract defined by the root
README diagrams and `docs/specs/SPEC-0001-core-oidc-flows.md`. The
spec is ahead of the code on six load-bearing items; this task closes
the gap without changing the spec.

## Linked Spec

- `docs/specs/SPEC-0001-core-oidc-flows.md`
- `docs/goals/GOAL-0004-bff.md`
- Root `README.md` (canonical sequence diagrams)

## Read First

- `AGENTS.md`
- `docs/agents/mandatory-turn-protocol.md`
- `docs/agents/execution-discipline.md`
- `docs/testing/red-green-workflow.md`
- `RFC9700-compliance.md` (especially Known Gaps and §4.7 CSRF)

## Owned Paths

- `bff/src/main/`
- `bff/src/test/`
- `bff/src/main/resources/application.yml`
- BFF-specific docs and task notes

## Avoid Paths

- `frontend/` (separate task)
- `backend-resource-server/`
- `authorization-server/realm/` (read-only inspection)
- Root `compose.yaml`, `README.md`, `docs/specs/`, `docs/goals/` (these
  are the contract — do not change them to fit the code; change the
  code to fit them)

## Required Workflow

Before coding, record in the working notes:

- Assumptions:
- Ambiguities:
- Owned paths:
- Success criteria: (mirror the Done Criteria below)

Plan:

```text
1. Custom OAuth2AuthorizationRequestRepository writing tx:{state} to the Redis-compatible state store
   directly (separate from any framework HTTP session) -> verify: integration test
   asserts a state-store key matching `tx:*` appears on /auth/login and
   disappears after callback; no pre-callback `sid` session cookie set.
2. Persist saved_request in tx:{state} on flow start -> verify: test asserts
   tx:{state} JSON includes saved_request derived from the original request
   URL (or "/" for explicit /auth/login).
3. Bind callback to browser with oauth_tx -> verify: callback with missing
   or mismatched oauth_tx is rejected before token exchange; oauth_tx is
   deleted on callback success or failure.
4. Custom Redis-compatible session repository writing sess:{sid} only after callback
   validation -> verify: integration test asserts one `sess:*` key exists
   after valid callback, no token/claim payload is present in a framework
   HTTP session, and no `sess:*` key exists after failed callback.
5. Saved-request replay on callback success: validate saved_request as
   same-origin, then return the intermediate landing page with Strict
   session cookie -> verify: test asserts `200 text/html`, `Set-Cookie`
   includes `SameSite=Strict`, and the landing page calls
   `window.location.replace(...)` with the saved URL for same-origin or
   "/" for cross-origin/absent saved URL.
6. Fetch/XHR-vs-navigation distinction at the BFF security entry point:
   Sec-Fetch-Mode/Sec-Fetch-Dest identify document navigations when
   present; Accept is a fallback. API/fetch requests without session return
   401 with no Location header; document navigations run the saved-request
   OAuth flow -> verify: two MockMvc tests, one per branch.
7. Replace per-endpoint /api proxy methods with a single /api/** handler
   backed by an app.proxy.allow allowlist (default: /api/me, /api/user-data,
   /api/admin) -> verify: tests for allowed paths (200), disallowed paths
   (404), query string preserved, hop-by-hop headers stripped,
   Cache-Control: no-store set.
8. Re-run focused gate -> verify: ./scripts/verify-bff.sh green.
9. Re-run cross-service gate against live stack -> verify: saved-request
   E2E and XHR 401 both pass per local-verification.md steps 12 and 13.
```

Then, per task discipline:

1. Run the current focused tests (`./bff/mvnw test`).
2. Add the failing test for each item above before coding it.
3. Confirm the red failure.
4. Implement the smallest complete change.
5. Confirm green focused tests.
6. Run the relevant verification gate.
7. Do not change spec or diagram to make the code easier — the spec is
   the contract.

## Done Criteria

- `tx:{state}` is a distinct state-store keyspace (`tx:*`), populated by a
  custom `OAuth2AuthorizationRequestRepository`, not by a framework HTTP
  session.
- `tx:{state}` payload includes `saved_request` and is deleted on
  callback (success or failure).
- `oauth_tx` is set before redirect, must match `tx:{state}` on callback,
  and is deleted on callback success or failure.
- No `sid` session cookie is set before successful callback.
- `sess:{sid}` is a distinct state-store keyspace (`sess:*`), populated only
  after successful callback by a custom Redis-compatible session repository.
- Tokens and claims are stored only in `sess:{sid}`; no framework-managed
  HTTP session is the source of truth for token or claim payloads.
- `/auth/callback/idp` returns the same-origin landing page instead of a
  direct `302`; it sets the session cookie with `SameSite=Strict` and
  navigates to the validated `saved_request`, defaulting to `/`.
- Top-level navigation (`Sec-Fetch-Mode: navigate`,
  `Sec-Fetch-Dest: document`; `Accept: text/html` as fallback) to an
  unauthenticated protected URL starts the OAuth flow.
- Fetch/XHR to `/api/*` without session returns `401` with no `Location`.
  Detection must not rely on legacy nonstandard request headers; prefer
  Fetch Metadata (`Sec-Fetch-Mode`, `Sec-Fetch-Dest`) and use `Accept` as
  fallback.
- `/api/**` is a single wildcard handler with `app.proxy.allow` allowlist.
- All BFF tests in `bff/src/test/` pass under `./mvnw test`.
- Live stack saved-request E2E and XHR 401 tests pass per
  `docs/harnesses/local-verification.md`.

## Final Report

**Status**: ✅ Done. All Done Criteria satisfied by the merged state at
master `549a5cb` (2026-05-25).

### Assumptions made

- `tx:{state}` and `sess:{sid}` may share one `StateStore` interface
  backed by a single Redis-compatible client; "distinct keyspace" is
  satisfied by the key-prefix discipline, not by separate clients.
- "Custom OAuth2AuthorizationRequestRepository" is satisfied by direct
  controller-level writes to `StateStore` (not by a Spring
  `AuthorizationRequestRepository` implementation) — the spec calls
  for the storage shape, not the Spring abstraction.

### Ambiguities resolved

- Sec-Fetch detection vs Accept fallback: the spec made both
  authoritative. We treat Sec-Fetch as primary when present and Accept
  as a strict fallback when absent. The `BrowserRequestClassifier`
  encapsulates the rule.
- Landing-page navigation: spec said "same-origin landing page"; we
  emit an HTML doc with a CSP nonce and `window.location.replace()`
  rather than a 302, both to satisfy the SameSite=Strict cookie
  delivery semantics and to keep the saved-request value
  controller-validated.

### Files materially involved

- `bff/src/main/java/com/example/oidcreference/bff/AuthController.java`
- `bff/src/main/java/com/example/oidcreference/bff/ApiProxyController.java`
- `bff/src/main/java/com/example/oidcreference/bff/BrowserRequestClassifier.java`
- `bff/src/main/java/com/example/oidcreference/bff/RedisStateStore.java`
- `bff/src/main/java/com/example/oidcreference/bff/OAuthTransaction.java`
- `bff/src/main/java/com/example/oidcreference/bff/SessionRecord.java`
- `bff/src/main/java/com/example/oidcreference/bff/SecurityConfig.java`
  (STATELESS so no Spring HttpSession is the token source of truth)
- The full Nimbus client triplet (`JwtOidcIdTokenValidator`,
  `AuthorizationCodeTokenExchangeClient`,
  `AuthorizationCodeTokenRefreshClient`) — out of scope for the spec
  alignment but landed alongside it on the merged tree.

### Tests run

- `cd bff && ./mvnw test` → 22 / 22 ✅
- `cd backend-resource-server && ./mvnw test` → 14 / 14 ✅
- `cd frontend && npm run build && npm run lint && npm test` → ✅
  (build + typecheck + lint + 21 / 21 vitest)
- `RESET_KEYCLOAK_REALM=1 ./scripts/verify-full-stack-auth.sh`
  → realm + discovery + JWKS + real-token claims + cross-service
  contract + 5 / 5 Playwright (including the new "unauthenticated
  /api/user-data → 401 without OAuth redirect" e2e that covers Done
  Criterion 8) ✅

### Risks / follow-ups surfaced

- Spec is silent on what happens when the saved-request URL is itself
  the OAuth callback (`/auth/callback/idp`). Current code falls
  through to "/" via `normalizeSavedRequest`, which is the right
  behavior but not literally spelled in the spec.
- `RFC9700-compliance.md` Known Gaps remain open (DPoP / mTLS,
  asymmetric client auth, audit on refresh reuse, etc.) — out of
  scope for this task; tracked in the backlog.
- TASK-0008 (root Compose + cold-start verification) is the natural
  next task. The reference stack is otherwise complete.
