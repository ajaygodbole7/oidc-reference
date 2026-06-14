# Recommended Code Improvements - 2026-06-14 11:22

This is the improvement backlog for making `oidc-reference` stronger as a
copyable OAuth/OIDC reference implementation.

The target is practical: code a staff engineer or security architect can take
seriously, then adapt to their own gateway, cache, IdP, deployment, TLS, secrets,
and observability stack. This file focuses on code and tests that should survive
that adaptation. It deliberately avoids local-infra hardening debates.

## Rules For This Backlog

- Fix concrete correctness, security, proof, or latency issues.
- Do not add abstraction for its own sake.
- Do not start a broad controller-splitting or service-layer cleanup task.
- Keep the main flows visible in code.
- Prefer package-private helpers and records over public interfaces.
- Add an interface only when there are multiple implementations or the test seam
  is otherwise painful.
- If a proposed change cannot name the bug, test gap, or measured latency cost it
  fixes, do not do it.

The hot path must stay easy to trace:

```text
APISIX -> Auth Service /internal/resolve -> state store -> Resource Server
```

JVM class count is not the latency concern. Network calls, state-store round
trips, IdP calls, JSON work, connection setup, and lock contention are the
latency concerns.

## Phase 1 - Correctness And Security Fixes

These are real behavior fixes. Do these before organization cleanup.

### 1. Make the OP `sid` index a set

Problem:

- `idp_sid:{opSid}` stores one local sid.
- A back-channel logout by OP `sid` can delete only that one local session.
- `sub_sessions:{sub}` already uses set semantics, so the scalar OP-sid index is
  inconsistent.

Change:

- Store `idp_sid:{opSid}` as a set of local sids.
- `deleteByIdpSid` deletes every local session in that set.
- Sid rotation updates the set without resurrecting a session removed by logout.

Tests:

- Two local sessions share one OP `sid`; logout by `sid` deletes both.
- Logout token containing both `sid` and `sub` deletes the OP-sid set members.
- Refresh sid rotation repoints the OP-sid set.
- Logout racing with refresh fails closed.

### 2. Ignore bare `sid` on secure Auth Service requests

Problem:

- Auth Service falls back from `__Host-sid` to bare `sid`.
- Bare `sid` is local HTTP compatibility.
- Production secure requests should use only `__Host-sid`.

Change:

- Secure request: accept only `__Host-sid`.
- Non-secure local HTTP request: accept bare `sid`.
- If both are present, prefer `__Host-sid`.
- Clear both names where cleanup needs to be robust.

Tests:

- HTTPS or `X-Forwarded-Proto: https` with only `sid` is rejected.
- HTTPS with `__Host-sid` is accepted.
- HTTP local with `sid` is accepted.
- Both cookies present uses `__Host-sid`.

### 3. Prevent session index TTL shrink

Problem:

- `sub_sessions:{sub}` uses `SADD` plus unconditional `PEXPIRE`.
- A later short-lived session can shorten the subject index.
- Later sub-based logout can miss longer-lived sessions.

Change:

- Set-index TTL updates must extend only, never shorten.
- Use Redis-compatible behavior: `PEXPIRE ... GT` where available, or `PTTL`
  comparison before updating.

Tests:

- Long-lived then short-lived subject session keeps the longer TTL.
- Short-lived then long-lived subject session extends the TTL.
- Redis and in-memory stores behave the same.

### 4. Map distributed refresh-lock failure explicitly

Problem:

- Distributed lock acquisition can time out.
- That can escape as a generic 500.
- The lock configuration does not fully validate timing relationships.

Change:

- Catch lock acquisition failure around refresh.
- Return a documented transient no-store response, likely 503.
- Emit a structured audit event.
- Validate lock mode, TTL, max wait, and poll interval.

Tests:

- Lock that never acquires returns the documented status and headers.
- Refresh action is not run when the lock is unavailable.
- Invalid lock configuration fails at binding or boot.
- Normal concurrent refresh still collapses to one upstream refresh.

### 5. Bind OAuth error callbacks to the browser transaction

Problem:

- Success callbacks validate `oauth_tx`.
- IdP error callbacks consume `tx:{state}` without validating `oauth_tx`.
- Impact is mostly pending-login cancellation if state leaks.

Change:

- For `?error=...&state=...`, load the transaction, validate `oauth_tx`, then
  consume it.
- If this remains intentionally unbound, document the exact tradeoff.

Tests:

- Error callback with missing `oauth_tx` is rejected and audited.
- Error callback with mismatched `oauth_tx` is rejected and audited.
- Error callback with matching `oauth_tx` consumes the transaction and returns
  the graceful error response.

## Phase 2 - Proof And Contract Tightening

These make the reference harder to accidentally weaken.

### 6. Strengthen the no-token-in-browser proof

Problem:

- The E2E helper checks storage and `document.cookie`.
- It does not inspect every browser cookie through Playwright.
- It does not scan same-origin JSON response bodies broadly.

Change:

- Inspect `context.cookies()` for token-like names and values.
- Capture and scan `/auth/me`, `/api/me`, `/api/user-data`, `/auth/logout`, and
  gateway error responses.
- Reject `access_token`, `refresh_token`, `id_token`, JWT-looking strings,
  JWE-looking strings, and long opaque bearer-looking values.
- Keep the only allowed ID-token appearance: `id_token_hint` in the
  server-generated top-level redirect from `/auth/logout/continue` to the IdP.

Tests:

- A negative fixture proves the scanner fails if `/auth/me` returns
  `access_token`.
- HttpOnly cookies are also checked for token-like names.

### 7. Project `/auth/me` server-side

Problem:

- Auth Service returns the stored session claim map.
- The frontend sanitizes it, but the server should own the public contract.

Change:

- Return a typed response with only:
  - `sub`;
  - `preferred_username`;
  - `name`;
  - `email`;
  - `roles`;
  - `auth_time`;
  - `acr`.
- Do not return arbitrary IdP claims, token material, nested provider objects, or
  implementation details.

Tests:

- Allowed fields are returned.
- Unexpected fields in the session record are dropped.
- Token-shaped fields are never returned.

### 8. Make token-bearing internal responses explicitly no-store

Problem:

- `/internal/resolve` returns access-token JSON to the gateway.
- Spring Security may add cache headers, but the endpoint contract should be
  explicit.

Change:

- Add `Cache-Control: no-store` to `/internal/resolve` success and error
  responses.
- Keep problem responses as `application/problem+json`.

Tests:

- Fresh-token response has `Cache-Control: no-store`.
- Rotated-token response has `Cache-Control: no-store`.
- Error responses have `Cache-Control: no-store`.

### 9. Fail fast on malformed CSRF signing keys

Problem:

- Auth Service detects sentinel and short valid base64 keys, but invalid base64
  can still reach runtime.
- Gateway-side validation is weaker.

Change:

- Auth Service validates base64 decoding and decoded length at boot.
- Gateway render/schema validation checks base64 and 32-byte decoded length.
- Local-dev sentinel remains allowed only in explicit local/test profiles.

Tests:

- Invalid base64 key fails Auth Service boot.
- Short decoded key fails outside local/test profiles.
- Gateway render rejects invalid or short keys.
- Valid 32-byte base64 key passes.

### 10. Clean test-only gateway echo exposure

Problem:

- `/api/_test/echo` is useful for gateway proof.
- The route exists in the normal APISIX template and relies on the Resource
  Server test profile for safety.

Change:

- Render the echo route only in test gateway config.
- Keep the Resource Server profile gate as a second guard.

Tests:

- Test config exposes `/api/_test/echo`.
- Default/prod config does not expose it.
- Gateway header-shaping tests continue to use the test route.

### 11. Fix stale gateway cookie test

Problem:

- The live gateway test expects plaintext `__Host-sid` rejection.
- The plugin accepts `__Host-sid` unconditionally.

Change:

- Align the test with the intended policy.
- If `__Host-sid` is always accepted, make the live test prove bare `sid` is
  rejected when `allow_insecure_sid=false`.

Tests:

- `__Host-sid` accepted when present.
- Bare `sid` rejected when `allow_insecure_sid=false`.
- Bare `sid` accepted only when `allow_insecure_sid=true`.

### 12. Fix frontend proof and docs nits

Problem:

- Storage lint misses variants such as `window.localStorage.setItem`,
  assignment, bracket access, and aliases.
- Sign-in is an anchor but exposed as `role="button"`.
- Frontend README implies authenticated coverage runs through `npm run test:e2e`,
  but the full proof is driven by the repo E2E script.

Change:

- Tighten lint rules for storage access in production source.
- Use normal link semantics for sign-in.
- Point authenticated verification docs to the actual full-stack script.

Tests:

- Lint fails on common storage-write variants.
- Sign-in is queried as a link.
- README command matches the harness.

## Phase 3 - Hot-Path Performance

Do this after the correctness fixes. This phase is about reducing I/O, not
adding layers.

### 13. Keep `/internal/resolve` cheap

Problem:

- Every `/api/**` request calls Auth Service.
- That boundary is correct, but the common path must be cheap.

Target common path:

```text
Auth Service receives sid
state store reads sess:{sid}
state store touches idle TTL only when needed
Auth Service returns current access token
```

Non-goals:

- No IdP call on the fresh-token path.
- No broad lock on the fresh-token path.
- No gateway token cache for this milestone.
- No refresh jitter unless load testing shows synchronized refresh herds.

Change:

- Combine session read and idle touch into one state-store operation where
  practical.
- Avoid rewriting TTL on every request when the TTL is already comfortably above
  the touch threshold.
- Keep refresh only inside the configured refresh window.

Tests:

- Fresh session resolve performs no refresh.
- Fresh session resolve uses the combined read/touch operation where available.
- TTL is not rewritten on every call above the touch threshold.
- Near-expiry access token still enters refresh.
- Logout or session delete is visible on the next request.

## Phase 4 - Minimal Organization Cleanup

This is not a separate refactor project. Apply these only while fixing the phases
above.

### 14. Keep controller changes surgical

Guidance:

- Do not split controllers just to reduce line count.
- Extract only pure logic that is easier to test outside Spring.
- Good candidates:
  - return-to validation;
  - user-profile projection;
  - cookie name/attribute selection.
- Keep `AuthController` readable as the HTTP flow owner.
- Keep `/internal/resolve` visible as one flow: read session, absolute-expiry
  check, fresh-token return, refresh-under-lock, sid rotation.
- Do not introduce public interfaces for one implementation.

Tests:

- Move only directly relevant tests to extracted pure helpers.
- Keep controller tests for HTTP contract, cookies, headers, and wire shape.

### 15. Use typed records for response contracts

Problem:

- Raw `Map<String, Object>` responses make accidental fields and contract drift
  easier.

Change:

- Use records for `/auth/me`, `/auth/logout`, `/internal/resolve`, and Resource
  Server responses where practical.
- Keep RFC 7807 `ProblemDetail` for errors.

Tests:

- JSON contract tests assert snake_case where required.
- Unexpected fields are not serialized.

### 16. Centralize repeated claim handling only if drift appears

Problem:

- Audience normalization, `azp` / `client_id`, role paths, `auth_time`, and `acr`
  appear in multiple places.

Change:

- If a fix touches repeated claim logic, move the repeated pure parsing into a
  package-private helper.
- Do not create a claim framework.

Tests:

- Audience as string and array.
- Missing and wrong audience.
- `azp`, `client_id`, and neither.
- Top-level, nested, and URI-shaped role claims.

## Phase 5 - Provider Portability Proof

This is not a new architecture. It is evidence that the current config surface is
real.

### 17. Add targeted portability tests

Change:

- Keep the hermetic alternate-realm proof for:
  - different access-token audience;
  - roles under top-level `groups`.
- Keep live Okta or other external-provider runs as documented, non-gating
  evidence.
- Add unit tests for provider-shaped tokens:
  - missing `refresh_expires_in`;
  - missing `acr`;
  - stale `auth_time`;
  - wrong `acr`;
  - audience as string and array;
  - URI-shaped role claim name.

## Preserve

Keep these design choices intact while making the improvements:

- BFF/session-cookie pattern.
- No SPA-held access or refresh tokens.
- Mandatory `return_to`.
- Authorization Code with PKCE S256.
- OIDC nonce validation.
- Browser-binding `oauth_tx` cookie on callback.
- Server-side token storage.
- API Gateway as browser boundary.
- Gateway-to-Auth Service `/internal/resolve` on `/api/**`.
- No Resource Server calls to Auth Service.
- Resource Server stateless JWT validation.
- Explicit issuer, audience, expiry, and RS256 checks.
- Configurable role claim path.
- Refresh-token rotation enforcement.
- Sid rotation on refresh.
- Back-channel logout support.
- Signed double-submit CSRF bound to sid.
- Step-up challenge behavior for sensitive operations.

## Done Criteria

The code is ready for the next reference-quality review when:

1. OP-sid logout revokes every matching local session.
2. Secure requests accept only the production session cookie shape.
3. Session indexes cannot expire before the sessions they are needed to revoke.
4. Distributed refresh-lock failure is documented, tested, audited, and transient.
5. Browser-visible surfaces prove no access token, refresh token, or ID token
   exposure, except the explicit `id_token_hint` logout redirect exception.
6. `/auth/me` is a minimal typed projection.
7. `/internal/resolve` is no-refresh on the fresh-token path, low round-trip,
   no-store, and covered by operation-count or equivalent tests.
8. Test-only routes cannot ship in default runtime.
9. Refactors remain small, local, and tied to the fixes above.
