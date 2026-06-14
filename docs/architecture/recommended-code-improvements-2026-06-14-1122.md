# Recommended Code Improvements - 2026-06-14 11:22

This review backlog consolidates the latest architecture, security, code, and test
review findings for `oidc-reference`.

Goal: keep the reference implementation close to OAuth/OIDC standards, keep the
BFF/session-cookie pattern intact, and make the code strong enough that a staff
engineer or security architect can adapt it to their own infrastructure without
rewriting the security model.

This list deliberately avoids local-infra debates. Production teams will replace
or harden the gateway, cache, IdP, deployment, TLS, secret management, and
observability stack. The items below focus on code and tests that should survive
that adaptation.

## Priority 1

### 1. Make the OP `sid` index a set, not a scalar

Current risk:

- `idp_sid:{opSid}` stores one local sid.
- If one OP session maps to more than one local session, a back-channel logout by
  `sid` can delete only the last indexed local session.
- `sub_sessions:{sub}` already uses set semantics, so the scalar OP sid index is
  inconsistent with the rest of the session model.

Recommended change:

- Store `idp_sid:{opSid}` as a set of local sids.
- Add atomic add, remove, and rotate semantics.
- Make `deleteByIdpSid` delete every local session in that set.
- Ensure sid rotation updates the set without resurrecting a session already
  removed by logout.

Tests:

- Two local sessions share one OP `sid`; back-channel logout by `sid` deletes
  both.
- Logout token containing both `sid` and `sub` deletes the OP-session members,
  not just one scalar pointer.
- Refresh sid rotation repoints the OP sid set.
- Logout racing with refresh fails closed and does not rebuild a deleted index.

### 2. Ignore bare `sid` on secure Auth Service requests

Current risk:

- Auth Service falls back from `__Host-sid` to bare `sid`.
- The gateway gates bare `sid` for `/api/**`, but Auth Service owns `/auth/me`
  and `/auth/logout`.
- In production, the security model should be `__Host-sid` only. Bare `sid` is
  an HTTP local-dev compatibility cookie.

Recommended change:

- On secure requests, accept only `__Host-sid`.
- On non-secure local HTTP requests, accept bare `sid`.
- Prefer `__Host-sid` if both are present.
- Clear both cookie names where doing so is safe and useful.

Tests:

- HTTPS or `X-Forwarded-Proto: https` plus only `sid` is rejected.
- HTTPS plus `__Host-sid` is accepted.
- HTTP local request plus `sid` is accepted.
- Both cookies present uses `__Host-sid`.
- Logout clears the correct cookie name and does not leave stale auth state.

### 3. Prevent session index TTL shrink

Current risk:

- `sub_sessions:{sub}` uses `SADD` plus unconditional `PEXPIRE`.
- A later short-lived session can shorten the whole subject index.
- A future sub-based back-channel logout can miss longer-lived sessions.

Recommended change:

- Change set TTL behavior to extend only, never shorten.
- Use `PEXPIRE ... GT` where supported, or compare `PTTL` and update only when
  the new TTL is longer.
- Keep Redis-compatible semantics in the state-store abstraction.

Tests:

- Add a long-lived subject session, then a short-lived subject session. The set
  TTL remains long.
- Add a short-lived session, then a long-lived session. The set TTL extends.
- Redis implementation and in-memory test implementation behave the same.

### 4. Map distributed refresh lock failures explicitly

Current risk:

- The distributed refresh lock can throw on lock acquisition timeout.
- That path can escape as a generic 500 instead of the documented transient
  session-resolution response.
- Lock property relationships are not fully validated.

Recommended change:

- Catch lock acquisition failures around `refreshLock.withLock`.
- Return a documented no-store transient problem response, likely 503.
- Emit a structured audit event.
- Validate lock configuration:
  - mode is `in-process` or `distributed`;
  - TTL is positive;
  - max wait is positive;
  - poll interval is positive and less than max wait;
  - TTL covers the expected IdP refresh call budget.

Tests:

- A lock that never acquires returns the documented status and no-store headers.
- The refresh action is not run when the lock is unavailable.
- Invalid lock properties fail binding or boot.
- Concurrent refresh tests still prove exactly one upstream refresh under the
  normal lock.

### 5. Strengthen the no-token-in-browser proof

Current risk:

- The E2E helper checks storage and `document.cookie`, but not every browser
  cookie visible through Playwright or every same-origin JSON response body.
- A regression could set an HttpOnly token cookie or return token fields in
  `/auth/me` while the current browser proof stays green.

Recommended change:

- Extend the E2E proof to inspect all browser cookies through
  `context.cookies()`.
- Reject cookie names and values that look like `access_token`, `refresh_token`,
  `id_token`, JWT, JWE, or long opaque bearer values.
- Capture relevant same-origin responses:
  - `/auth/me`;
  - `/api/me`;
  - `/api/user-data`;
  - `/auth/logout`;
  - gateway error responses.
- Assert no token fields or token-shaped values appear in those bodies.
- Keep the precise allowed exception: `id_token_hint` may appear only in the
  server-generated top-level redirect Location from `/auth/logout/continue` to
  the IdP.

Tests:

- Add a negative fixture or route-mocked response proving the token scanner would
  fail if `/auth/me` returned `access_token`.
- Add an assertion that no HttpOnly cookie name contains token-like names.

## Priority 2

### 6. Project `/auth/me` server-side

Current risk:

- The Auth Service returns the stored session claim map directly.
- The frontend sanitizes it, but the server should own the public contract.

Recommended change:

- Introduce a typed `UserProfileResponse`.
- Return only:
  - `sub`;
  - `preferred_username`;
  - `name`;
  - `email`;
  - `roles`;
  - `auth_time`;
  - `acr`.
- Do not return arbitrary IdP claims, token material, raw nested claim objects,
  or provider-specific implementation details.

Tests:

- `/auth/me` includes expected allowed fields.
- `/auth/me` drops unexpected fields from the stored session record.
- `/auth/me` never returns token-shaped fields.

### 7. Bind OAuth error callbacks to the browser transaction

Current risk:

- The success callback validates the `oauth_tx` browser-binding cookie.
- The IdP error callback consumes `tx:{state}` without validating that binding.
- Impact is mostly login denial of service if a high-entropy state leaks.

Recommended change:

- For `?error=...&state=...`, load the transaction, validate `oauth_tx`, then
  consume it.
- If choosing not to bind the error path, document the exact tradeoff.

Tests:

- Error callback with missing `oauth_tx` is rejected and audited.
- Error callback with mismatched `oauth_tx` is rejected and audited.
- Error callback with matching `oauth_tx` consumes the transaction and returns
  the intended graceful response.

### 8. Make token-bearing internal responses explicitly no-store

Current risk:

- `/internal/resolve` returns access-token JSON to the gateway.
- Spring Security may add cache headers, but the controller contract should be
  explicit.

Recommended change:

- Add `Cache-Control: no-store` to every `/internal/resolve` success and error
  response.
- Keep problem responses as `application/problem+json`.

Tests:

- Fresh-token resolve response has `Cache-Control: no-store`.
- Rotated-token resolve response has `Cache-Control: no-store`.
- Error responses have `Cache-Control: no-store`.

### 9. Fail fast on malformed CSRF signing keys

Current risk:

- Auth Service validates sentinel and short valid base64 keys, but invalid
  base64 can still be discovered at runtime.
- Gateway validation is weaker and can discover key issues only during requests.

Recommended change:

- Auth Service validates base64 decoding and decoded length at boot.
- Gateway render or schema validation checks base64 and 32-byte decoded length.
- Keep the local-dev sentinel allowed only in explicit local/test profiles.

Tests:

- Invalid base64 key fails Auth Service boot.
- Short decoded key fails outside local/test profiles.
- Gateway render rejects invalid or short key.
- Valid 32-byte base64 key passes.

### 10. Add safe configurable authorization request extras

Current risk:

- The authorization request builder emits only the fixed standard request
  parameters used by the local reference.
- Some IdPs or deployments need `audience` or RFC 8707 `resource`.
- Docs already mention the Auth0 `audience` gap.

Recommended change:

- Add a narrow config surface for extra authorization request parameters.
- Prefer explicit knobs for `resource` and `audience` over a fully arbitrary map.
- If a generic map is added, reject overrides of load-bearing parameters:
  - `client_id`;
  - `redirect_uri`;
  - `response_type`;
  - `scope`;
  - `state`;
  - `nonce`;
  - `code_challenge`;
  - `code_challenge_method`;
  - `prompt` and `acr_values` unless explicitly owned by the step-up path.

Tests:

- Configured `resource` appears on the authorize redirect.
- Configured `audience` appears on the authorize redirect.
- Dangerous override keys are rejected at boot or login start.
- Default local Keycloak flow remains byte-for-byte compatible where expected.

### 11. Clean test-only gateway echo exposure

Current risk:

- `/api/_test/echo` is useful for proving header and cookie shaping.
- The APISIX route exists in the normal template and relies on the Resource
  Server profile gate to return 404 in non-test runtime.

Recommended change:

- Render the echo route only for the test gateway config.
- Keep the Resource Server controller profile-gated as a second guard.
- Add a production-profile test proving `/api/_test/echo` is not routable.

Tests:

- Test config exposes `/api/_test/echo`.
- Default/prod config does not expose the route.
- Gateway header-shaping tests still use the test route.

### 12. Fix stale gateway cookie test

Current risk:

- The live gateway test expects plaintext `__Host-sid` to be rejected.
- The plugin accepts `__Host-sid` unconditionally.
- A contradictory security test reduces trust in the gate.

Recommended change:

- Decide the intended policy and align unit plus live tests.
- If `__Host-sid` is always accepted, rename the test to prove bare `sid` is
  rejected when `allow_insecure_sid=false`.
- If secure-only acceptance is desired, change plugin behavior and tests
  together.

Tests:

- `__Host-sid` accepted when present.
- Bare `sid` rejected when `allow_insecure_sid=false`.
- Bare `sid` accepted only when `allow_insecure_sid=true`.

## Priority 3

### 13. Split `AuthController` by security responsibility

Current risk:

- The controller is cohesive, but it carries many security responsibilities in
  one file.
- Auditing is harder than it needs to be.

Recommended change:

- Extract pure or narrowly scoped collaborators:
  - `ReturnToValidator`;
  - `SessionCookieService`;
  - `LoginTransactionService`;
  - `LogoutContinuationService`;
  - `UserProfileMapper`.
- Keep route behavior unchanged.
- Keep comments focused on non-obvious security invariants.

Tests:

- Move existing unit tests to the extracted collaborators where possible.
- Keep controller tests for HTTP contract and cookie/header behavior.

### 14. Use typed response records for contracts

Current risk:

- Some endpoints use raw `Map<String, Object>`.
- Raw maps make accidental fields and contract drift easier.

Recommended change:

- Use records for:
  - `/auth/me`;
  - `/auth/logout`;
  - `/internal/resolve`;
  - Resource Server API responses where practical.
- Keep RFC 7807 `ProblemDetail` for error shapes.

Tests:

- JSON contract tests assert snake_case where required.
- Unexpected fields are not serialized.

### 15. Centralize claim extraction

Current risk:

- Claim handling is good but spread across layers.
- Audience string-or-array, `azp` vs `client_id`, role claim paths, `auth_time`,
  and `acr` should not drift independently.

Recommended change:

- Add a small claim utility or package-local helper set for:
  - audience normalization;
  - caller client id extraction;
  - role claim path extraction;
  - `auth_time` parsing;
  - `acr` extraction.

Tests:

- String and array audience forms.
- Missing and wrong audience.
- `azp` present, `client_id` present, neither present.
- Top-level and nested role claim paths.
- URI-shaped role claim names.

### 16. Improve provider portability tests

Current risk:

- The local Keycloak path is strong.
- Provider portability is partly proven by alternate realm and docs, but more
  negative tests would make the config-driven claim stronger.

Recommended change:

- Add or keep tests for:
  - ID-token audience is BFF client id;
  - access-token audience is Resource Server audience;
  - audience claim as string and array;
  - missing `refresh_expires_in`;
  - missing `acr`;
  - stale `auth_time`;
  - wrong `acr`;
  - roles under top-level `groups`;
  - roles under URI-shaped claim name.

Tests:

- Unit tests for claim mapping and validation.
- Hermetic alt-realm E2E for different audience and top-level groups.
- Keep live Okta or external-provider runbook non-gating.

### 17. Tighten frontend storage lint guard

Current risk:

- The lint rule catches direct storage writes, but misses variants such as
  `window.localStorage.setItem`, property assignment, bracket access, or aliases.

Recommended change:

- Ban all frontend storage access in production source unless an explicit
  allowlisted test/helper file needs read-only inspection.
- If read-only access is kept for debug code, make it narrow and tested.

Tests:

- Lint fails on:
  - `window.localStorage.setItem`;
  - `localStorage["token"] = value`;
  - `localStorage.token = value`;
  - `const s = localStorage; s.setItem(...)`;
  - `indexedDB.open(...)`.

### 18. Fix frontend link semantics

Current risk:

- Sign-in is an anchor navigation but exposed as `role="button"`.
- That weakens accessibility semantics and causes tests to assert the wrong
  role.

Recommended change:

- Use a normal link with accessible name `Sign in`.
- Update tests to query by role `link`.

Tests:

- Anonymous state shows a sign-in link.
- Link `href` is `/auth/login?return_to=...`.

### 19. Surface `/auth/me` transport errors distinctly

Current risk:

- Frontend collapses `/auth/me` server/transport failures into anonymous state.
- Manual verification can mistake an outage for a normal signed-out page.

Recommended change:

- Keep `401` as anonymous.
- Show an error state for non-401 failures or malformed `/auth/me` shape.

Tests:

- `401` shows anonymous sign-in state.
- `500` shows an auth-service unavailable message.
- Malformed JSON shape shows an auth-state error.

### 20. Fix frontend README E2E command

Current risk:

- `npm run test:e2e` runs the anonymous Playwright spec.
- The README says `E2E_FULL_STACK=1 npm run test:e2e` includes authenticated
  coverage.

Recommended change:

- Point authenticated verification to `scripts/e2e-auth.sh`.
- Keep frontend-only E2E description scoped to anonymous behavior.

## Preserve

These parts look strong and should be preserved while making the improvements:

- BFF/session-cookie pattern; no SPA-held access or refresh tokens.
- Mandatory `return_to` login contract.
- Authorization Code with PKCE S256.
- OIDC nonce validation.
- Browser-binding `oauth_tx` cookie on the success callback.
- Server-side token storage.
- API Gateway as browser security boundary.
- Phantom-token style `/internal/resolve` rather than gateway direct store reads.
- Resource Server stateless JWT validation.
- Explicit issuer, audience, expiry, and RS256 checks.
- Configurable role claim path.
- Refresh-token rotation enforcement.
- Sid rotation on refresh.
- Back-channel logout support.
- Signed double-submit CSRF bound to sid.
- Step-up challenge behavior for sensitive operations.
- Alt-realm portability proof.

## Done Criteria

The code should be considered ready for the next "world-class reference" review
when:

1. The Priority 1 items are implemented with unit and live-gate coverage.
2. No browser-visible surface exposes access tokens, refresh tokens, or ID tokens
   except the explicit front-channel `id_token_hint` logout redirect exception.
3. Back-channel logout revokes every matching local session for `sid` and `sub`.
4. Secure requests accept only the production session cookie shape.
5. Session indexes cannot expire before the sessions they are needed to revoke.
6. Distributed refresh-lock failure is a documented, tested transient path.
7. `/auth/me` and `/internal/resolve` are typed, minimal, and cache-safe.
8. Test-only routes cannot be accidentally shipped in the default runtime.
