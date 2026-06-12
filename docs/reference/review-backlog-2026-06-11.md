# Review Backlog — Staff-Engineer / Security Evaluation

**Generated:** 2026-06-11
**Source:** Multi-dimension review (design · security · testing · production-readiness · doc-honesty), originally cross-checked against the code at commit `9dda6ad`.
**Status of this document:** open backlog. Items are independent and can be taken in any order.

**Ported to `master` and reconciled against the phantom-token refactor (`b93454e`)
on 2026-06-11.** That refactor moved session resolution — lookup, idle-TTL slide,
and the refresh-token grant — out of the API Gateway and behind the Auth Service's
`POST /internal/resolve` (replacing the old direct-Valkey read + `/internal/refresh`).
Items it already resolved are marked **[done]**; items whose file/endpoint targets
changed have been retargeted in place.

This file replaces the previous `review-decisions-pending.md`, which was deleted
because three of its entries asserted things that are no longer true:
- its CSRF "grace-window" item claimed SPEC-0001 §7.3 *promises* a dual-key window — the spec says the opposite ("not shipped reference behavior");
- its circuit-breaker item claimed the spec *mandates* a breaker — the spec marks it production hardening;
- its `realm_access.roles` item claimed the path is hardcoded — it is config-driven (`OIDC_ROLES_CLAIM_PATH` → `AuthProperties.rolesClaimPath`).
The still-valid items from that file are carried forward below and marked `[carried]`.

**Already actioned (not in this backlog):**
- Back-Channel Logout contradiction reconciled across README + SECURITY.md (`S-6`, audit events) and documented in SPEC-0001 (endpoint + all five logout keyspaces).
- Version drift fixed: README React 18→19, APISIX 3.11→3.16; SPEC-0001 Valkey 8→9.

**Scope key:**
- `REF` — appropriate for this *reference* to demonstrate or fix.
- `PROD` — a production-hardening concern; the action is to *document it honestly*, not build it (consistent with the repo's "what's deliberately not here" philosophy). CI was explicitly ruled out as a PROD concern and is intentionally absent here.

---

## A. Design / structural

### A1 — Extract a `RefreshLock` interface so the distributed lock is a swap, not a rewrite — **[done]**
**Resolved.** The reference-counted per-sid `ReentrantLock` map is now behind a `RefreshLock` interface with `<T> T withLock(String key, Supplier<T> action)`; the default `InProcessRefreshLock` (`@Component`) holds the map and the acquire/release reference-counting, mirroring the `StateStore`/`RedisStateStore` split. `InternalResolveController` depends only on the interface — the locked body moved to a `refreshUnderLock(...)` method invoked via `refreshLock.withLock(sid, …)`. The distributed swap (Valkey `SET refresh_lock:{sid} … NX PX` + compare-and-delete release + loser-re-reads-`sess:{sid}`) is documented in the `RefreshLock` javadoc rather than shipped as a dead stub. New `InProcessRefreshLockTest` pins mutual exclusion, per-key independence, refcount cleanup, and release-on-throw; verified red→green (skipping the lock fails the mutual-exclusion test). Controller regression (incl. `concurrentResolveCallsForSameSidSerializeOnLock`) and the live refresh-delegation e2e stay green.
**Where.** `auth-service/.../RefreshLock.java`, `InProcessRefreshLock.java`, `InternalResolveController.java`.

### A2 — De-duplicate the `bff-session` plugin config across the four APISIX routes — **[done]**
**Resolved.** The secret-bearing `bff-session` config is now declared once as an APISIX standalone `plugin_configs` entry (`id: bff-session-api`); `api-me`, `api-user-data`, `api-admin`, and `api-test-echo` each reference it with `plugin_config_id` (a one-line reference, not a copy of the block + its secrets). `render-apisix-config.sh` needed no change — the keys appear once and its empty-value/REPLACE_ME guards still fire. Behavior-preserved: full e2e green (gateway suite 60/0 exercises all four routes through the shared config — bearer injection, CSRF, echo, refresh; conformance 9/0).
**Where.** `api-gateway/apisix.yaml.template`.

### A3 — Add a cross-language contract test for the idle-TTL sliding math — **[done]** (obsolete after phantom-token)
**Resolved by `b93454e`.** The duplication this item targeted no longer exists. Phantom-token deleted the Lua `slide_session_ttl` from the gateway; the idle-TTL slide now lives in exactly one place — `SessionRecord.nextTtl`, applied by the Auth Service inside `/internal/resolve`. There is no second-language implementation to drift against, so no cross-language contract test is needed. `SessionRecord.nextTtl`'s own unit tests (the `remaining < idle` cap and the zero/expired case) remain the coverage.

### A4 — Make `RedisStateStore.addToSet` atomic (SADD + EXPIRE) — **[done]**
**Resolved.** `addToSet` now runs a single server-side Lua script (`SADD` + `PEXPIRE`, TTL in ms) via a static `DefaultRedisScript<Long>` + `redis.execute(...)`, one round-trip — no window for a TTL-less `sub_sessions:` set. `StateStore.addToSet` signature unchanged; `SessionIndexesTest` green; exercised live by the e2e refresh/session-creation path.
**Where.** `auth-service/.../RedisStateStore.java`.

### A5 — Consider splitting `AuthController` — **[done]** (decided: keep)
**Decision: keep `AuthController` cohesive; do not split.** The two candidate extractions were evaluated against the backlog's own bar ("only if it improves readability without inventing indirection") and both fail it for a *reference*:
- **`CookieFactory`** — the five cookie factories (`sidCookie`, `oauthTxCookie`, `clearOauthTxCookie`, `xsrfCookie`, `clearCookie`) are already a cohesively grouped ~90-line block at the end of the file, not scattered. Moving them to a separate class buys little and costs locality-of-behavior: a reader following the callback flow would have to jump files to see exactly how `__Host-sid`/`XSRF-TOKEN` are shaped. For a teaching reference, cookie minting next to the flow that mints it aids comprehension.
- **`LogoutController`** — login/callback/logout/`/auth/me` are one responsibility (the OAuth-client/BFF surface) over shared session + cookie + base-URL machinery; splitting by verb scatters that shared state across controllers, the definition of inventing indirection.
The size (~720 LOC) is real but is cohesion, not a god-class. Revisit only if a genuinely independent concern (e.g. a second protocol surface) lands.
**Where.** `auth-service/.../AuthController.java` (unchanged).

### A6 — Rotate `sid` on refresh-token rotation — `REF`, Med `[carried]`
**Why.** A once-observed `sid` stays valid across N token rotations for the full 8h absolute window (SECURITY.md S-5 discloses this). RFC 6265bis §8.6 and standard session practice favor rotating the session id on privilege/credential boundary changes; refresh rotation is the natural boundary here.
**What's needed.** On a successful refresh, mint `sid'`, copy `sess:{sid}` → `sess:{sid'}`, `DEL sess:{sid}`, return `sid'` in the `/internal/resolve` response so the gateway re-issues the `__Host-sid` cookie, and update the `idp_sid:`/`sub_sessions:` indexes to point at `sid'`. Invisible to the SPA (the gateway calls `/internal/resolve` on every `/api/**` and re-reads the rotated `sid`). Note the interaction with A1 (lock is keyed by `sid`).
**Where.** `InternalResolveController` (refresh path) / `AuthorizationCodeTokenRefreshClient`; `SessionIndexes`; the gateway's cookie re-issue in `bff-session.lua`. Decide explicitly and reflect in SPEC-0001 §7.2.

---

## B. Security

### B1 — Close the gateway-client-secret sentinel gap (or disclose it precisely) — **[done]**
**Resolved.** Added a render-time fail-closed guard: `render-apisix-config.sh` refuses to emit the route file when `REQUIRE_NONDEV_SECRETS=1` and `GATEWAY_CLIENT_SECRET`/`CSRF_SIGNING_KEY` are still dev sentinels — the gateway secret never reaches the Java `SecretSentinelValidator`, and APISIX `check_schema` can't fail a route load, so the Lua guard stays WARN-only and render time is the place to fail closed. Disclosure corrected: README's security-controls row and `SECURITY.md` D-1 + the `GATEWAY_CLIENT_SECRET` row now name the three distinct guards (Java fail-closed at boot; render fail-closed for the gateway secret + CSRF key; Lua WARN-only). Covered by `verify-api-gateway.sh` (rc==3 on sentinels, rc!=3 on real secrets), red→green verified.
**Where.** `scripts/render-apisix-config.sh`, `scripts/verify-api-gateway.sh`, `README.md`, `SECURITY.md`.

### B2 — Name the Resource Server's east-west exposure as a load-bearing control — **[done]**
**Resolved.** SECURITY.md threat model gains row **G-8** (valid token from a non-gateway caller hits the RS directly: bearer tokens are not sender-constrained, the route allowlist constrains paths not callers, so network isolation of the RS is the load-bearing control until DPoP/mTLS). README's "what's deliberately not here" DPoP/mTLS bullet now names the network-isolation dependency and cross-refs G-8.
**Why.** The RS authorizes purely on `aud=oidc-reference-api` + scope/roles; it has no notion that a request came from the BFF gateway. Any holder of a token with that audience (e.g. the `oidc-reference-service` client, or a server-side-exfiltrated user token) that gains network reachability can call the RS directly. The browser-token boundary protects the *browser*, not the RS's east-west surface. The threat model never lists "valid token from a non-gateway caller," and frames the route allowlist (which constrains *paths*, not *callers*) as the RS's protection. Network isolation is the real control. `REF` (disclosure); the fix (DPoP/mTLS) is `PROD`.
**What's needed.** Add a threat-model row: bearer tokens are not sender-constrained, so network isolation of the RS is load-bearing until DPoP/mTLS is added. Cross-reference the existing DPoP/mTLS "what's deliberately not here" bullet.
**Where.** `SECURITY.md` (G-section threat model), README "What's deliberately not here".

### B3 — Don't derive the cookie-name/`Secure` decision from client-controlled `X-Forwarded-Proto` — **[done]**
**Resolved.** Bare-`sid` acceptance is now gated behind an explicit `allow_insecure_sid` plugin flag (default **false**), not the spoofable scheme. `get_session_cookie(cookies, allow_insecure_sid)` honors `__Host-sid` unconditionally and accepts the bare `sid` only when the route opts in; a client `X-Forwarded-Proto` can no longer coax the gateway into honoring a bare `sid`. The local-dev template sets `allow_insecure_sid: true` (plain HTTP) with a comment that a production HTTPS render drops it → `__Host-sid` only. Verified: new Lua unit cases (`bare sid REJECTED by default` → nil, accepted only with the flag) via `test-pure-fns.lua`, and the live e2e (real login over the bare-`sid` path with the flag on) stays green 60/0. `effective_scheme` keeps driving only the eviction cookie's `Secure` attribute (not an acceptance decision).
**Where.** `api-gateway/plugins/bff-session.lua` (`get_session_cookie`, schema), `api-gateway/apisix.yaml.template`, `api-gateway/tests/test-pure-fns.lua`.

### B4 — Strip a positive set of inbound identity headers at the gateway — **[done]**
**Resolved.** `bff-session.lua` gains an `IDENTITY_HEADERS` strip set (x-user, x-forwarded-user/-email/-groups/-preferred-username, x-auth-request-*, x-email/-groups/-roles, x-remote-user, remote-user, x-authenticated-user, x-forwarded-access-token, x-id-token), cleared before proxying alongside HOP_BY_HOP, with the contract documented in a comment ("the RS MUST ignore all client-supplied identity headers"). New live gateway test `test_inbound_identity_headers_stripped` sends the set and asserts none reach the echo upstream; verified red→green (disabling the strip lets `x-roles=admin`, `x-id-token=forged` through). Gateway suite 60/0, full e2e green.
**Where.** `api-gateway/plugins/bff-session.lua`; `api-gateway/tests/test-gateway-behavior.sh`.

### B5 — Optional refresh-token-age ceiling for IdPs that omit `refresh_expires_in` — **[done]**
**Resolved (both routes).** Added the optional `app.max-refresh-token-age` (a `Duration`, unset by default → today's behavior). `SessionRecord` gains a nullable `refresh_minted_at` stamped at initial exchange and at every refresh-rotation, so it tracks the live refresh token; `refreshTokenExpired(maxRefreshTokenAge)` now also reports expired when the knob is set and `now - refresh_minted_at > maxAge`, independent of the IdP `refresh_expires_in`. `InternalResolveController` passes the knob into the short-circuit. Disclosed in SECURITY.md S-4/S-5 (absolute TTL is the only brake unless the knob is set). Nullable/tolerant for old sessions; 4 new `SessionRecordTest` cases; auth-service suite 170/0; e2e green (knob unset → refresh path unchanged).
**Where.** `SessionRecord`, `AuthProperties`, `AuthController`, `AuthorizationCodeTokenRefreshClient`, `InternalResolveController`; SECURITY.md S-4/S-5.

### B6 — `typ=at+JWT` validation at the Resource Server — **[done]** (decided: document, audience pin covers it)
**Decision: the audience pin is the load-bearing control; `typ` validation is a documented Do-Later.** The threat `typ=at+JWT` would guard — an ID token presented as an access token — is already blocked at the RS by the audience pin: this realm's ID tokens carry `aud=oidc-reference-auth` and access tokens carry the configured API audience, so an ID token fails RS validation regardless of `typ`. A strict `typ=at+JWT` validator can't be added in isolation — Keycloak emits `typ=JWT` by default, so the RS would 401 every token until the realm is reconfigured to emit `at+JWT`; the two must ship together. Took the backlog's "document that the audience pin already covers the threat" option, recorded in `SecurityConfig.jwtValidator` next to the validator chain so the decision is discoverable where a future contributor would add the check.
**Where.** `backend-resource-server/.../SecurityConfig.java` (comment at `jwtValidator`).

### B7 — OIDC RP-Initiated Logout `state` round-trip — **[done]**
**Resolved.** Took the cleaner option: stopped emitting the unused `state` on the logout redirect (it was generated but never validated on return). `id_token_hint`, `post_logout_redirect_uri`, `client_id`, `Referrer-Policy: no-referrer`, and cookie eviction are unchanged. `AuthControllerTest` now asserts the logout redirect carries no `state=`.
**Where.** `AuthController` logout path; `AuthControllerTest`.

---

## C. Testing

### C1 — Directly assert the gateway's bearer injection — **[done]**
**Resolved.** `GatewayTestEchoController` now reflects every inbound header (not a fixed allowlist), and the new live test `test_valid_session_injects_exact_bearer_and_strips_credentials` seeds a real access token, then asserts the upstream received `Authorization: Bearer <that exact token>`, the cookie was stripped, and neither the `sid` nor the CSRF value reached the RS in any header. Verified red→green against the live stack (passes on the correct gateway; fails with an exact-bearer mismatch + 401 when the injection is tampered). The earlier inference-only `test_valid_session_returns_200_with_bearer_injected` is kept for the tolerant-reader/forward path.
**Where.** `api-gateway/tests/test-gateway-behavior.sh`; `backend-resource-server/.../GatewayTestEchoController.java`.

### C2 — Reconcile SPEC-0002 C2/C3 "live matrix" claims with reality — **[done]**
**Resolved (softening route).** The universal "every matrix behavior MUST also have a live assertion / not a fabricated JWT" over-claim lived in `SPEC-0002`, which was folded into `SPEC-0001` and deleted (no `SPEC-0002` reference remains repo-wide). SPEC-0001's "Live conformance gates" section already scopes "real tokens, not fabricated JWTs" to *the live suites* (e2e-auth, C8, C9, BCL); it never claimed the ID-token / RS issuer-aud negatives are live. Added a sentence making the split explicit: those token-shape negatives are unit-layer with synthetic JWTs (`JwtDecoderNegativeTest` + the AS ID-token tests), the live suites assert the happy path + the trust-boundary/session-window/logout negatives end-to-end — two deliberate layers, not a gap. The spec now claims exactly what is true.
**Where.** `docs/specs/SPEC-0001-core-oidc-flows.md` § "Live conformance gates".

### C3 — De-flake the timing-based conformance gates — **[done]**
**Resolved.** Replaced the two fixed `sleep 6` against idle=10 (4s of drift margin) with polling. C9.4 (keep-alive) now polls `/api` at gaps of `idle/3` across >1 idle window and asserts the session still EXISTS with a live TTL — a slow host only delays, can't flip it. C9.5 (ceiling) polls `/api` to a deadline well past the 11s ceiling and detects death by `EXISTS=0` (a non-JWT yields RS 401 whether the session is alive or gone, so only EXISTS distinguishes — the old `*:401:0` match was fragile). Verified: C9.4/C9.5 PASS in the live conformance run.
**Where.** `scripts/e2e-conformance.sh` (C9.4/C9.5).

### C4 — Live PKCE-mismatch and `tx:{state}` 5-minute expiry negatives — **[done]** (unit complement; live parts deferred with rationale)
**Resolved.** Added the unit complement: `exchangeFailsClosedWhenTokenEndpointRejectsTheCode` drives the token endpoint to `invalid_grant` (what a PKCE-verifier mismatch / reused-or-expired code returns) and asserts the exchange fails closed (`IllegalStateException`) before id-token validation or session creation — the same fail-closed path a live mismatch would take. The `tx:{state}` negatives it pairs with are already unit-covered (`callbackRejectsWhenOauthTxCookieIsMissing`, `...DoesNotMatchStoredHash`, the iss-param and no-code cases), and the live happy-path PKCE round-trip is proven by `e2e-auth`.
**Deferred (Do-Later, documented):** the two *live* negatives the item names — waiting `tx:{state}` out to its 5-minute TTL, and a real verifier-mismatch against Keycloak — are not added as live gates: the 5-minute TTL can't be waited in a gate without TTL-compression plumbing, and a live mismatch needs partial-flow orchestration to obtain a real authorization code with a swapped verifier. Their fail-closed outcomes are asserted at the unit layer above; a future harness with a compressed `tx` TTL could promote them.
**Where.** `AuthorizationCodeTokenExchangeClientTest`.

### C5 — Unit-test the pure Lua functions — **[done]**
**Resolved (scoped to what bare LuaJIT can run).** Added `test-pure-fns.lua` with isolated unit tests for `constant_time_equals` — the constant-time byte comparison under signed-CSRF/HMAC validation, exposed via a new `_M._constant_time_equals` hook (mirroring the existing `_resolve_session` pattern). 13 assertions (equality, equal-length inequality at first/last byte, length mismatch, nil/non-string, 64-byte HMAC-length vectors); run by `test-lua-unit.sh` inside the pinned APISIX image via `docker run` (the existing Lua-unit gate, alongside the resolve-flow decision-table test). Green. `hmac_b64url` / `csrf_ok` need OpenResty's `resty.hmac` + `ngx.encode_base64`, absent in bare LuaJIT, so they stay covered by the live signed-CSRF battery in `test-gateway-behavior.sh` (no-CSRF / unsigned / mismatched / forged-HMAC / cross-session / valid) — noted in the test file. (ISO-8601 parser + refresh state machine already moved to Java with phantom-token.)
**Where.** `api-gateway/plugins/bff-session.lua` (`_constant_time_equals` hook); `api-gateway/tests/test-pure-fns.lua`, `test-lua-unit.sh`.

### C6 — Decouple tests from the SLF4J audit wire format — **[done]**
**Resolved.** `SecurityAudit` now holds the wire format in two `static final` constants (`FORMAT`, `FORMAT_WITH_SUBJECT`); both `event(...)` overloads reference them (format byte-identical). Two focused `SecurityAuditTest` cases own the rendered-shape invariant. A future format change updates the two constants + the one owning test, not the ~20 substring assertions (left passing). Partial by design — full decoupling of all 20 sites was over-investment for a Low item.
**Where.** `SecurityAudit.java`, `SecurityAuditTest.java`.

---

## D. Documentation honesty / cleanup — `REF`

### D1 — Remove the phantom `internal.refresh` scope check from the docs — **[done]**
**Resolved by `b93454e`.** The phantom-token §7.1 rewrite dropped the `scope contains "internal.refresh"` line. The endpoint is now `/internal/resolve`, and §7.1 documents exactly what the code enforces: Bearer signature + `iss` + `exp` + `aud` contains the configured internal-refresh audience + `azp`/`client_id` equals the gateway client id — no scope check. Re-grep `internal.refresh` if reviving any related doc to confirm it stays gone.

### D2 — Fix the Referrer-Policy coverage claim — **[done]**
**Resolved.** `RFC9700-compliance.md` §4.2.4 now states `Referrer-Policy: no-referrer` is set on the logout 302 and on **both** the callback success and callback error redirects (verified against the three set-points in `AuthController.java`). The inaccurate claim existed only in RFC9700-compliance.md; SECURITY.md carried no contradicting version.

### D3 — Trim unsupported superlatives and post-hoc rationale — **[done]**
**Resolved.** The asserted-as-fact scaling-asymmetry claim ("auth low-frequency big-payload, API high-frequency small-payload") is reframed as a design expectation — "different expected load profiles, so each can scale independently" — in both `architecture-decisions.md` and README §"Why this shape". The "uniquely sophisticated" / "production-grade" superlatives were already gone (no occurrences remain).

### D4 — Resolve SPEC-0001's "Status: Draft" vs "the build contract" — **[done]** (already resolved)
**Resolved.** No "Status: Draft" label exists in `SPEC-0001-core-oidc-flows.md` (a prior pass removed it; its header already reads "This spec is the build contract"). Verified by grep for "Draft" / "Status:" — no contradiction remains. No edit needed.

### D5 — Relocate the agent-process docs out of the reference surface — Low (mostly done)
**Why.** `AGENTS.md` "Mandatory Turn Protocol" describes an internal authoring workflow, not the BFF reference. It adds surface a consumer must wade past.
**Status.** `agent.md` and `docs/agents/*` were already moved to the gitignored `.agents/` (commit `369e335`), so they are no longer on the published surface. **Remaining:** only `AGENTS.md` still sits at the repo root.
**What's needed.** Decide `AGENTS.md`'s fate — keep it (it is the canonical agent-context file many tools auto-read) or fold its consumer-irrelevant process content under `docs/contributing/` and keep `CONTRIBUTING.md`.
**Where.** `AGENTS.md`.

### D6 — Generalize the SPA `callApi` (CSRF for unsafe methods) — **[done]**
**Resolved.** `callApi(path, { method, body, headers }?, navigate?)` — GET stays the default with a byte-identical request shape; unsafe methods (not GET/HEAD/OPTIONS) attach `X-XSRF-TOKEN` from `readCsrfCookie()`, object bodies are JSON-encoded with `Content-Type: application/json`, and the 401-never-navigates-to-the-API contract holds for all methods. Backward-compatible with existing GET call sites. Covered by 4 vitest cases (GET no-CSRF, bare GET, POST CSRF+JSON, unsafe+401); suite 29/29 green.
**Where.** `frontend/src/auth.ts`, `frontend/src/auth.test.ts`.

---

## E. Production-hardening doc completeness — `PROD` (document, don't build)

The `production-hardening.md` checklist nails the refresh-lock and secret-cutover items but is a *partial* list presented as the path to done. These are the operational fundamentals an enterprise rollout fails on first; the action is to add them to the hardening doc (and, where noted, the threat model) so the doc is a complete starting subset rather than implying completeness. **Not** asking the reference to implement them.

**[done] (2026-06-11)** — E1–E8 are disclosed in `docs/operations/production-hardening.md` § "Operational Fundamentals Not Built Here" (E1 single-Valkey SPOF + stateless-tier note, E2 observability/correlation IDs, E3 graceful shutdown, E4 dependency-checked readiness, E5 Valkey eviction/durability, E6 supply-chain — scoped to the container/Maven-download layer, since the poms already ship a CycloneDX aggregate SBOM, E7 rate-limit/refresh-amplification, E8 zero-downtime-deploy precondition).

### E1 — Session-store HA and the single-Valkey SPOF — High (disclosure)
Single Valkey, no replica/Sentinel/Cluster, no Lettuce failover config. It is a hard SPOF for the entire authenticated surface (every request reads `sess:{sid}`; `tx:{state}` also lives there). Add: HA topology guidance, the failover decision for in-flight refreshes, and the (reassuring, currently-unstated) point that sessions are externalized so APISIX/auth-service are stateless and need no sticky sessions.

### E2 — Observability and cross-tier correlation IDs — High (disclosure)
Zero Micrometer/OTel; no `traceId`/`X-Request-Id` stitching gateway→auth→RS. When the multi-instance logout storm (A1) hits in production there is no metric or trace to see it. The audit log is good *within* auth-service but carries no correlation id. Add: a correlation-ID propagation contract (cheap, high value, a precondition for the tracing the doc already says to add) and a RED-metrics/IdP-SLO note.

### E3 — Graceful shutdown — High (disclosure)
No `server.shutdown: graceful` / `spring.lifecycle.timeout-per-shutdown-phase` in either service. On SIGTERM the JVM stops immediately, killing in-flight refreshes mid-rotation — and a refresh interrupted after Keycloak rotated but before `putIfPresent` persisted will orphan the session (next refresh → `invalid_grant` → logout). This actively compounds A1 during any rolling deploy. Add to the checklist (and it's a near-free config win the reference could even adopt).

### E4 — Dependency-checked readiness probes — Med (disclosure)
`management.endpoint.health.probes.enabled` auto-creates `/readiness`, but with default content it reflects only Spring lifecycle — it does **not** check Valkey or IdP reachability. A replica with a dead Valkey reports Ready and takes traffic. Document the need for a custom readiness `HealthIndicator`/group; note the Compose healthcheck hits the aggregate `/actuator/health`, not `/readiness`.

### E5 — Valkey eviction policy and durability footguns — Med (disclosure)
No `maxmemory`/`maxmemory-policy` → default `noeviction`, which under memory pressure *rejects refresh writes* (→ logout); a naive switch to `allkeys-lru` would *evict live sessions*. No persistence → a Valkey restart is a fleet-wide logout. The docs discuss AUTH/TLS but not durability or eviction. Recommend `volatile-ttl` + capacity headroom (every key has a TTL) and state the restart-is-mass-logout implication. (Supersedes the old C9 AUTH/TLS item, which remains valid for transport security.)

### E6 — Supply-chain pinning — Med (disclosure)
All images are mutable tags (no `@sha256` digest pinning); the Dockerfile downloads Maven over the network with no checksum verification; no SBOM, no image signing. Tags can be re-pushed, breaking reproducibility. Add digest-pinning, checksum-verified build downloads, and SBOM/signing to the hardening doc. (Credit: images are pinned to specific minor tags, not `:latest`; runtime images are non-root JRE.)

### E7 — Rate-limit coverage and IdP refresh-amplification — Med (disclosure)
`limit-req` covers only `/auth/login` + `/auth/callback/idp`. Post-phantom-token every `/api/**` request already makes a synchronous gateway→`/internal/resolve` call; when the access token is near expiry, each such call drives a refresh through the gateway→`/internal/resolve`→Keycloak chain — so an authenticated client looping `/api/**` in that window amplifies load on the IdP token endpoint. Document the amplification path and recommend limits on the refresh-driving path; note the `remote_addr` keying caveat behind a real LB (already flagged in the template).

### E8 — State the zero-downtime-deploy precondition plainly — High (disclosure)
A1 (in-process lock) + E1 (single Valkey) + single-key CSRF/oauth_tx hard cutover + E3 (no graceful shutdown) combine so that the architecture **cannot do a single zero-downtime/blue-green/rolling deploy today** — the first `kubectl rollout` logs everyone out. Each prerequisite is disclosed piecemeal; the compound conclusion is not. Add one explicit sentence: "Do not roll this with >1 replica until A1 + a shared session store + dual-key signing + graceful shutdown are in place." Also note the single signing key is shared by CSRF *and* `oauth_tx`, so a rotation breaks in-flight logins too (blast radius wider than the CSRF framing).
