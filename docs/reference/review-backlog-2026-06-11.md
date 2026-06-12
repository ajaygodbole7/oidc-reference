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

### A2 — De-duplicate the `bff-session` plugin config across the four APISIX routes — `REF`, Med
**Why.** `apisix.yaml.template` repeats the identical ~8-line, secret-bearing plugin config block verbatim for `api-me`, `api-user-data`, `api-admin`, and `api-test-echo`. This *is* the "add a new protected route" extensibility path, and it's the worst-maintained part of the design: one divergent copy (a stale `refresh_window_seconds`, a missing CSRF key after a careless edit) is a silent security inconsistency no test would catch. For a reference teaching the single-chokepoint pattern, the chokepoint config should be DRY.
**What's needed.** Use APISIX standalone `plugin_configs` (a named, reusable plugin configuration referenced by `plugin_config_id`) so the `bff-session` config is declared once and referenced by each route. Update `render-apisix-config.sh` accordingly.
**Where.** `api-gateway/.../apisix.yaml.template`, `scripts/render-apisix-config.sh`.

### A3 — Add a cross-language contract test for the idle-TTL sliding math — **[done]** (obsolete after phantom-token)
**Resolved by `b93454e`.** The duplication this item targeted no longer exists. Phantom-token deleted the Lua `slide_session_ttl` from the gateway; the idle-TTL slide now lives in exactly one place — `SessionRecord.nextTtl`, applied by the Auth Service inside `/internal/resolve`. There is no second-language implementation to drift against, so no cross-language contract test is needed. `SessionRecord.nextTtl`'s own unit tests (the `remaining < idle` cap and the zero/expired case) remain the coverage.

### A4 — Make `RedisStateStore.addToSet` atomic (SADD + EXPIRE) — `REF`, Low
**Why.** `addToSet` issues `SADD` then `EXPIRE` as two round-trips. The rest of the store is meticulous about atomicity (`GETDEL`, `SET XX`); this is the one non-atomic op. A failed/reordered `EXPIRE` can leave a `sub_sessions:` set with no TTL (leaked key) or a wrong one. Impact is low (leaked index keys are explicitly tolerated), but it's an inconsistency with the store's own standard.
**What's needed.** Make it a single `MULTI`/pipeline or a small Lua `redis.call` script.
**Where.** `auth-service/.../RedisStateStore.java` `addToSet`; caller `SessionIndexes.addSubjectSession`.

### A5 — Consider splitting `AuthController` — `REF`, Low
**Why.** At ~720 LOC it owns login, callback, logout, logout-continue, `/auth/me`, cookie minting, base-URL computation, and saved-request validation — the one cohesion outlier in an otherwise single-responsibility codebase. Not a defect; it's where the next contributor will struggle.
**What's needed.** Optional: extract a `CookieFactory` and/or a `LogoutController`. Only if it improves readability without inventing indirection.
**Where.** `auth-service/.../AuthController.java`.

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

### B3 — Don't derive the cookie-name/`Secure` decision from client-controlled `X-Forwarded-Proto` — Med
**Why.** `effective_scheme` reads `X-Forwarded-Proto` with no trusted-proxy gate, and `get_session_cookie` accepts the non-`__Host-` bare `sid` when the computed scheme is `http`. Severity is bounded — the plugin checks `__Host-sid` *first, unconditionally* (`bff-session.lua:139`), so a real `__Host-sid` session can't be downgraded by the header — but feeding a spoofable header into a security decision is a smell, and it matters where only a bare `sid` is present (e.g. a TLS-terminating LB that forwards plaintext + client-supplied XFP). `REF`.
**What's needed.** Gate the bare-`sid` acceptance behind an explicit plugin flag (e.g. `allow_insecure_sid`, default off) instead of inferring from scheme, and/or gate XFP behind an APISIX trusted-address/real-IP allowlist. In production, require `__Host-sid` and never honor bare `sid`. (Supersedes/merges the old C10.)
**Where.** `bff-session.lua` (`effective_scheme`, `get_session_cookie`, `expire_session_cookie`), `apisix.yaml.template`.

### B4 — Strip a positive set of inbound identity headers at the gateway — **[done]**
**Resolved.** `bff-session.lua` gains an `IDENTITY_HEADERS` strip set (x-user, x-forwarded-user/-email/-groups/-preferred-username, x-auth-request-*, x-email/-groups/-roles, x-remote-user, remote-user, x-authenticated-user, x-forwarded-access-token, x-id-token), cleared before proxying alongside HOP_BY_HOP, with the contract documented in a comment ("the RS MUST ignore all client-supplied identity headers"). New live gateway test `test_inbound_identity_headers_stripped` sends the set and asserts none reach the echo upstream; verified red→green (disabling the strip lets `x-roles=admin`, `x-id-token=forged` through). Gateway suite 60/0, full e2e green.
**Where.** `api-gateway/plugins/bff-session.lua`; `api-gateway/tests/test-gateway-behavior.sh`.

### B5 — Optional refresh-token-age ceiling for IdPs that omit `refresh_expires_in` — Low
**Why.** When `refresh_expires_in` is absent (common on Okta/Auth0/Entra), `refreshExpiresAt` is null and `refreshTokenExpired()` always returns false, so the only brake on a non-rotating-`sid` session is the 8h absolute cap. Combined with S-5 (sid never rotates) a stolen `sid` can refresh for the full window. `REF` to disclose; optional knob.
**What's needed.** Either document that absolute TTL is the only brake on such IdPs, or add an optional `app.max-refresh-token-age` independent of the IdP-supplied value.
**Where.** `AuthorizationCodeTokenExchangeClient.parseRefreshExpiresIn`, `SessionRecord`, `AuthProperties`; SECURITY.md S-4/S-5.

### B6 — `typ=at+JWT` validation at the Resource Server — Low `[carried]`
**Why.** RFC 9068 §2.1 RECOMMENDS access tokens carry `typ=at+JWT`. Keycloak emits `typ=JWT` by default and the RS doesn't check `typ`. The audience pin (`aud=oidc-reference-api`) already blocks ID-token-as-access-token confusion, so this is defense-in-depth, not the only defense.
**What's needed.** Configure Keycloak to emit `typ=at+JWT` (per-client mapper, realm-file change) and add a `typ` header validator at the RS. Or document that the audience pin already covers the threat.
**Where.** `authorization-server/realm/...`; `backend-resource-server/.../SecurityConfig.java`.

### B7 — OIDC RP-Initiated Logout `state` round-trip — Low `[carried]`
**Why.** A random `state` is generated for the logout redirect but never validated on return; `post_logout_redirect_uri` lands at public `/`, so there's no exploit today, but the pattern is incomplete vs the OIDC RP-Initiated Logout 1.0 SHOULD.
**What's needed.** Either stop emitting `state` on logout (cleaner than emit-and-ignore), or add a `/auth/post-logout-callback` that validates `state` against a short-TTL entry then redirects.
**Where.** `AuthController` logout path.

---

## C. Testing

### C1 — Directly assert the gateway's bearer injection — **[done]**
**Resolved.** `GatewayTestEchoController` now reflects every inbound header (not a fixed allowlist), and the new live test `test_valid_session_injects_exact_bearer_and_strips_credentials` seeds a real access token, then asserts the upstream received `Authorization: Bearer <that exact token>`, the cookie was stripped, and neither the `sid` nor the CSRF value reached the RS in any header. Verified red→green against the live stack (passes on the correct gateway; fails with an exact-bearer mismatch + 401 when the injection is tampered). The earlier inference-only `test_valid_session_returns_200_with_bearer_injected` is kept for the tolerant-reader/forward path.
**Where.** `api-gateway/tests/test-gateway-behavior.sh`; `backend-resource-server/.../GatewayTestEchoController.java`.

### C2 — Reconcile SPEC-0002 C2/C3 "live matrix" claims with reality — Med
**Why.** SPEC-0002 states every matrix behavior MUST also have a live assertion against the running stack ("not a fabricated Jwt"). C2 (ID-token negatives) and C3 (RS negatives *through the gateway*) have only synthetic-token unit tests (excellent, but unit-layer); the one live RS-negative hits the RS directly, not through the gateway, and is gated behind an env flag. The behavior is well-tested; it is not tested the way the spec claims.
**What's needed.** Either add the live assertions (a second realm/key to drive wrong-issuer at the RS through the gateway → 401; an expired real access token), or soften the SPEC-0002 language for C2/C3 to "unit-level, with live happy-path."
**Where.** `docs/specs/SPEC-0002-conformance-and-cleanup.md`; `scripts/e2e-conformance.sh`, `verify-rs-negatives.sh`.

### C3 — De-flake the timing-based conformance gates — Med
**Why.** C9.4/C9.5 use fixed `sleep 6` against compressed TTLs (idle=10s). On a loaded host or slow APISIX reload, the sleep + request latency can drift across the 10s boundary and flip the gate to a false failure (or false pass if timing coincidentally aligns).
**What's needed.** Poll the Valkey TTL/EXISTS transition instead of sleeping a fixed interval, or widen the margins.
**Where.** `scripts/e2e-conformance.sh` (C9.4/C9.5).

### C4 — Live PKCE-mismatch and `tx:{state}` 5-minute expiry negatives — Low `[carried as C1-spec]`
**Why.** SPEC-0002 C1 lists "code redeemed without matching verifier → token endpoint rejects" and "expired `tx:{state}`". Single-use consumption is tested structurally, but no test drives the 5-minute TTL expiry or the live PKCE mismatch.
**What's needed.** A harness test that lets `tx:{state}` expire and asserts callback rejection; a live PKCE-verifier-mismatch negative against Keycloak.
**Where.** conformance harness; `AuthorizationCodeTokenExchangeClientTest` (unit complement).

### C5 — Unit-test the pure Lua functions — Low `[carried]`
**Why.** Security-critical Lua whose pure functions are covered only end-to-end via the gateway harness: the constant-time compare (`constant_time_equals`), the CSRF HMAC validator (`csrf_ok` / `hmac_b64url`), and cookie parsing (`parse_cookies` / `get_session_cookie` / `effective_scheme`). (Phantom-token moved the ISO-8601 parser and the refresh state machine out of the gateway and into the Auth Service — they are now Java, unit-tested there; the old `test-iso8601-parse.lua`/`test-refresh-flow.lua` are gone.)
**What's needed.** Extract the pure functions (or use the existing `_M._*` test hooks) and add isolated tests via `busted`/`resty.test`. Leave the Valkey + HTTP paths to integration.
**Where.** `bff-session.lua`; new Lua test files under `api-gateway/tests/`.

### C6 — Decouple tests from the SLF4J audit wire format — Low `[carried]`
**Why.** ~20 assertions pin the exact `event=… reason=…` log string; moving to JSON structured logging would break all of them at once.
**What's needed.** Introduce a `SecurityAuditFormat` constant referenced by both the emitter and the tests, so a format change updates one place. Keep one focused `SecurityAuditTest` that owns the wire-format invariant.
**Where.** `SecurityAudit.java`; the audit-asserting tests.

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
