# Review Backlog — Phantom-Token Re-Review

**Generated:** 2026-06-12
**Reviewed at:** git HEAD `444cd0c` (post phantom-token re-architecture).
**Source:** Second multi-dimension review (architecture · security · concurrency · testing · doc-honesty), run after the gateway moved to the phantom-token pattern (gateway calls `POST /internal/resolve` on the Auth Service instead of reading Valkey) and the prior backlog (`review-backlog-2026-06-11.md`) was worked.
**Verification:** the four highest-impact findings (N1–N4) were verified directly against source; the rest come from the audit set + spot checks. No build/test run was performed.

This file supersedes the 2026-06-11 backlog as the live list. Items from that
file are now essentially all done (verified against code, not commit messages);
the residuals are carried here as `[from 2026-06-11]`.

**Scope key:** `REF` = the reference itself should fix/demonstrate it. `PROD` =
production-hardening concern; the action is to document honestly, not build
(CI remains intentionally out of scope as a production concern).
**Status key:** OPEN · FIXED-2026-06-12 (done in the same commit that adds this file).

---

## 0. Headline assessment (context for the items below)

The phantom-token rewrite is sound and the prior backlog was addressed with real
substance. Error-mapping fails closed/non-destructive correctly; only the access
token crosses to the gateway (refresh/id never do); CSRF stayed session-bound and
constant-time; no security test was deleted (the `InternalRefreshControllerTest`
→ `InternalResolveControllerTest` rename *gained* coverage). What remains is
concentrated in two hot-path operational gaps the new topology created (N1, N2),
two rotation-window refinements (N3, N4), and minor cleanup.

---

## A. New findings from the phantom-token architecture

### N1 — No HTTP connection pooling on the resolve hot path — `REF`, **High**, OPEN
**Why.** `bff-session.lua` uses resty.http's one-shot `request_uri()` for both the
resolve call (`:564`) and the Keycloak client-credentials call (`:508`), with **no
`set_keepalive` anywhere in the module**. Pre-rewrite this ran only on refreshes;
under phantom-token it runs on **every `/api/**` request**, so each API call now
pays a full TCP handshake + teardown (TIME_WAIT churn, socket-exhaustion risk
under load) to the Auth Service. The ADR's "one cheap extra RPC on a local
network" latency accounting silently assumes a warm connection it never keeps.
**What's needed.** Switch to the low-level API: `httpc:connect` → `request` →
`httpc:set_keepalive(idle_ms, pool_size)`, so connections to the Auth Service (and
the Keycloak CC leg) are pooled per nginx worker. Expose pool size as a knob.
**Where.** `api-gateway/plugins/bff-session.lua:508,564`.

### N2 — Auth Service is now a hard SPOF for all `/api` traffic, with no circuit breaker — `REF`+`PROD`, **High**, OPEN
**Why.** The resolve RPC is gated only by timeouts (connect 1s / read 5s) and one
CC retry; a real circuit breaker is deferred to "production" in the SPEC. When the
Auth Service is *slow* (not down), every `/api` request blocks up to ~5s before
returning 503 and the gateway worker pool fills with stalled resolves — a classic
latency-induced cascading failure. Pre-rewrite, a slow/down Auth Service degraded
only the refresh minority; now it degrades 100% of API traffic. The topology
change is exactly what makes a breaker load-bearing *now*, not "later". (The
latency cost and the CC-token "availability floor" are disclosed in prose; the
fixes are not built, and the Auth-Service availability-SPOF was — now fixed in the
ops SPOF section, see DD6.)
**What's needed.** Add an APISIX `api-breaker` (or an in-plugin rolling-window
breaker with half-open probe + 503/Retry-After) in front of `/internal/resolve`,
paired with N1's pooling. Consider a bounded per-worker resolve concurrency limit.
**Where.** `bff-session.lua` resolve path; `apisix.yaml.template`; SPEC-0001 §7.1.

### N3 — sid-rotation resurrection window on concurrent subject logout — `REF`, **Medium**, FIXED-2026-06-12 *(self-disclosed)*
**Fix.** `StateStore.rotateIfPresent` now writes the `rotated:{old}` breadcrumb in the
SAME atomic op as the `sess:{old}`→`sess:{new}` move (Redis: one Lua script; in-memory
twin mirrors it). The separate post-move `put` is gone. A concurrent subject-wide logout
now sees either `sess:{old}` (EXISTS-gate fails closed) or `sess:{new}`+breadcrumb (follows
it) — never an in-between state. Index-repoint keeps its existing `idp_sid` CAS. Parity test
asserts breadcrumb-written-atomically + no-orphan-on-fail; teeth via mutation.
**Why.** Rotation does three non-atomic store calls — move `sess:{sid}`→`sess:{sid'}`
(`InternalResolveController.java:220`), write the `rotated:{sid}` breadcrumb
(`:228`), repoint indexes (`:234`) — and **logout does not take the refresh lock**
(comment at `:216`). Interleaving: a subject-wide / back-channel logout calling
`SessionIndexes.deleteLocalSession(old)` in the sub-millisecond window *between*
the move and the breadcrumb write finds no breadcrumb to follow, so the live
`sess:{new}` is not deleted; the subsequent `rotate()` then re-adds `new` to
`sub_sessions`, leaving a **logged-out session alive to the absolute ceiling**.
The `idp_sid` path self-heals via its CAS; the subject path has no second gate.
The code comment (`SessionIndexes.java:130-132`) acknowledges the window as a
"Do-Later for HA" — but it is a single-instance revocation bypass, not purely HA.
**What's needed.** Write the breadcrumb **before** the move (converts the dangerous
window into a fail-closed one — a logout reaching `old` before the move deletes
`sess:{old}`, and `rotateIfPresent`'s EXISTS-gate then fails closed), or — better —
fold move + breadcrumb + index-repoint into a single atomic Lua script. Gate the
subject-path `addSubjectSession(new)` on `sess:{new}` still existing.
**Where.** `InternalResolveController.java:219-241`, `SessionIndexes.java:74-77,114-143`.

### N4 — 30s rotation grace keeps the OLD sid valid — `REF`, **Medium**, FIXED-2026-06-12
**Fix.** `ROTATION_GRACE` 30s → 10s (`InternalResolveController.java:45`), comfortably above
the ~5s resolve read timeout the only legitimate consumer (a raced in-flight request) needs.
SECURITY S-5 updated. Replay surface after each rotation cut ~3×.
**Why.** `ROTATION_GRACE = 30s` (`InternalResolveController.java:45`): a stolen old
sid still resolves (via breadcrumb → fresh token) for 30s after each rotation. A6
reduced the fixation window from 8h to 30s — a real win — but "a once-observed sid
stops working after refresh" is actually "…30s after refresh." The only legitimate
consumer of the breadcrumb is a request that raced the rotation, bounded by the
~5s resolve read timeout, not 30s.
**What's needed.** Shrink `ROTATION_GRACE` to ~5–10s (cuts the replay surface
3–6×); document the residual window in SECURITY S-5. Optionally make it a knob.
**Where.** `InternalResolveController.java:45`; `SECURITY.md` S-5.

### N5 — `hasExpectedCaller` accepts `azp` OR `client_id` — `REF`, **Med/Low**, OPEN
**Why.** `InternalResolveController.java:309-316` returns true if *either* `azp` or
`client_id` matches the gateway client id. The JWT signature + audience are the
strong gates (low real-world risk in a single-tenant realm), but the OR is looser
than the SPEC's conjunctive intent and accepts a token that proves the identity in
only one claim.
**What's needed.** Prefer `azp`; fall back to `client_id` only when `azp` is absent;
reject when both are present and only one matches.
**Where.** `InternalResolveController.java:309-316`.

### N6 — Rotation `Set-Cookie` overwrites any upstream `Set-Cookie` — `REF`, **Low**, OPEN
**Why.** `bff-session.lua:843` assigns `ngx.header["Set-Cookie"] = {…}`, which
**replaces** (not appends) any Set-Cookie the Resource Server emitted on that
response — silently, and only on the intermittent rotation responses. Harmless
while the RS is cookieless (it is), latent otherwise and very hard to debug.
**What's needed.** Read existing `Set-Cookie`, append the rotation cookies, reassign;
or assert/document the "RS MUST NOT set cookies" invariant at the gateway.
**Where.** `bff-session.lua:843-847`.

### N7 — 502/503 inconsistency on CC-retry transport failure — `REF`, **Low**, OPEN
**Why.** A transport failure (status 0) on the CC-retry maps to 502
(`bff-session.lua:659`), while the same failure on the first attempt maps to 503
(`:663`). Same root cause ("auth-service unreachable"), different status/Retry-After
to the SPA. Neither clears the cookie, so it is cosmetic, not a session-safety bug.
**What's needed.** In the 401-retry branch, map `retry_status == 0` to `"503"` like
the primary path; reserve `"502"` for a genuine second 401 / malformed body.
**Where.** `bff-session.lua:642-661`.

### N8 — `rotateIfPresent` is overwrite-on-collision, safe only by newSid entropy — `REF`, **Info**, OPEN
**Why.** The rotate primitive gates on `EXISTS old` then does an unconditional
`SET new` (`RedisStateStore.java:31-36`); a pre-existing `sess:{new}` would be
clobbered. `newSid` is a 256-bit `SecureRandom` token so a real collision is
impossible — but the safety rests entirely on entropy, and a parity test enshrines
clobber-on-collision as intended.
**What's needed.** One-line threat-model note that safety depends on newSid entropy;
no code change required.
**Where.** `RedisStateStore.java:31-36`; threat model.

---

## B. Carried residuals from the 2026-06-11 backlog (verified short of "done")

### B1 — Audit-format constant not actually shared with tests (C6 PARTIAL) — `REF`, **Low**, OPEN `[from 2026-06-11]`
**Why.** The format constant is shared between the two production `SecurityAudit.event()`
overloads, but `SecurityAuditTest` still hardcodes the wire-format string as a
literal (references the constant only in a comment). The format is duplicated
prod↔test; a change still requires editing both. The backlog labels it "partial by
design," but it was logged as resolved.
**What's needed.** Have the test assert against `SecurityAudit.FORMAT` /
`FORMAT_WITH_SUBJECT` (build the expected line from the constant), so a format
change updates one place.
**Where.** `SecurityAudit.java`, `SecurityAuditTest.java:217-231`.

### B2 — "Keep AuthController un-split" decision recorded only in the backlog (A5) — `REF`, **Low**, OPEN `[from 2026-06-11]`
**Why.** The decision is defensible, but its rationale lives only in the review
backlog file — not in `AuthController.java` or the architecture docs where a future
contributor looks. It won't survive the backlog being archived.
**What's needed.** A one-line class-level note in `AuthController.java` (or an ADR
entry) recording the deliberate "kept cohesive, not split" decision.
**Where.** `AuthController.java`; optionally `docs/architecture/architecture-decisions.md`.

### B3 — Relocate the agent-process docs out of the published surface (D5) — `REF`, **Low**, OPEN `[from 2026-06-11]`
**Why.** Partially done (`.agents/` is now gitignored, `AGENTS.md` cleaned up,
`CONTRIBUTING.md` added). Confirm nothing left in the published tree describes the
internal authoring workflow rather than the reference itself.
**What's needed.** Final sweep; this is the one genuinely-open item from the prior
backlog per the doc-honesty audit.
**Where.** repo root, `docs/`.

---

## C. Missing tests (new architecture)

### C1 — No test proves the OLD sid stops working after the breadcrumb expires — `REF`, **Medium**, FIXED-2026-06-12
**Fix.** `InternalResolveControllerTest.oldSidIsDeadOnceTheRotationGraceBreadcrumbExpires`:
rotate, prove the old sid resolves WHILE the breadcrumb lives, delete `rotated:{old}` (simulate
the grace TTL elapsing), assert the old sid 404s while the new session stays alive.
**Why.** The A6 security bound ("a stolen old sid is dead within ~`ROTATION_GRACE`
of rotation") is asserted only by the 30s TTL literal in code — there is no test
that, after the breadcrumb expires, presenting the old sid yields 404/no-session.
A breadcrumb accidentally set to the absolute ceiling would silently re-open the
exact S-5 hole A6 closed, and nothing would catch it. This is the highest-value
missing rotation test.
**What's needed.** A test (Testcontainers or fast-clock) asserting old-sid → 404
once `rotated:{old}` has expired.
**Where.** `InternalResolveControllerTest` / a rotation-focused harness test.

### C2 — No live gateway test that the 503 transient path keeps the cookie — `REF`, **Low**, OPEN
**Why.** The 502→503-keep-cookie mapping is unit-tested in Lua and the AS-side
non-destructive 502 is proven, but no end-to-end test drives a real transient Auth
Service failure and asserts the browser keeps its cookie + sees `Retry-After`. The
unit + AS tests bracket it, so value is moderate.
**What's needed.** A gateway-behavior test that makes resolve return 502 (or the AS
unreachable) and asserts cookie retained + 503 + Retry-After.
**Where.** `api-gateway/tests/test-gateway-behavior.sh`.

### C3 — Gateway TTL/ceiling tests are mislabeled to the wrong layer — `REF`, **Low**, OPEN
**Why.** `test_api_activity_slides_session_ttl`, `test_ttl_slide_capped_at_absolute_ceiling`,
and `test_session_past_absolute_ceiling_returns_401` still seed Valkey and carry
"the slide that used to live in the gateway's Lua EXPIRE" comments. The slide now
happens in the Auth Service inside `/internal/resolve`; the tests still pass (they
observe the end-to-end effect) but read as gateway-plane units they no longer
exercise. `lib.sh:5-7` carries the same stale framing.
**What's needed.** Re-comment these as Auth-Service-plane integration assertions, or
consolidate with the `InternalResolveControllerTest` slide tests + conformance C9.
**Where.** `api-gateway/tests/test-gateway-behavior.sh:673,697,720`; `lib.sh:5-7,115`.

---

## D. Documentation drift introduced by the rewrite — FIXED 2026-06-12

These were the "gateway reads `sess:{sid}`" claims the rewrite left behind. All
fixed in the commit that adds this file; recorded here for completeness.

- **DD1** `schema/sess-payload.example.json` `$comment` said "the API Gateway is a
  tolerant reader … the Lua plugin's parser." Rewritten: Auth-Service-private
  schema (sole reader+writer); the gateway consumes `access_token` /
  `access_token_expires_at` via the `/internal/resolve` response, not by parsing
  the key; no Lua parser exists. **FIXED-2026-06-12.**
- **DD2** `SessSchemaContractTest` javadoc asserted the deleted "Gateway (tolerant
  reader) … Lua-side reader has its own check" contract. Reworded to the
  Auth-Service-private writer-binding pin. **FIXED-2026-06-12.**
- **DD3** `SPEC-0001` Appendix A.3 told you to "replace the `resty.redis` block in
  `bff-session.lua`'s `read_session`" (neither exists) and listed
  `sess-payload.example.json` as an unchanged cross-component contract
  (contradicting §7.2). Rewritten: store swap is Auth-Service-only; the gateway
  holds no store client. A.1's cross-component-contracts line corrected likewise.
  **FIXED-2026-06-12.**
- **DD4** `README.md` architecture table said the gateway owns "`sess:{sid}` lookup."
  Changed to "sid resolution via `/internal/resolve` (holds no session-store
  handle)." **FIXED-2026-06-12.**
- **DD5** `SecurityConfigTest` carried stale `internal.refresh` *scope* comments and
  a method named `…WithoutInternalRefreshScope` (code uses audience+azp, no scope).
  Renamed to `…WithWrongCaller`, comments corrected to audience+azp, the
  `scope=some.other.scope` red herring removed. **FIXED-2026-06-12.**
- **DD6** `production-hardening.md` SPOF section enumerated Valkey but not the new
  Auth-Service hot-path availability SPOF. Added the paragraph (Auth Service is now
  as load-bearing as Valkey; front `/internal/resolve` with pooling + a breaker).
  **FIXED-2026-06-12.**

---

## E. Informational

- **E1 — `review-backlog-2026-06-11.md` now reads as a changelog, not a backlog**
  (all items `[done]`). Consider retitling it "Review Resolution Log (2026-06-11)"
  or archiving it; this 2026-06-12 file is the live list. `REF`, Info, OPEN.
- **E2 — Phantom-token ADR over-justifies in spots** (the pattern-conformance
  paragraph restates "Auth Service is the only component that touches the store"
  ~4×). Stylistic; trim ~40% if touched. No invented precision found — all TTLs /
  timeouts / grace values match code. `REF`, Info, OPEN.

---

## Recommended order

1. **N1 + N2 (High):** connection pooling + circuit breaker on `/internal/resolve`
   — the only items I'd treat as blocking before running the reference under real
   `/api` load. The new topology made both load-bearing.
2. **N3 + C1 (Medium):** breadcrumb-before-move (or atomic rotation script) and the
   test proving the old sid dies after the grace window.
3. **N4 (Medium):** shrink the 30s rotation grace to the real in-flight budget.
4. **N5–N8, B1–B3, C2–C3, E1–E2 (Low/Info):** opportunistic cleanup.
