# Review Backlog — Open TODOs

**Last updated:** 2026-06-12 · **Reviewed at:** git HEAD `2951672`.
**This is the single living backlog.** It supersedes and replaces the dated files
`review-backlog-2026-06-11.md` and `review-backlog-2026-06-12.md` (both deleted —
their items are either done or carried below).

This list is scoped for the next agent. **Scope rule:** this is a *reference*, not a
deployment. Only items in the substance a reader copies into a prod build are
TODOs — the OAuth/OIDC protocol logic, session-security semantics, the SPEC §7
wire contracts, the Auth Service / Resource Server / frontend code, and the tests
that pin them. Gateway-platform and deployment-infra concerns are **out of scope**
(see §Out of scope) — the APISIX/Lua gateway is swappable (Kong, AWS API Gateway,
Envoy/mesh), so we disclose infra requirements in `production-hardening.md` and do
**not** harden the throwaway infra.

**Status of the codebase:** no High/Critical issues in the copyable surface. The
sid-rotation revocation race (N3) is fixed and verified; all prior security
controls and doc-drift fixes held. What remains is one Medium contract-doc drift
plus Low comment/test/doc-hygiene.

---

## Priority — reference fixes for the next agent

### P1 — SPEC §7.1 `/internal/resolve` success-response omits the rotation fields — `REF`, **Medium** — DONE 2026-06-12
**Fixed.** Added `rotated_sid` / `rotated_sid_max_age` / `rotated_csrf` (marked "present
only on rotation," authoritative snake_case) to the §7.1 success-response block, with the
gateway's MUST-re-issue-both-cookies obligation; updated the §7.1 gateway-handling table
(200 row), pseudocode step 11, and the §A.2 gateway-swap wire contract #1 to match.
**Why.** The contract block in SPEC-0001 §7.1 (~`:690-692`) documents the 200 body as
only `access_token` + `access_token_expires_at`, but the actual `ResolveResponse`
(`InternalResolveController.java`, `record ResolveResponse`) emits **five** fields:
adds `rotated_sid`, `rotated_sid_max_age`, `rotated_csrf` (present only when this
resolve rotated the sid). A gateway implementer copying the documented contract —
exactly the audience for a reference — would never re-issue the rotated cookie/CSRF
and would silently break A6 sid-rotation on their gateway.
**What's needed.** Add the three fields to the §7.1 success-response JSON, marked
"present only on rotation," with the exact wire names. Note the prose says "cookie
max-age" while the wire name is `rotated_sid_max_age`. Cross-check the gateway-role
contract in §A.2 mentions consuming them.
**Where.** `docs/specs/SPEC-0001-core-oidc-flows.md` §7.1 success-response block.

### P2 — C1 "old-sid-dies" test has a teeth gap — `REF`, **Low–Medium** — DONE 2026-06-12
**Fixed.** The C1 test now asserts `ttl(rotated:{sid})` is positive AND `<= 10s` right
after the rotation (before the hand-delete), so a mutation of `ROTATION_GRACE` to the
idle/absolute TTL fails the Java suite. Teeth proven by widening the constant to 1800s
(test went red on the grace pin), then reverted.
**Why.** `InternalResolveControllerTest` (the old-sid-after-grace test, ~`:416-417`)
deletes the breadcrumb **by hand** instead of letting its TTL lapse, so it proves
(a) old sid resolves while the breadcrumb lives, (b) 404s once it's gone, (c) the new
session is unaffected — but it would **still pass if `ROTATION_GRACE` were set to the
absolute ceiling**, the exact regression the test names. The 10s binding is asserted
only by the code literal at `InternalResolveController.java:233`.
**What's needed.** In the same test, after the first rotation assert
`stateStore.ttl("rotated:" + sid)` is `<= ROTATION_GRACE` (≈ ≤10s), so a mutation of
the grace value to the idle/absolute TTL fails the Java suite.
**Where.** `auth-service/.../InternalResolveControllerTest.java`.

### P3 — Stale comment contradicts the shipped N3 fix — `REF`, **Low** — DONE 2026-06-12
**Fixed.** Reworded the `SessionIndexes.deleteLocalSession` breadcrumb-follow comment: the
"residual sub-millisecond window … Do-Later for HA" sentence (made false by `2951672`) is
gone, replaced by the accurate statement that the move + breadcrumb are one atomic op
(`rotateIfPresent`), so there is no window where `sess:{new}` exists without a breadcrumb.
**Why.** `SessionIndexes.java:130-132` still reads *"A residual sub-millisecond window
remains between the rotation's session move and its breadcrumb write; closing it
fully needs a single atomic move+breadcrumb, a Do-Later for HA."* Commit `2951672`
closed exactly that window (move+breadcrumb are now one atomic Lua op). This is the
file whose correctness the N3 argument hinges on, so a comment claiming the race is
still open is actively misleading — and comments are part of a reference's deliverable.
**What's needed.** Reword to: the move+breadcrumb is atomic (`rotateIfPresent`), so
after the move the breadcrumb is guaranteed present until consumed by the owning
sid's delete path; this follow is what kills the rotated-to session.
**Where.** `auth-service/.../SessionIndexes.java:130-132`.

### P4 — Pin the refreshed identity to the original session — `REF`, **Low/Info**
**Why.** On refresh, `sub`/`sid` are taken from the refresh response and re-indexed
(`AuthorizationCodeTokenRefreshClient` + `SessionIndexes.rotate`) without asserting
the refreshed `sub` equals the original session's `sub`. Low exploitability (the
refresh leg is client-authenticated, server-to-server — not attacker-reachable
without IdP/channel compromise), but a misbehaving IdP could change identity
mid-session. Cheap defense worth showing in a reference.
**What's needed.** After `validateRefreshed`, assert `refreshed sub == stored session
sub` (optionally that the IdP `sid` is unchanged); on mismatch throw
`InvalidRefreshTokenException` so the session fails closed.
**Where.** `auth-service/.../AuthorizationCodeTokenRefreshClient.java`.

---

## Other open reference items (Low / Info)

- **O1 — `RS is cookieless` as an explicit SPEC invariant.** `REF`, Low. On rotation
  the gateway sets `Set-Cookie`, which in APISIX replaces any upstream Set-Cookie —
  fine because the RS is cookieless, but currently implicit. State it in SPEC §7 (RS
  contract): "the Resource Server MUST NOT set cookies; the gateway owns the cookie
  jar." Any gateway impl then inherits it. (Was N6.)
- **O2 — 502/503 consistency on the CC-retry path.** `REF`, Low. A transport failure
  on the CC-token retry maps to 502 while the same failure on the first attempt maps
  to 503 (`bff-session.lua` resolve path) — the §7.1 status table says 503. Make the
  retry branch match the documented contract. (Impl-vs-own-SPEC drift; the contract is
  reference-level even though the impl is in the swappable gateway.) (Was N7.)
- **O3 — `rotateIfPresent` overwrite-on-collision note.** `REF`, Info. The rotate
  primitive `SET`s the new key unconditionally after the EXISTS-gate; safe only
  because `newSid` is a 256-bit token. One-line threat-model note that safety rests
  on newSid entropy. (Was N8.)
- **O4 — Audit-format constant not referenced by its test.** `REF`, Low. The
  `SecurityAudit` format constant is shared between the two `event()` overloads but
  `SecurityAuditTest` hardcodes the wire-format literal. Have the test build its
  expected line from the constant so a format change updates one place. (Was C6/B1.)
- **O5 — Record the "keep AuthController un-split" decision in code/ADR.** `REF`, Low.
  The decision currently lives only in a (now-deleted) backlog; add a one-line class
  note or ADR entry so it survives. (Was A5/B2.)
- **O6 — Final sweep relocating agent-process docs off the published surface.** `REF`,
  Low. Mostly done (`.agents/` gitignored, `AGENTS.md` cleaned, `CONTRIBUTING.md`
  added); confirm nothing left in the published tree describes the internal authoring
  workflow. (Was D5/B3.)
- **O7 — Live test that the 503 transient path keeps the cookie.** `REF`, Low. The
  502→503-keeps-cookie mapping is unit-tested (Lua) and the AS-side non-destructive
  502 is proven, but no end-to-end test drives a real transient AS failure and asserts
  cookie retained + `Retry-After`. Lower value (unit + AS tests bracket it). (Was C2.)
- **O8 — Re-comment the gateway TTL/ceiling tests to the right plane.** `REF`, Low.
  `test-gateway-behavior.sh` TTL/ceiling tests + `lib.sh` still carry "the slide that
  used to live in the gateway's Lua EXPIRE" framing; the slide now runs in the Auth
  Service behind `/internal/resolve`. Re-comment or consolidate with the
  `InternalResolveControllerTest` slide tests. (Was C3.)
- **O9 — Trim the phantom-token ADR's repetition.** `REF`, Info. It restates "the Auth
  Service is the only component that touches the store" ~4×. Stylistic; no invented
  precision (all TTLs/timeouts match code). (Was E2.)

**Closed / non-issue:** N5 (`hasExpectedCaller` accepts `azp` OR `client_id`) was
re-checked and is **acceptable** — both are pinned to the single configured gateway
client id and audience is independently enforced, so an attacker would already have
to be the gateway. Optional tightening only; not a TODO.

---

## Out of scope — infra / deployment layer (do NOT action in the reference)

Properties of the gateway platform / deployment infra, swapped wholesale in prod
(APISIX → Kong / AWS API Gateway / Envoy+mesh). Already disclosed in
`production-hardening.md`. Listed so the next agent does not re-raise them as defects:

- gateway→Auth-Service connection pooling (was N1); circuit breaker on the resolve
  RPC (was N2) — both are the chosen gateway/mesh's job, not application code.
- Session-store + Auth-Service HA / SPOF; observability & cross-tier correlation IDs;
  graceful shutdown; dependency-checked readiness probes; Valkey eviction policy &
  durability; supply-chain image pinning; rate-limit coverage; zero-downtime deploy.

The phantom-token "resolve on every request, no token cache" design (instant
revocation + single reader) is a deliberate, documented choice whose latency/availability
cost the chosen infra absorbs differently. Not relitigated.

---

## Done ledger (for context — do not re-open)

- **N3** sid-rotation revocation race — fixed in `2951672` (atomic move+breadcrumb in
  one Lua script; verified correct across all logout/rotation interleavings).
- **N4** rotation grace 30s → 10s — `2951672`; SECURITY S-5 updated.
- **C1** old-sid-dies-after-grace test + breadcrumb gone/absolute-expired branch tests
  — `2951672` / `175f8a7` (see P2 for the residual teeth gap).
- **DD1–DD6** phantom-token doc drift (gateway-reads-`sess:{sid}` claims) — fixed in
  `0a9ccfe`.
- **All 2026-06-11 backlog items** (A1–A6, B1–B7, C1–C6, D1–D6, E1–E8) — done with
  substance; the BCL reconciliation, version pins, dropped phantom `internal.refresh`
  scope, and superlative removal all held.
