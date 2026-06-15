# Reference hardening — design notes for review

**Status:** Draft, for review. Nothing here is implemented yet.
**Date:** 2026-06-15.
**Author:** raised during a "would you adopt this as the canonical BFF shape"
review.

## What this is and what I'm asking

A review of the repo as "the reference shape a new security hire implements and
production-hardens against" surfaced four items that are not bugs in the running
system but are places where the *reference* either oversells a property or lets a
copying engineer reproduce a weaker version by accident. Each section states the
issue with file:line, why it matters for a reference (not just for this repo),
the current state, a proposed approach with options and a recommendation, and a
verification plan.

Reviewers: please weigh in on **scope** (which of these belong in the core
reference vs. a downstream hardening fork) and on the **recommended approach** in
each section. Two of these (§1, §3) are small and self-contained; §2 changes a
public configuration surface; §4 closes a parity gap that is half-done already.

The items are independent — they can be accepted, deferred, or rejected
individually.

---

## 1. ID-token `at_hash` derives its hash algorithm from the token's own header

### Issue
`JwtOidcIdTokenValidator.enforceAtHash` validates the access-token hash binding
using the algorithm read from the ID token's own JWS header:

- `auth-service/.../JwtOidcIdTokenValidator.java:152-154` —
  `AccessTokenValidator.validate(..., signed.getHeader().getAlgorithm(), claimed)`.

The hash function used to check `at_hash` (the only cryptographic binding between
the ID token and the access token) is therefore taken from a field inside the
object being validated.

### Why it matters
As written this is **not exploitable**: the signature key selector is pinned to
RS256 at `JwtOidcIdTokenValidator.java:59`
(`new JWSVerificationKeySelector<>(JWSAlgorithm.RS256, jwks)`), so only an
RS256-signed token reaches `enforceAtHash`, and RS256 fixes the `at_hash`
function to SHA-256. The safety of the `at_hash` check is real, but it is
**load-bearing-coupled** to a pin set in a different method, with nothing at the
`at_hash` site asserting the relationship.

For a reference a hire copies, "derive a security-relevant hash algorithm from a
field in the credential you are validating" is the alg-confusion pattern. A
plausible future change — loosening the key selector to accept the provider's
advertised algorithms (see §2) — silently re-opens it, because the `at_hash` site
will then trust whatever `typ`/`alg` the token carries.

### Current state
Correct, but the coupling is implicit and undocumented at the `at_hash` site.

### Proposed approach
Make the coupling explicit and fail-closed at the point of use. Options:

- **A (recommended): assert the header algorithm against the pinned/allowed set
  before using it for `at_hash`.** Before calling `AccessTokenValidator.validate`,
  check `signed.getHeader().getAlgorithm()` is in the same allow-list the key
  selector enforces; reject otherwise. This keeps `at_hash` safe even if the key
  selector is later widened, and documents the invariant in code.
- **B: pass the expected algorithm explicitly** rather than reading it from the
  header — derive the `at_hash` algorithm from the pinned signing algorithm, not
  from the token. Strongest, but couples `at_hash` to the §2 outcome.
- **C: comment only.** Document that `at_hash` safety depends on the RS256 key-
  selector pin and that the two must move together. Cheapest, weakest — relies on
  the next editor reading the comment.

Recommend **A**, and revisit toward **B** if §2 lands (so the allowed-algorithm
set has a single source of truth).

### Verification plan
Add a negative unit test: an ID token whose header advertises an unexpected
algorithm for the `at_hash` computation is rejected at `enforceAtHash`, not
silently accepted. The existing `JwtOidcIdTokenValidatorTest` at_hash cases
(present/absent/mismatch) stay green.

---

## 2. RS256 is hard-pinned in five places — the "swappable IdP" claim oversells

### Issue
The accepted JWS signature algorithm is a compile-time constant in five
selectors across both services:

- `auth-service/.../JwtOidcIdTokenValidator.java:59` — ID-token signature.
- `auth-service/.../SecurityConfig.java:68` — gateway client-credentials token
  decoder (`internalJwtDecoder`).
- `auth-service/.../BackChannelLogoutTokenValidator.java:135` — logout-token
  signature.
- `backend-resource-server/.../SecurityConfig.java:112` and `:117` — the two
  access-token decoders.

### Why it matters
This is **fail-closed** — an ES256/PS256 IdP is rejected, not silently trusted —
so it is a portability cliff, not a vulnerability. But the reference documents
"IdP swappable by configuration." Pointing it at an Entra, Auth0, or Okta tenant
that signs with ES256 or PS256 makes every login fail signature validation with
no obvious cause and **no configuration knob to fix it** — the fix is a code
change in five places. For a reference whose headline includes provider
portability, that is a gap a hire discovers the hard way.

### Current state
RS256 only, by constant, in five selectors. Documented honestly in
`docs/operations/provider-adapters.md` / architecture decisions as a known code-
change point, but not configurable.

### Proposed approach
Make the accepted JWS algorithm set a validated configuration field, defaulting
to RS256 so the fail-closed default is unchanged.

- Add `app.id-token-jws-algs` (and the corresponding access-token / logout-token
  knobs, or one shared `app.accepted-jws-algs`) to `AuthProperties` /
  `AppProperties` as a validated, non-empty `Set<JwsAlgorithm>` with
  `@DefaultValue` RS256.
- Apply it to all five selectors from the single configured set.
- Validate at boot (reuse the record compact-constructor pattern): reject an
  empty set, reject `none`, reject unknown algorithm names — fail closed on
  misconfiguration rather than silently accepting nothing.

Open question for reviewers: **one shared knob or per-token-type knobs?** The ID
token, the gateway CC token, and the access token can in principle be signed by
different issuers with different algorithms; a single knob is simpler but less
precise. Recommendation: one shared `app.accepted-jws-algs` for v1 (covers the
realistic "this IdP signs ES256" case), with per-type override deferred until a
concrete need appears.

### Verification plan
- Unit: binding defaults to RS256; an empty set, `none`, and an unknown name each
  fail boot.
- Portability gate: the existing alt-realm `e2e-portability.sh` proves RS256; add
  (or document as a manual matrix entry) an ES256-realm variant proving the knob
  actually switches the accepted algorithm end-to-end. Note this needs a Keycloak
  realm signing ES256, so it may belong in the provider-adapter matrix rather than
  the default battery.

---

## 3. Frontend storage-boundary lint has two known gaps; the real proof is the e2e

### Issue
The ESLint rule that forbids token storage in the SPA
(`frontend/eslint.config.js:45-101`) covers `localStorage`, `sessionStorage`, and
`indexedDB` writes in every direct spelling (member call, bracketed, window/
globalThis-qualified, assignment) — and a meta-test proves those spellings. Two
gaps remain:

- **Aliasing is not statically catchable** and is acknowledged in-rule
  (`eslint.config.js:51`): `const s = localStorage; s.setItem(...)` passes lint.
- **`document.cookie` writes are not covered at all** — there is no selector for
  `document.cookie = ...`, though the README explicitly discusses `document.cookie`
  as a token-exfiltration surface.

The authoritative proof that no token reaches the browser is the live e2e guard
`assertNoBrowserTokens()` in `frontend/tests/e2e/reference-flow.spec.ts`, which
sweeps `localStorage`, `sessionStorage`, IndexedDB, `document.cookie`, **and**
HttpOnly cookies via `context.cookies()`. That guard runs only under
`just e2e-auth` / `RUN_FULL_STACK_AUTH=1 verify-all`, **not** under
`verify-frontend` (which runs the SPA unit suite without the full stack).

### Why it matters
"Lint green" is not "no storage write," and a hire who treats the lint rule as
the guarantee — or who runs `verify-frontend` and assumes the leak guard ran —
is mistaken. The SPA cannot set HttpOnly cookies and the e2e would catch a
token-shaped value at runtime, so this is defense-in-depth and expectation-
setting, not an open hole. But a canonical boundary rule should ban what it can
and be explicit about what it cannot.

### Proposed approach
- **Add a `document.cookie` write selector** to the rule
  (`AssignmentExpression` with `left.object.name === 'document'` and
  `left.property.name === 'cookie'`), matching the existing assignment-selector
  style. Add a spelling to the meta-test.
- **State the alias limitation in the rule message** so a reader knows lint is a
  fast first line and the e2e is the backstop — rather than leaving it only in a
  source comment.
- **Documentation:** make explicit (README / verification-gates) that the token-
  leak proof lives in the live e2e and runs under `e2e-auth`/full-stack
  `verify-all`, not `verify-frontend`. This is expectation-setting, not a code
  change.

Reviewers: is `document.cookie` worth banning given the SPA can only ever set a
non-HttpOnly cookie (which the e2e already catches)? Argument for: a canonical
rule should be complete and self-documenting. Argument against: lint scope creep
for a case the runtime guard covers. Recommendation: add it — it is one selector
and removes a "why isn't this caught?" question.

### Verification plan
Extend `eslint-boundary.test.ts` with a `document.cookie = ...` case (must be
flagged) and confirm the existing spellings stay flagged. No change to the live
e2e guard, which already inspects `document.cookie`.

---

## 4. CSRF/HMAC cross-implementation parity is asserted on the Java side only

### Issue
The signed-CSRF token contract is HMAC-SHA256 over `token_value + ":" + sid`,
base64url no-padding, token = `value + "." + hmac`. Two implementations must
agree byte-for-byte:

- Java: `auth-service/.../SignedCsrfSupport.java` — HMAC at `:82-83`, message
  shape `value + ":" + sid` at `:94`, base64url-no-pad at `:18`, constant-time
  compare at `:41,:97`.
- Lua: `api-gateway/plugins/bff-session.lua` — `hmac_b64url` at `:363`, `csrf_ok`
  at `:388`, message `value .. ":" .. sid` at `:424`, base64url-no-pad via
  `ngx.encode_base64(digest, true)` at `:372`.

A committed cross-language fixture already exists at `schema/csrf-fixture.json`
(known key + sid + value → expected `hmac_base64url` and `signed_token`), and the
**Java side asserts against it** (`auth-service/.../CsrfFixtureTest.java`). The
gap is the **Lua side**: `api-gateway/tests/test-pure-fns.lua:5-7,17-19` stubs out
`resty.hmac` and notes that `hmac_b64url`/`csrf_ok` "are NOT present in bare
LuaJIT; they are covered end-to-end by the live signed-CSRF battery." So the Lua
HMAC's byte-level parity with the fixture is proven only by the live stack, not by
a fast unit assertion.

Separately, the inbound-`Authorization`-strip safety
(`bff-session.lua:99-107`, `:816-827`) depends on APISIX's `set_header` *overwrite*
(not append) semantics — the plugin comment says so explicitly — and a hire
porting to Kong/Envoy can get the strip-then-set ordering wrong.

### Why it matters
The edge-vs-policy boundary is otherwise clean (policy in copyable Java, mechanics
in swappable gateway config), but the CSRF *validation* is mechanics-in-Lua that a
hire re-implements per gateway. The two ways to get it wrong silently — a
different HMAC encoding, or appending the injected bearer instead of overwriting
an attacker-supplied one — are exactly the cases a fast, committed parity test
would catch.

### Current state
Fixture committed; Java asserts against it; Lua parity proven only by the live
battery; `Authorization` overwrite is a documented-but-untested assumption.

### Proposed approach
- **Close the Lua half of the fixture parity.** Add a Lua test that loads the
  real `resty.hmac` + `ngx.encode_base64` (run under `resty`/OpenResty in CI, or a
  thin harness) and asserts `hmac_b64url(key, value..":"..sid)` equals the
  fixture's `expected.hmac_base64url`, and that `csrf_ok` accepts the
  `expected.signed_token`. This makes byte-for-byte parity a tested invariant on
  both sides, not a prose claim plus a Java-only test.
- **Make the `Authorization` overwrite a live assertion.** The `gateway-test` echo
  controller already reports `value_count` and a SHA-256 fingerprint of the
  injected bearer. Add an e2e case: a request carrying its own
  `Authorization: Bearer <attacker>` must yield `value_count == 1` and a
  fingerprint matching the *injected* token, proving the strip-then-set actually
  overwrote rather than appended.
- **Documentation:** the fixture's `$comment` already says new implementations
  must add an equivalent test; make that a checklist item in the provider/gateway
  adapter docs.

Reviewers: the Lua test needs OpenResty in CI (the repo currently runs Lua pure-
fn tests under bare LuaJIT). Is adding an OpenResty step worth it, or is the live
battery sufficient given the fixture + Java assertion already pin the contract?
Recommendation: add the OpenResty parity test — it is the one fast guard that
fails if a gateway port drifts the HMAC, and it is the half currently missing.

### Verification plan
- Lua fixture parity test (new), asserting against `schema/csrf-fixture.json`.
- E2e `Authorization`-overwrite assertion via the echo controller's fingerprint.
- Existing `CsrfFixtureTest` (Java) and the live signed-CSRF battery stay green.

---

## Summary for reviewers

| # | Item | Type | Size | Recommendation |
|---|------|------|------|----------------|
| 1 | `at_hash` algorithm coupling | correctness hardening | small | assert header alg at use site |
| 2 | RS256 hard-pin | portability | medium (config surface) | one shared `app.accepted-jws-algs`, default RS256 |
| 3 | storage-boundary lint gaps | defense-in-depth + docs | small | add `document.cookie` selector; document e2e is the proof |
| 4 | CSRF/HMAC Lua parity | teachability + test rigor | small–medium (CI) | close Lua fixture parity; assert `Authorization` overwrite |

None of these block the reference being adopted as the shape; they are the spots
where "copy the reference" can produce a weaker result, ordered by how easily a
hire would hit them.
