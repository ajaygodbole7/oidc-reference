# Pending Design Decisions from the Staff-Engineer Review

These items came out of the cross-cutting staff review (architecture / code
quality / concurrency / OIDC RFC compliance / security) as **legitimately
ambiguous**: they have more than one defensible answer, and picking one
without input would entrench a choice that the project hasn't actually made
yet. Each entry below records the option space so the next maintainer
session can decide explicitly rather than having the implementation drift
into a position by accident.

Each decision is independent — they can be taken in any order, or
deferred individually.

---

## C1 — CSRF key rotation: dual-key acceptance window

**Spec status:** SPEC-0001 §7.3 promises a grace window where both the
current and previous CSRF signing keys validate. **Code status:** neither
`SignedCsrfSupport.java` nor `bff-session.lua` implements it. Rotation
today is a hard cutover; every in-flight session 403s during the swap.

**Options:**

1. **Implement dual-key acceptance.** Add `app.cookie-signing-key.previous`
   (and the equivalent gateway plugin field). Validator tries the current
   key first, then the previous, with constant-time short-circuiting.
   Issue tokens only with the current key. Drop the previous after the
   configured TTL. Adds ~30 LOC in Java and ~20 LOC in Lua, plus tests.
2. **Remove the rotation grace-window claim from SPEC-0001 §7.3.** The
   spec would then say "rotation requires a maintenance window that
   invalidates all in-flight CSRF tokens." Honest but worse UX.
3. **Document the gap** in SPEC-0001, tracking it explicitly without
   implementing yet.

**Recommendation:** (1) — the dual-key pattern is standard, the LOC cost
is small, and it's the kind of thing a real reference should demonstrate.

---

## C2 — Regenerate `sid` on refresh-token rotation

A once-leaked `sid` remains valid for the entire 12 h absolute window
through N token rotations. RFC 6265bis §8.6 and standard session-management
practice say rotate session IDs on privilege boundary changes.

**Options:**

1. **Rotate `sid` on every refresh.** Mint `sid'`, copy
   `sess:{sid}` → `sess:{sid'}`, `DEL sess:{sid}`, `Set-Cookie` for `sid'`.
   The browser sees a Set-Cookie on every refresh-window response. The old
   key is briefly orphaned (TTL clean-up handles it). Cleaner; defeats
   sid-leak replay across rotations.
2. **Rotate only on a privilege boundary** (logout-and-reauth, scope
   change, role change). The current code has no such boundary other than
   re-login, so this collapses to "no rotation."
3. **Leave as-is.** Document that `sid` is intentionally stable across
   refresh.

**Tradeoff:** (1) adds a Set-Cookie to every refresh response (acceptable),
but is invisible to the SPA since the gateway re-reads after refresh
anyway. The plugin needs no change; the cookie is set by the Auth Service
in the refresh response forwarded by the gateway. **Recommendation: (1).**

---

## C3 — Real circuit breaker in `bff-session.lua`

SPEC-0001 §"Timeout and circuit-breaker" mandates "rolling-window breaker
with half-open probe, 503 + Retry-After when open." The plugin has
request-level timeouts but no breaker state machine.

**Options:**

1. **Build it.** Roughly 150–200 LOC of Lua: rolling failure window in
   `ngx.shared.cc_token_cache` (reuse the dict), state machine with
   `closed | open | half_open`, single-probe acceptance in half-open.
   Per-upstream tracking (`auth_service_base`).
2. **Use APISIX's built-in `api-breaker` plugin** on the request path that
   calls `auth_service_base/internal/refresh`. Less code, less flexibility.
   Requires shifting some of the refresh-delegation logic out of
   `bff-session` into a separate route or chained plugin.
3. **Defer with a tracked task.** Document the gap explicitly in SPEC-0001
   and the backlog; ship without it.

**Recommendation:** (2) if APISIX's `api-breaker` semantics match what the
spec wants (it does, per APISIX 3.x docs). (1) is the build-from-scratch
fallback. (3) is acceptable for the current scope if we're honest about it.

---

## C4 — Move `realm_access.roles` Keycloak-specific path to config

**File evidence:** `JwtOidcIdTokenValidator.java:84–89` and RS
`SecurityConfig.java:108` both hardcode the `realm_access.roles` JSON path.
This breaks IdP portability the moment the IdP changes (Auth0 uses
`https://example.com/roles`, Cognito uses `cognito:groups`, Entra uses
`roles` flat, etc.).

**Options:**

1. **Add `app.claims.roles-path` config** (JSON Pointer or dotted path)
   and consume it from both validators. Adds ~50 LOC + tests + a
   `docs/reference/idp-portability.md` to sit alongside
   `refresh-rotation.md`.
2. **Leave hardcoded with a doc note** that this reference is
   Keycloak-pinned. Cheaper but contradicts the architecture overview's
   "swap IdPs" framing.
3. **Implement a minimal `RolesExtractor` strategy interface** with one
   `KeycloakRealmRolesExtractor` impl. Open for extension without yet
   doing the config plumbing.

**Recommendation:** (1) if portability is a goal; (2) if not. The README
should match whichever we pick. Right now it implies (1) but the code
ships (2).

---

## C5 — Log-format coupling in tests

~20 assertions of the form
`assertThat(output.getOut()).contains("event=foo").contains("reason=bar")`
pin the SLF4J wire format. Switching to JSON structured logging breaks all
of them simultaneously.

**Options:**

1. **Refactor to behavior-only.** Tests assert: session deleted, status
   code, response shape. Move format coverage to one focused
   `SecurityAuditTest` that owns the wire format invariant.
2. **Leave as-is.** Accept the brittleness as a deliberate design choice
   — "tests document the exact log format."
3. **Add a `SecurityAuditFormat` constant** that both the audit emitter
   and the tests reference. Format changes update one place, tests still
   pin via the shared constant.

**Recommendation:** (3) is the cleanest middle ground. (1) loses some
useful coverage; (2) blocks any future logging-stack migration.

---

## C6 — Lua plugin unit tests

719 LOC of Lua with no in-isolation tests for the constant-time compare,
ISO-8601 parser, CSRF HMAC validator, or CC-token cache stampede
protection. Integration tests via the gateway harness cover end-to-end
but not the isolated functions.

**Options:**

1. **Add `busted` or `resty.test` infrastructure.** New CI step, new
   test files alongside `bff-session.lua`. Real ongoing investment but
   the right answer for a 700-LOC security-critical Lua module.
2. **Extract testable pure functions** into a separate file
   (`bff-session-core.lua` for crypto + parsing + state-machine) and
   add tests for that subset only. Smaller cost; integration tests
   continue to cover the I/O paths.
3. **Defer with a tracked task** and accept the integration-only
   coverage.

**Recommendation:** (2) — the constant-time compare, ISO parser, HMAC
validator, and refresh state machine are pure functions that should be
unit-tested. The Valkey + HTTP paths legitimately stay in integration.

---

## C7 — `typ=at+JWT` validation at the Resource Server

RFC 9068 §2.1 RECOMMENDS access tokens carry `typ=at+JWT`. Keycloak emits
`typ=JWT` by default. The RS doesn't validate `typ`. Adding the check
defends against ID-token-as-access-token confusion.

**Options:**

1. **Configure Keycloak to emit `typ=at+JWT`** (per-client mapper) +
   validate at RS via a `JwtClaimValidator` on the `typ` header.
   Requires realm-file change.
2. **Validate at RS without changing Keycloak.** Reject anything that
   isn't `at+JWT`; existing Keycloak tokens then break. Not viable
   without (1) first.
3. **Skip.** The audience-pin defense (`aud=oidc-reference-api`) already
   prevents an ID token (which has `aud=oidc-reference-auth`) from being
   accepted at the RS. The `typ` check is defense-in-depth, not the
   only defense.

**Recommendation:** (1) for a "demonstrates current best practice"
reference. (3) if we're honest that the audience pin already covers the
threat.

---

## C8 — OIDC RP-Initiated Logout `state` round-trip

`AuthController.java:409` generates a random `state` for the logout
redirect but never validates it on the post-logout return. The
`post_logout_redirect_uri` lands at `/`, which is public — so there's no
exploit today. The pattern is incomplete vs. the OIDC RP-Initiated Logout
1.0 SHOULD.

**Options:**

1. **Stop emitting `state` on logout.** It's optional; omitting is
   cleaner than emitting-and-ignoring.
2. **Add a `/auth/post-logout-callback` handler** that validates the
   `state` against a short-TTL `tx_logout:{state}` entry and then 302s
   to the real post-logout URL. Needs a new endpoint and a new
   storage prefix.
3. **Document as known gap.**

**Recommendation:** (1) if we don't have a real reason to want the
state round-trip. (2) if "demonstrate full logout protocol" matters.

---

## C9 — Valkey AUTH / TLS and token-at-rest

**File evidence:** `auth-service/src/main/resources/application.yml` configures
`spring.data.redis` with host/port only (no `ssl.enabled`, no password);
`compose.yaml` keeps Valkey on the internal Compose network with no `requirepass`.
`SessionRecord` persists the full `access_token` / `refresh_token` / `id_token`
to Valkey as plaintext JSON. Acceptable for the single-tenant local reference;
dangerous if a deployment points `SPRING_DATA_REDIS_HOST` at a shared/managed
Valkey without re-securing it. This is the **Do-Next "Redis AUTH/TLS guidance"**
item from the scope bar, surfaced by the 2026-05-31 review.

**Options:**

1. **Add an `ssl:`/password toggle + a hardening note.** Wire
   `spring.data.redis.ssl.enabled` + `password` through env, default off for
   local dev, and document "trusted+encrypted Valkey required outside
   loopback" in SECURITY.md. ~10 LOC + docs.
2. **Field-level encryption of token columns** in `SessionRecord` (envelope
   encryption with a KMS-held key). Demonstrates token-at-rest protection but
   adds key-management surface the reference deliberately keeps out of scope.
3. **Document only.** Keep the loopback assumption explicit and defer transport
   /at-rest protection to the deploying team.

**Recommendation:** (1) — small, matches the sentinel-pattern philosophy
(safe local default, explicit knob for real deployments). (2) is Do-Later.

---

## C10 — Gateway accepts the bare `sid` cookie on `scheme == "http"`

**File evidence:** `bff-session.lua` `get_session_cookie` honors the unsigned,
non-`__Host-` `sid` cookie whenever `ngx.var.scheme == "http"`. Intended as a
local-dev affordance (SPEC §"Session Cookie"), but a TLS-terminating LB that
forwards plaintext to APISIX presents `scheme == "http"` in production, dropping
the `__Host-` origin/Secure guarantee. Tied to the **Do-Next "TLS termination /
mTLS guidance"** item.

**Options:**

1. **Gate the bare-`sid` acceptance on an explicit dev flag** (plugin config
   `allow_insecure_sid = true`) instead of inferring from `scheme`. Production
   never sets it; the `__Host-` prefix is then mandatory.
2. **Require the deployer to forward `X-Forwarded-Proto` and key off that**
   rather than the listener scheme. More moving parts.
3. **Document only** — note the loopback/dev assumption and the TLS-terminator
   caveat in SECURITY.md.

**Recommendation:** (1) — a single explicit toggle is safer to copy than a
scheme inference and keeps the `__Host-` guarantee on by default.

---

## C11 — Gateway strips only `Authorization`, not client identity headers

**File evidence:** `bff-session.lua` clears `Authorization` + transport
hop-by-hop headers before injecting the session's bearer, but does not strip
inbound identity headers (`X-User`, `X-Forwarded-User`, `X-Roles`, …). The RS
does not currently trust such headers, so there is no exploit today; this is
defense-in-depth for the gateway-as-security-boundary invariant.

**Options:**

1. **Strip a positive identity-header set** before injecting gateway context,
   so a future RS change that trusts `X-User` can't be reached by a
   client-supplied header. ~5 LOC + a gateway-behavior test using the
   `gateway-test` Resource Server echo endpoint.
2. **Document the contract** ("the RS MUST ignore all client-supplied identity
   headers; the gateway only guarantees the bearer") and rely on RS discipline.
3. **Both** — strip-list now, document the contract too.

**Recommendation:** (3). The strip-list is cheap and the contract is worth
writing down regardless.

---

## C12 — `callApi` is GET-only and omits CSRF

**File evidence:** `frontend/src/auth.ts` `callApi` is the SPA's general
`/api` client but hardcodes a credentialed GET with no method/body and no
`X-XSRF-TOKEN`. Any future state-changing call routed through it would be
rejected by the gateway CSRF contract, with no parameter to supply the method
or header — a silent dead-end rather than a live bug (the only state-changing
call today, `signOut`, attaches the header correctly).

**Options:**

1. **Generalize `callApi(path, { method, body })`** and attach
   `readCsrfCookie()` as `X-XSRF-TOKEN` for unsafe methods. ~10 LOC + tests.
2. **Leave GET-only and document** that state-changing calls must go through a
   dedicated helper that mirrors `signOut`'s CSRF handling.
3. **Defer** until a real POST-through-`/api` use case exists.

**Recommendation:** (1) when the first mutating `/api` call lands; (3) until
then. Either way, not a live defect.
