# SPEC-0002 — CSRF session-binding, scope-honesty, and live OAuth 2.1 / OIDC conformance tests

Status: ready for implementation. Author: reviewer. Implementer: the other agent.
This spec is the authoritative contract for this change; GOAL packets are not.

## Purpose

Two outcomes, in priority order:

1. **The contract docs describe exactly what the code does.** Implement the one
   security gap that belongs to the reference (session-bound CSRF), scope out the
   two operational features that don't (circuit breaker, CSRF key grace-window
   rotation), and fix the residual mislabels.
2. **The tests prove the OAuth 2.1 / OIDC security behaviors against the live
   stack — positive and negative — not just the happy path on default config.**
   The real Keycloak / APISIX / Valkey / browser infra exists so the code can be
   shown to survive real-world adversarial scenarios. Today the negatives live in
   mocked unit tests and the live suite is happy-path on defaults. That is the gap.

## Out of scope

DPoP, PAR/JAR, FAPI, mTLS, token-at-rest encryption, multi-replica distributed
refresh lock, OpenTelemetry. These are production-hardening, documented as such.
Do not add them here.

---

## Part A — Code changes

### A1. Session-bound signed CSRF (IMPLEMENT)

Current: CSRF token = `value · base64(HMAC(key, value))`; validation is
`cookie == header` plus signature. Not bound to the session — any validly-signed
token validates against any session.

Change: bind the token to the session id.

- **Issue** (auth-service, at callback, where `sid` is known):
  `token = value · base64(HMAC(key, value + ":" + sid))`.
- **Validate** (auth-service `/auth/logout`, and gateway `bff-session.lua` on
  state-changing methods): recompute `HMAC(key, value + ":" + sid)` where `sid`
  comes from the `__Host-sid` / `sid` cookie already present on the request.
  Reject on mismatch.
- No new store read is added. `sid` comes from the parsed `__Host-sid` / `sid`
  cookie, not the Valkey record — the binding needs only the cookie, which the
  plugin already parses. Keep the existing plugin ordering (today the session read
  precedes CSRF validation); binding to the parsed `sid` requires no reordering.
- Signer (Java) and validator (Lua) MUST agree byte-for-byte on the
  `value + ":" + sid` construction, exactly as they agree on the key today.

Acceptance: a token issued for session A fails validation when presented with
session B's `sid`; a tampered value or signature is rejected; the legitimate
same-session token passes.

### A2. Compose forwards every documented knob (FIX)

`.env.example` and `provider-adapters.md` advertise knobs the containerized stack
silently ignores (no `env_file:`, so only vars named in `environment:` reach the
container).

- auth-service `environment:` — add, as `${VAR:-default}`:
  `AUTH_CLIENT_ID`, `OIDC_SCOPES`, `OIDC_ROLES_CLAIM_PATH`,
  `APP_REFRESH_REQUIRE_ROTATION`, `SESSION_IDLE_TTL`, `SESSION_MAX_TTL` (A4).
- APISIX render — `SESSION_IDLE_TTL` must also reach the gateway plugin
  (`idle_ttl_seconds`) through `render-apisix-config.sh`, defaulted, exactly like
  `GATEWAY_CLIENT_ID` (A4).
- resource-server `environment:` — change `OIDC_AUDIENCE: oidc-reference-api`
  (literal) to `${OIDC_AUDIENCE:-oidc-reference-api}`; confirm
  `OIDC_ROLES_CLAIM_PATH` is forwarded.

Defaults MUST be byte-for-byte unchanged; the default stack stays identical.

Acceptance: `docker compose config` with each var overridden on the host shows the
override in the resolved auth-service / resource-server environment.

### A3. Gateway honors `X-Forwarded-Proto` (FIX)

`bff-session.lua` keys its cookie-scheme decision off `ngx.var.scheme`; the
auth-service honors `X-Forwarded-Proto`. Behind a TLS-terminating LB that forwards
plaintext, this splits. Make the gateway prefer `X-Forwarded-Proto` when present,
falling back to `ngx.var.scheme` — matching the auth-service. (Pairs with the
`allow_insecure_sid` decision in `review-decisions-pending.md` C10 — a different
C-list from this spec's tests; at minimum, end the asymmetry and document it.)

Acceptance (live, in the gateway-behavior suite): a request with
`X-Forwarded-Proto: https` to the plaintext-listener gateway is treated as secure
by the cookie-scheme decision, matching the auth-service; without the header it
falls back to the listener scheme. Extract the scheme resolution into a testable
function if needed.

### A4. Session idle window slides on activity, never on a liveness probe (FIX)

Principle: the idle timeout measures **user inactivity**, so only genuine user
activity (`/api/**` traffic) slides it. A background `/auth/me` liveness poll must
NOT extend the session. The absolute ceiling (8h) is always honored.

Today this is inverted: the auth-service `session()` helper slides the TTL on
every read (`AuthController:393`), so `/auth/me` extends the session — while the
gateway is a read-only tolerant reader, so real `/api/**` activity does NOT slide
it (except indirectly when a call triggers a refresh).

Change:
- **Gateway slides on `/api/**`:** on each authenticated `/api` request, after the
  session read, issue `EXPIRE sess:{sid} min(idle_ttl, remaining_absolute)`. The
  gateway reads `absolute_expires_at` from the session (it is already a tolerant
  reader) to compute the cap, so it can never extend past the ceiling. This is a
  TTL touch, not a content write — the auth-service stays the sole **content**
  writer.
- **Auth-service stops sliding on read:** remove the `EXPIRE` from `session()`
  (`AuthController:393`). `/auth/me`, logout reads, etc. become pure reads.
- **Absolute ceiling:** both writers cap at `remaining_absolute`; the gateway must
  enforce it (treat a session past `absolute_expires_at` as 401, and never
  `EXPIRE` beyond it).

**Both TTLs MUST be configuration, not hardcoded constants.** Today
`SessionRecord.SESSION_IDLE_TTL` (30m) and `ABSOLUTE_TTL` (8h) are literals;
make them config-driven and forward them through the whole chain:

Both env vars are **integer seconds** — one unambiguous unit that the Java side
(`Duration.ofSeconds`) and the Lua plugin (`EXPIRE` seconds) consume as the
*identical number*, so "both planes agree" is exact, not a parse coincidence.
(`app.session-refresh-window` stays its existing `60s` Duration form; the new
TTLs are seconds because they cross the Java↔Lua boundary.)

| Value | Env (integer seconds) | Reaches | Used by |
|---|---|---|---|
| Idle TTL | `SESSION_IDLE_TTL` (default `1800`) | auth-service `app.session-idle-ttl` **AND** APISIX plugin `idle_ttl_seconds` (via the render) | auth-service `SessionRecord.nextTtl()` and the gateway `EXPIRE` — **both planes must agree**, same as `GATEWAY_CLIENT_ID` |
| Max (absolute) TTL | `SESSION_MAX_TTL` (default `28800`) | auth-service `app.session-absolute-ttl` only | auth-service stamps `absolute_expires_at` at session creation; the gateway reads the stamp, so it needs no separate value |

- Forward both in `compose.yaml` as `${VAR:-default}` (per A2). Wire the idle value
  into `apisix.yaml.template` plugin conf (`idle_ttl_seconds: ${SESSION_IDLE_TTL}`)
  through `render-apisix-config.sh`, defaulted, exactly like `GATEWAY_CLIENT_ID` —
  the same integer reaches both planes, no conversion. Add `idle_ttl_seconds` to
  the `bff-session.lua` plugin **schema** (integer) so the conf validates.
- The idle value MUST agree across auth-service and gateway. If they diverge, the
  session slides by two different windows — name this trap in the docs and catch
  it with the C9 test.
- Keep the C14 invariant: `SESSION_MAX_TTL` ≤ the IdP SSO max session lifespan;
  carry the provider-swap checklist note.

Net: the session lives exactly as long as real `/api` connectivity keeps it
alive, bounded by the configured max; `/auth/me` is a non-extending liveness probe.

Acceptance: with **non-default** `SESSION_IDLE_TTL` / `SESSION_MAX_TTL`, a session
polled only via `/auth/me` idles out at the configured idle bound (no extension);
a session with steady `/api` activity stays alive up to — and not past — the
configured max; `docker compose config` and the rendered `apisix.yaml` both show
the overridden values. Proven live (C9), not just unit-tested.

### A5. OIDC Back-Channel Logout — IdP-driven session revocation (IMPLEMENT)

Default revocation is IdP-driven and real-time. Implement OpenID Connect
Back-Channel Logout 1.0 (an OpenID Foundation spec, server-to-server).

- **Endpoint:** `POST /backchannel-logout`, content-type
  `application/x-www-form-urlencoded`, body field `logout_token`. Register its URL
  as the Keycloak client's `backchannel_logout_uri`. Reachable by the IdP
  (server-to-server); no browser cookie involved — the signed token is the
  authority.
- **Validate `logout_token`** (a JWT) per the spec: signature via the IdP JWKS,
  `iss`, `aud` = this client id, `iat` fresh, an `events` claim containing
  `http://schemas.openid.net/event/backchannel-logout`, a `sub` and/or `sid`
  present, and **no `nonce`** (distinguishes it from an id_token). Optional `jti`
  replay guard.
- **Map IdP session → local session:** at login, write a small index
  `idp_sid:{idp_sid} → {local sid}` (the id_token carries the IdP `sid`). On a
  valid logout token, look up the local `sid`(s) and `DEL sess:{sid}` (and the
  index entry). If only `sub` is present, delete all of that subject's sessions.
- **Enforcement is free:** both `/api/**` (gateway) and `/auth/me` (auth-service)
  read `sess:{sid}` on every request, so deleting it kills the session on the very
  next request through either door. No per-door logic.
- Respond `200` on success, `400` on an invalid/unverifiable token. Never reveal
  whether a session existed.
- **Enablement (will silently no-op otherwise):** the Keycloak client must have
  "Backchannel logout session required" ON so `sid` is stamped into the id_token
  AND the logout_token — without it the index can't map IdP session → local
  session. Register `backchannel_logout_uri` at the internal auth-service URL
  (`http://auth-service:8081/backchannel-logout`); the IdP reaches it on the
  Compose network, no host port. The endpoint sits on the Order-2 permitAll chain
  (no session/CSRF — the signed token is the authority).

Acceptance: a valid back-channel logout for an active user → the user's next
`/api/**` AND next `/auth/me` both return 401; an invalid/forged `logout_token` →
400, session untouched.

### A6. Short access-token TTL (CONFIG + DOC)

Revocation in this reference is **session revocation, and it is instant.** An IdP
back-channel logout or a session delete (A5) removes `sess:{sid}`, and the gateway
401s the very next `/api/**` or `/auth/me` request. There is no separate, slower
"entitlement" path — to take access away in real time, you revoke the session.

Short access-token TTL addresses a different, narrower thing: the Resource Server
is **stateless** and trusts a valid JWT until it expires. An access token minted
*before* revocation therefore stays technically valid at the RS until its own
expiry (the browser never holds it and can't reach the RS directly, but the
token's validity window is real). Keep that window small.

- Set the realm access-token lifespan to ~2 minutes; name the value in the realm
  JSON and document it. On refresh the auth-service re-validates a fresh id_token
  and updates `sess.claims` (`AuthorizationCodeTokenRefreshClient:83-89`), so any
  role change the IdP makes is reflected on the next refresh.
- Do NOT implement instant role-strip-without-logout — it requires stateful
  per-request authorization that defeats the stateless RS model. If a role must be
  revoked immediately, model it as a **session revocation** (A5), which is instant.
- Document the contract honestly and without hedging: **to revoke access, revoke
  the session — it takes effect on the next request. An access token already
  issued remains valid at the RS for at most its (short) lifetime.**

### A7. Multi-tab / concurrent login must not break (IMPLEMENT — was C16)

`OAuthTxBinding` uses a single fixed cookie name `oauth_tx`; `beginLogin`
overwrites it on every `/auth/login`. A second concurrent login (open-in-new-tab,
middle-click a protected link, back/forward, a stale tab retrying) clobbers the
first tab's cookie, so the first tab's callback fails the browser-binding check
with a hard `400`. Open-in-new-tab is normal user behavior; this is a real
flow-robustness bug, not an edge case.

Fix: scope the binding **per transaction**, not per browser.
- Name the cookie per `state`: `oauth_tx_<short-stable-hash(state)>`, same
  attributes (HttpOnly, SameSite=Lax, Path=/auth/callback/idp), `Max-Age` = the
  `tx:{state}` TTL (5m) so abandoned-login cookies self-expire.
- The callback already receives `state` in the query; it computes the expected
  cookie name, reads that specific cookie, verifies its HMAC against
  `tx:{state}.tx_cookie_hash` exactly as today, and evicts only that cookie on
  completion (success or failure).
- Threat model is unchanged — still browser-bound, still single-use per
  transaction. The only thing removed is the "one in-flight login per browser"
  limitation.

Acceptance: two `/auth/login` flows started concurrently from the same browser
each complete their own callback successfully; neither clobbers the other; each
transaction's cookie is single-use and evicted on its callback.

### A8. Logout must terminate the IdP SSO even with no local session (IMPLEMENT — was C17)

When the local `sess:{sid}` is already gone (idled out, or deleted), `/auth/logout`
returns `401` and never drives the IdP `end_session`, so the Keycloak SSO cookie
survives → "I logged out but the next sign-in silently SSO's me back in" on a
shared/kiosk machine. A5 (back-channel logout) is IdP→app and does NOT cover this
user-initiated case.

Fix: a logout request with no local session still drives IdP logout.
- Build the `end_session` URL with `client_id` + `post_logout_redirect_uri` (no
  `id_token_hint` is available, and it is optional — `client_id` identifies the
  RP), stash it under the same single-use `logout:{handle}` and return the
  same-origin `logoutUrl`, exactly as the with-session path does.
  `post_logout_redirect_uri` is the **fixed registered value, never request
  input** — no open redirect.
- CSRF: with no session there is nothing to protect, and forcing a logout is not a
  meaningful attack — do NOT require signed CSRF on the no-session branch
  (requiring a token the anonymous client cannot have would just re-break logout).
  Document this branch explicitly.
- Net: `/auth/logout` always terminates the IdP SSO, whether or not a local
  session still exists.

Acceptance: `POST /auth/logout` with an expired/absent local session returns a
`logoutUrl` that, when followed, terminates the Keycloak SSO session — the next
sign-in prompts for credentials rather than silently re-authenticating.

---

## Part B — Doc scope-honesty

### B1. Scope out the two ops features (do NOT implement)

- **Circuit breaker** — remove the delivered-contract framing from SPEC §7.1 and
  GOAL-0005. State the implemented behavior (per-request connect/read timeouts +
  status mapping) and name APISIX's built-in `api-breaker` plugin as the
  production primitive, as a documented Do-Later.
- **CSRF key grace-window rotation** — remove the "documented grace-window
  procedure" claim from GOAL-0004 and SPEC §7.3. State single-key with a hard
  cutover; note dual-key acceptance as a backlog item.

### B2. Fix the two contract-doc lines

- **SPEC §7.2** — A1 makes the CSRF token genuinely session-bound, so the
  session-bound *property* stops being an overclaim. But §7.2 also describes the
  wrong *mechanism*: "cookie matches header matches **stored**" implies a
  comparison against the stored `xsrf_token`, which the code never does and A1
  does not add — A1 binds cryptographically via `HMAC(value + ":" + sid)`,
  verified with **no** session-store read. Correct the wording to the real
  mechanism (signed double-submit, session-bound by HMAC, stateless to validate),
  and decide the stored `xsrf_token` field: if nothing reads it after A1, drop it
  from the schema rather than keep dead state.
- **README:208** — the 409 outcome is `refresh_token_rejected` /
  session-invalidated on `invalid_grant`, NOT "reuse detection." Keep "reuse" only
  as a realm-feature mention, never as what the 409 *means*.

### B3. GOAL packets are build-intent, not contract

Either bring each GOAL in line with the shipped code, or add a one-line banner:
`Build packet — SPEC-0001 + code are the authoritative contract.` A future agent
must not mistake a GOAL for the spec. At minimum fix GOAL-0001:122 ("callback
landing page" → direct 302, no landing page).

---

## Part C — Live OAuth 2.1 / OIDC conformance tests (the main work)

**Principle:** a security-critical behavior is proven against *real* Keycloak
tokens and *real* Keycloak error responses — not a fabricated `Jwt`. Mocked unit
tests remain as fast logic checks, but every behavior in the matrix below MUST
also have a live assertion against the running stack. Extend `e2e-auth.sh` / the
gateway + Playwright harness, or add `scripts/e2e-conformance.sh`.

### C1. Authorization Code + PKCE — negatives (live)
- state mismatch / unknown state → callback rejected, no session minted.
- missing or wrong `oauth_tx` browser-binding cookie → 400, no session.
- `iss` mismatch on callback (RFC 9207 mix-up) → rejected.
- replayed `(code, state)` (second callback, same code) → rejected.
- expired `tx:{state}` (past 5m) → rejected.
- PKCE: code redeemed without the matching verifier → token endpoint rejects;
  assert the flow fails closed.

### C2. ID-token validation — negatives, real tokens (live)
Through the real decoder + real JWKS, assert the auth-service rejects: wrong
`aud`, wrong `iss`, expired, bad `nonce`. Where a property can't be driven from
Keycloak directly, drive it via a second realm / key and assert the real decoder
rejects — not a synthetic JWT.

### C3. Resource Server JWT validation — negatives, real tokens (live)
- wrong audience → 401 at RS through the gateway.
- expired access token → 401.
- token signed by a different realm/key (wrong issuer/JWKS) → 401.
- `alg=none` / HS256-confusion attempt → rejected.
- valid token, insufficient scope/role → 403 (extend beyond the existing admin
  case with a scope-gated 403).

### C4. Refresh + rotation — real Keycloak (live)
- happy refresh: access token rotated, `access_expiry_extended` (exists — keep).
- real `invalid_grant`: revoke at Keycloak (admin API, or a second login that
  invalidates the first), trigger refresh → 409, session DELeted, audit event
  `refresh_token_rejected`.
- refresh-token-expired short-circuit → clean 404, no Keycloak call.
- concurrency: two simultaneous refreshes on one `sid` → exactly one upstream
  call (the per-session lock).

### C5. CSRF — live, including session-binding (A1)
- state-changing request with no `X-XSRF-TOKEN` → rejected.
- forged / garbage HMAC → rejected.
- unsigned (plain value) token → rejected.
- (after A1) valid token from session A replayed on session B → rejected.

### C6. Logout — live
- `/auth/logout` deletes the session; `/auth/logout/continue` 302s to Keycloak
  end-session with `id_token_hint`; after logout the Keycloak SSO session is
  actually terminated (next login prompts, not a silent SSO re-auth).
- **A8:** `/auth/logout` with an already-expired/absent local session STILL drives
  Keycloak end-session (via `client_id`, no `id_token_hint`) — assert the SSO is
  terminated (next sign-in prompts), not left alive.

### C7. Token isolation — live (exists; keep as a hard gate)
Playwright: after login, `localStorage` / `sessionStorage` / `document.cookie` /
IndexedDB contain no access / refresh / id token.

### C8. Non-default configuration — live (closes the highest config-drift risk)
The portability gate proves groups/alt-audience. Extend it (or add a variant) to
run with **non-default trust identifiers**: an alt realm whose gateway client id
and internal-refresh audience differ from the defaults, threaded through
`compose.portability.yml` + the APISIX render. Prove `GATEWAY_CLIENT_ID` /
`INTERNAL_REFRESH_AUDIENCE` are config-driven end-to-end, AND assert the negative:
a mismatched value (set on one side only) breaks `/internal/refresh`. This is what
turns the config knobs from "unit-tested in isolation" into "proven on the wire."

### C9. Session window — config-driven, slides on activity, not on liveness (live, for A4)

This MUST run on the live full-stack infra with **non-default, compressed** TTLs
set via env (integer seconds, e.g. `SESSION_IDLE_TTL=10`, `SESSION_MAX_TTL=30`) so the wall-clock
is bounded — and that override must flow through compose to the auth-service AND
through the render to the gateway. Assert all of:
- **Config reaches both planes:** `docker compose config` shows the overridden
  `SESSION_IDLE_TTL`/`SESSION_MAX_TTL` on auth-service; the rendered `apisix.yaml`
  shows the overridden `idle_ttl_seconds`. (The plumbing proof — this is the part
  that was missing before.)
- **`/auth/me` does not extend:** poll `/auth/me` faster than the idle bound;
  after `> SESSION_IDLE_TTL` of no `/api` traffic the session is gone (next
  `/auth/me` and `/api/**` → 401).
- **`/api` activity extends:** hit `/api/**` faster than the idle bound; the
  session stays alive well past one idle window.
- **Max ceiling enforced:** keep `/api` activity going continuously; at
  `SESSION_MAX_TTL` the session dies anyway (gateway never `EXPIRE`s past
  `absolute_expires_at`) → 401.
- **Both planes agree:** the same idle window governs whether the slide came from
  the gateway (`/api`) or not — a divergence between auth-service and gateway
  values would show up as the session outliving or undercutting the configured
  idle bound depending on path; assert it does not.

Run this in BOTH the default and an alt-config invocation; the alt-config run is
what proves the values are genuinely read from config, not constants.

### C10. Back-Channel Logout — IdP-driven revocation (live, for A5)
- A valid `logout_token` POSTed to `/backchannel-logout` for an active session →
  that user's next `/api/**` AND next `/auth/me` both 401 (prove BOTH doors).
- A forged / wrong-signature / missing-`events` / `nonce`-bearing token → 400, the
  session is untouched (the user stays logged in).
- Token-TTL bound (A6): an access token issued before a role change at the IdP
  stays valid at the RS only until its short expiry; after the next refresh
  `/auth/me` and `/api/**` reflect the new role. Proves the bound is the token
  lifetime. (Instant revocation is the back-channel-logout case above.)

### C11. Multi-tab / concurrent login — live (for A7)
- Start two `/auth/login` flows from the same browser context (two tabs), carry
  both through Keycloak, and complete both callbacks — **both succeed**; neither
  tab's callback 400s on the browser-binding check.
- Each transaction's `oauth_tx_<state>` cookie is single-use and evicted on its
  own callback; an abandoned login's cookie expires at the 5m tx TTL.

### Test-quality rules
- Live tests assert against real tokens / responses, not fabricated JWTs.
- Every negative is a distinct, named assertion with the expected status code and
  the expected audit event where one applies.
- No silent caps. If a scenario cannot be driven hermetically (e.g. real token
  revocation), say so in the harness output, provide the closest hermetic proxy,
  and document the manual step.
- Surefire tallies only after `clean`; e2e tallies from the actual run.

---

## Part D — Remaining verified review items (do not drop)

These came out of the adversarial pass and were each verified against the tree.
They are smaller than A–C but real; none may be silently skipped.

### D1. Frontend `/auth/me` DTO sanitization (token-isolation defense-in-depth)
`fetchMe` returns the **raw parsed body** after `isUser` checks required fields
(`auth.ts:60-62`); extra fields pass straight into SPA state. If `/auth/me` ever
returned a token-like field, the browser would hold it. Construct an allowlisted
`User` object — `{sub, preferred_username, name, email, roles}` only — and return
that, never the raw body. Live test: `/auth/me` response carrying an extra
`access_token` field → it does not appear anywhere in SPA state / storage (extends
C7).

### D2. Sentinel fail-closed posture must be consistent and safe
`SecretSentinelValidator` treats "no active Spring profile" as local → **WARN
only** (`:93-104`). `compose.yaml` sets `SPRING_PROFILES_ACTIVE` for the
resource-server but **not** the auth-service — so the shipped artifact a team
copies models unsafe-by-omission: drop in real secrets, forget the profile, and a
dev sentinel ships with only a log WARN. Fix: set an explicit profile for the
auth-service in compose too, AND/OR invert the guard to require an explicit
`local` opt-in to skip fail-closed. Both services must behave identically. (See
SECURITY.md D-1.)

### D3. `production-hardening.md` — fix or retire
It points hardeners at the **removed** `refresh_token_reuse` audit event (now
`refresh_token_rejected`), is a weaker duplicate of `SECURITY.md`, and omits
load-bearing items this codebase needs (sentinel profile gating, sid
non-rotation, `X-Forwarded-Proto` discipline, session ceiling ≤ IdP SSO max).
Either point it at `SECURITY.md` or bring it to parity. A SIEM rule built off the
stale event would never fire.

### D4. Document the two-sided coupling of IdP-identity knobs
`OIDC_AUDIENCE`, `INTERNAL_REFRESH_AUDIENCE`, `GATEWAY_CLIENT_ID` are only the
**RP's half**. The IdP must be configured to *issue* the matching value, and the
two move together (for Keycloak the realm JSON stamps them; no env drives the
realm value). State this explicitly in `provider-adapters.md` so an operator who
sets only the env — and nothing on the IdP — doesn't silently break refresh/authz.

### D5. Minor doc-correctness fixes
- `README` must not reference a `provider-adapters.md §"Portability scope"` anchor
  that doesn't exist — fix the link or the heading.
- SPEC XSRF `SameSite` inconsistency: the Test-Plan line says `Lax`; normative
  §7.3 and the code say `Strict`. Fix the Test-Plan line.

### D6. One real React-path browser E2E
Existing browser stories bypass the SPA's real code: the 401 case navigates
manually and logout calls `fetch("/auth/logout")` directly. Add at least one story
that drives the **actual** paths — sign out via the UI button, and a `callApi()`
401 → top-level navigation to `/auth/login?return_to=...` — so the live suite
covers SPA behavior, not just protocol hops.

### D7. Test-comment precision (token-isolation)
The storage-leak assertion comment must claim what it checks — "verifies the
common browser storage / cookie / response-body leak paths" — not "proves no
token can ever appear." Accuracy, not absolutes.

### D8. Documented caveats (no code — write the note)
- **CC-token cache cliff:** `bff-session.lua` proactively refreshes the gateway's
  client-credentials token 60s before expiry; if an IdP issues client-credentials
  tokens with `expires_in ≤ 60s`, every refresh-window `/api` request misses cache
  and serializes through one IdP token call. Note the assumption (CC tokens live
  well over a minute) and the cheap mitigation (make the skew a fraction of
  `expires_in`) as a documented limitation.
- **Two-token authz (C18):** `/auth/me` roles come from the id_token; RS authz
  from the access token. They agree only because the realm maps roles into both
  tokens. Document that an IdP swap MUST keep both mappers in sync (the alt realm
  already does), and that the SPA's `/auth/me` roles are display-only — the access
  token is the sole authorization source.

## Definition of done

- **A1–A8** implemented; **B1–B3** done; **D1–D8** done; docs match code exactly;
  no doc claims a feature the code does not implement.
- The Part C matrix (C1–C11) is green against the live stack, and **each negative
  was seen to fail the right way** — break the guard, watch the test go red,
  restore, watch it pass. Red→green discipline applies to the tests themselves.
- `docker compose config` and the rendered `apisix.yaml` prove every documented
  knob — including `SESSION_IDLE_TTL`/`SESSION_MAX_TTL` on both planes — is
  override-reachable.
- Non-default-config live runs are enforced gates: trust identifiers (C8) and
  session TTLs (C9), each proven on the wire, not just unit-tested.
- Full battery green: unit (clean), `e2e-auth`, `e2e-conformance`,
  `e2e-portability` (default + non-default trust ids), `test-e2e`.

## Reviewer gates (I will check, not implement)

For every item: I verify the change against the tree, and for Part C I confirm the
negative tests are real by watching at least a sample go red when the guard is
removed. A green suite on defaults is not acceptance — a green suite that includes
failing-the-right-way negatives against the live stack, on default and non-default
config, is.
