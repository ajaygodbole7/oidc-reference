# Architecture change: Auth Service as authentication oracle, gateway as edge

**Status:** reviewed — **declined**. The rename is not recommended; the boundary
clarity it seeks already exists and can be sharpened in docs at near-zero churn.
See "Review verdict" at the end.

> **Reviewer:** please challenge the responsibility boundary and the contract
> shape (the two tables + the reviewer questions at the end).

## Principle

- The API Gateway (APISIX + Lua) is swappable infrastructure; the Auth Service
  is the copyable reference.
- Authentication *policy* should live in the copyable layer; edge mechanics in
  the swappable one.
- Today the boundary is blurred: the gateway↔Auth-Service endpoint is named for
  a mechanism (`/internal/resolve`), and the login-entry decision is split
  across Lua and the SPEC. This change names the boundary explicitly.

## Responsibilities (the change)

| Layer | Owns |
|---|---|
| **API Gateway** (edge, swappable) | WAF, rate limiting, CSRF validation, forwarding/proxying, cookie + header shaping, and *front-end checking*: session-cookie presence, navigation-vs-XHR classification, the `302`-vs-`401` response, bearer injection, rotated-cookie re-issue. |
| **Auth Service** (copyable) | One question via `/internal/authenticate`: **is this session authenticated?** Yes → the current access token to inject. No → `401`. Owns the session store and the token lifecycle (idle-slide, near-expiry refresh, sid rotation) — those run internally to answer "yes" with a *valid* token. |

## What changes

- **Rename** `/internal/resolve` → `/internal/authenticate`. The endpoint is
  reframed as an authentication oracle (yes/no), not a token-resolve RPC.
- The implementation keeps the idle-slide, near-expiry refresh, and sid rotation
  — they are how it answers "yes, here is a valid token."
- Wire shape is otherwise unchanged: `sid` in; `access_token` + rotation fields
  out on yes; `401` on no; `404`/`409` → "no, the cookie is stale, clear it";
  `503`/`502` on upstream failure.
- `bff-session.lua` `access()` keeps its current shape; only the endpoint name
  and the comments/framing change.

## What does NOT change (behavior preserved)

- No-cookie navigation → `302 /auth/login?return_to=…`; no-cookie XHR → `401`.
  Still decided at the gateway (front-end check — see below).
- CSRF validation (signed double-submit) stays at the gateway, before the
  authenticate call (so a forged request never reaches the Auth Service).
- Rate-limit, WAF, header stripping, bearer injection, rotated-cookie re-issue —
  all stay at the gateway.
- Token lifecycle (refresh, rotation, idle TTL) stays inside the Auth Service.
- Observable browser behavior is identical. This is a rename + responsibility
  clarification, not a behavior change.

## No-cookie decision (confirmed)

The gateway short-circuits a no-cookie request to `302`/`401` itself — a
front-end check, no backend call. The Auth Service is invoked only when a
credential (`sid`) is present, keeping it a pure oracle.

- "Is a credential present?" is a front-end check (gateway).
- "Is this credential a valid authenticated session?" is the authentication
  decision (Auth Service).

The alternative — always calling `/internal/authenticate` (even no-cookie → "no")
— was considered and rejected: it burdens the Auth Service with unauthenticated
traffic for no policy gain, and a no-credential request is exactly what a gateway
should reject at the edge.

## Scope (files)

- `api-gateway/plugins/bff-session.lua` — rename the call URL to
  `/internal/authenticate`; relabel comments. No flow change.
- `api-gateway/apisix.yaml.template` / config — any path references.
- `auth-service/.../InternalResolveController.java` → `@PostMapping("/authenticate")`
  (likely rename the class to `InternalAuthenticateController`); reframe Javadoc.
- `docs/specs/SPEC-0001-core-oidc-flows.md` §7.1 + the `/internal/resolve` rows +
  the "Login Entry Conditions" framing.
- `README.md` — the authenticated-request diagram (endpoint name; edge-vs-oracle
  labels) + the architecture table.
- `SECURITY.md` and any other doc referencing `/internal/resolve`.
- Tests: gateway Lua tests, `InternalResolveControllerTest` (rename), the C8
  conformance gate (its identity check hits the path string), and any
  scripts/e2e referencing `/internal/resolve`.

## Test plan

- **Behavior-preserving** — the existing e2e stories (anonymous `/api` → `302`/`401`;
  authenticated `/api` proxy; refresh delegation; sid rotation) are the
  regression net and must stay green.
- **Rename coverage** — grep the repo for `/internal/resolve` and update every
  reference; the contract-string + cross-service gates confirm no dangling
  contract.
- **Conformance C8** — updated to the new path; configured gateway client still
  passes the identity check, foreign client still `401`.
- **Full live battery** (verify-all, e2e-auth, conformance, portability,
  c8-altids) green before commit.

## Risks

- **Rename churn** across the contract (Lua, Java, SPEC, gates, tests, docs) —
  bounded but wide; the contract-string gates catch misses.
- **Low functional risk** — no behavior change; the real risk is a missed
  reference to the old path, mitigated by grep + gates + the live battery.

## Reviewer questions

1. Is the edge-vs-oracle boundary right? Anything you would move across it?
2. Endpoint name `/internal/authenticate` — good, or prefer another?
3. Response shape: keep status-coded (`200` yes / `401` no / `404`-`409` stale)
   or move to an explicit decision object? (Recommendation: keep status-coded —
   minimal churn, the gateway already branches on it.)
4. Anything that makes this *not* worth the rename churn for a reference repo?

## Review verdict

**Decline the rename (`/internal/resolve` → `/internal/authenticate`).** This is a
rename plus a documentation reframe with no behavior change. Three findings sink
it for a reference repo.

**1. The motivating premise — "the boundary is blurred today" — does not hold.**
The edge-vs-policy split is already explicit in code and docs:

- `architecture-decisions.md §A6` (the Auth Service owns `/auth/*` +
  `/internal/resolve` and is sole reader/writer of `sess:{sid}`; the gateway holds
  no store handle and calls resolve to turn the opaque sid into an access token).
- `bff-session.lua`'s header already enumerates the gateway's edge job as steps
  1–4 (cookie read → no-cookie 302/401 classifier → CSRF → call resolve).
- SPEC-0001 §7.1 and `phantom-token-session-resolution.md` carry the contract.

The "No-cookie decision (confirmed)" section describes the status quo:
`bff-session.lua` already short-circuits no-cookie to 302/401 at the edge and only
calls resolve when a `sid` is present. That part is a no-op.

**2. The name change is a regression, not a clarification.** `/internal/resolve`
resolves a *phantom token* (opaque sid → real access token) **and** maintains the
session lifecycle (idle-slide, near-expiry refresh, sid rotation, cookie re-issue)
on every call. "resolve" names the phantom-token resolution that is this repo's
core teaching concept. "authenticate" / "oracle" implies a side-effect-free yes/no
check, but this endpoint mutates state every call, and "authenticate" collides with
the login-time authentication the IdP already performed. The `auth_request` /
oauth2-proxy precedent for naming a gateway sub-request `/authenticate` does not
transfer — those are pure checks; this is resolve + provision + maintain.

**3. The churn is wider than "bounded but wide," and it lands on the gates.**
`/internal/resolve` spans ~50 files — 41 occurrences in SPEC-0001 alone, plus the
Lua, the Java controller and six test classes, compose files, `schema/`, README,
SECURITY — and the verification gates: it is a required contract string
(`verify-cross-service.sh: require_present "/internal/resolve"`) and the C8
conformance gate references it nine times, including the literal
`curl …/internal/resolve` identity check. Large, gate-touching blast radius for
zero behavior change.

**On the doc:** this is the fourth standalone proposal doc (after `review-backlog.md`,
`enhancement-proposals-2026-06-12.md`, `java-spring-modernization-2026-06-12.md`,
all removed). Fine as a review input; if any of it lands it belongs as a refinement
to §A6 / SPEC §7.1, not a new `docs/architecture/` file.

**Answers to the reviewer questions:**

1. Boundary is right — and already documented in §A6 + SPEC §7.1 + the Lua header.
   Nothing to move.
2. Keep `/internal/resolve`. It is accurate to the phantom-token pattern;
   `/internal/authenticate` is a naming regression for a stateful resolve.
3. Keep the status-coded response — but it is moot without the rename.
4. Yes: that is what makes it not worth the churn. High blast radius into the
   conformance/contract gates, no behavior change, accuracy-neutral-to-negative
   naming.

**If the goal is sharper teaching of the edge-vs-policy boundary, do it in words,
not a rename:** add the "edge mechanics (swappable) vs authentication policy
(copyable)" framing to §A6 and the `bff-session.lua` header, keeping the
`/internal/resolve` name. That captures the full pedagogical benefit at near-zero
churn — without touching the contract string, the conformance gate, or the
phantom-token vocabulary — and keeps the endpoint name honest about what it does.
