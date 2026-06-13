# Architecture change: Auth Service as authentication oracle, gateway as edge

**Status:** proposed, awaiting review.

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
