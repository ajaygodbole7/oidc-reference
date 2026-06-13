---
name: extend-oidc-flow
description: >-
  Add or modify an OAuth/OIDC flow, endpoint, claim, or security control in the
  oidc-reference repo the way the repo expects. Use when implementing a feature
  or change here (e.g. a new /auth or /api behavior, a token-validation rule, a
  session-lifecycle change). Encodes this repo's architecture, its TDD and
  doc-as-contract discipline, its provider-agnostic + don't-fight-the-infra
  rules, and its commit convention.
---

# Extending a flow in oidc-reference

This is a *reference* implementation of the BFF/OIDC pattern, not a product.
Changes are judged by whether they belong in the substance a reader copies.

## Architecture you're working within

- **Auth Service** (`auth-service/`, Java/Spring, Nimbus): the confidential
  OIDC client. Owns `/auth/*`, the OAuth round-trip, session storage, and
  `/internal/resolve`. Sole reader/writer of `sess:{sid}` and `tx:{state}`.
- **API Gateway** (`api-gateway/`, APISIX + `bff-session.lua`): owns `/api/**`,
  resolves the sid via `POST /internal/resolve` (phantom-token — holds **no**
  store handle), injects the bearer, validates signed CSRF.
- **Resource Server** (`backend-resource-server/`): JWT validation only; never
  sees cookies.
- **Keycloak** realm + **Valkey** state store. Both are swappable vendors.

## The rules (these are how a change gets accepted here)

1. **TDD, red → green — and prove the test has teeth.** Write the failing test
   first and *run it to see it fail for the right reason*, then implement to
   green. For a test of code that already exists (a characterization or parity
   test that passes immediately), prove it can fail: mutate the guard it covers,
   watch THAT test go red, then revert. Security-critical paths get adversarial
   negatives (bad sig / wrong iss-aud-exp / stale / replayed / forged), not just
   happy paths; validators are tested against real crypto, not mocked away.
   Per-component runners: `cd auth-service && ./mvnw -Dtest=Foo test`, `cd
   backend-resource-server && ./mvnw test`, `cd frontend && npx vitest run`. When
   TALLYING a Java suite use `./mvnw clean test`, not `test` — surefire reports
   are not cleaned between runs, so a glob tally sweeps up stale reports from
   prior runs and invents phantom failures.

2. **SPEC-0001 is the build contract.** `docs/specs/SPEC-0001-core-oidc-flows.md`
   documents every endpoint, wire format, `tx:{state}`/`sess:{sid}` field, and
   the `/internal/resolve` contract. If you change behavior, update the SPEC in
   the same change — doc-vs-code drift is treated as a defect here. Update the
   compliance matrices too (`OIDC-compliance.md`, `RFC9700-compliance.md`,
   `RFC9470-compliance.md`) when you touch a control they track.

3. **Provider-agnostic code; provider specifics in config.** Application code
   branches on standard OIDC (`iss` / `aud` / scopes / claim paths / discovery
   endpoints), never on the provider brand. Per-provider differences live in
   env/`AuthProperties`/the Keycloak realm JSON. Example: step-up reads the
   standard `auth_time` claim; the *means* of emitting it (a Keycloak protocol
   mapper) lives in the realm files (both `oidc-reference-realm.json` and
   `oidc-reference-alt-realm.json`), not in Java.

4. **Don't fight the swappable infra.** The APISIX/Lua gateway, Compose, and the
   dev Keycloak (H2) are deployment-platform details that get replaced in prod
   (Kong / AWS API Gateway / Envoy, managed IdP, HA store). Connection pooling,
   circuit breaking, HA, observability, supply-chain pinning, native image, etc.
   are **production-hardening** concerns — disclose them in
   `docs/operations/production-hardening.md`, do **not** bake them into the
   reference default. Reference-level findings are protocol/security/contract/test.

5. **Fail closed.** New error/validation paths default to deny; never fail open.
   Mirror the existing audit events (`SecurityAudit`) for new outcomes.

6. **Two flows + the two cookies.** Auth Code + PKCE (with `state`, `nonce`,
   `oauth_tx` browser binding) and Client Credentials. Session is an opaque
   `__Host-sid`; CSRF is the signed double-submit `XSRF-TOKEN` bound to the sid.
   Keep tokens off the browser, *precisely*: access and refresh tokens never
   reach the browser; the **id_token** never reaches browser JS, storage,
   SPA-readable JSON, SPA-visible cookies, or app logs — **only** the server's
   `/auth/logout/continue → IdP` top-level redirect may carry `id_token_hint`.
   The live e2e asserts this; preserve it. (The loose paraphrase "no tokens in
   the browser" drops the `id_token_hint` exception that makes the rule precise.)

## Workflow

1. Plan the change against the SPEC; identify the reference-vs-infra split.
2. TDD each unit (auth-service, RS, frontend) red → green.
3. Add/extend an e2e story in `frontend/tests/e2e/reference-flow.spec.ts` when
   the behavior is observable end-to-end; keep it deterministic (no flaky
   sleeps — poll, or assert by construction).
4. Update SPEC-0001 + README "Security controls" + the relevant compliance doc.
5. Verify with the **verify-oidc-reference** skill after **every** change, not
   just at the end — the bar is the FULL sequential live battery (`test-e2e` +
   `e2e-conformance` + `e2e-auth` + `e2e-portability` + `e2e-c8-altids`), no
   skips. A unit suite passing in isolation is not the proof; a green
   cross-component run is. Do not decide a change "can't affect" a gate and skip
   it.

## Commit convention

Plain, descriptive commit messages. **Do NOT add a `Co-Authored-By: Claude`
trailer** (or any AI attribution) — this repo's commits omit it. If on the
default branch and the change is large, branch first; otherwise commit on the
working branch the user is on. Commit/push only when the user asks.
