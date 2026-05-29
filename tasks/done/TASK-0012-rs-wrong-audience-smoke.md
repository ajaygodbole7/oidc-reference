# TASK-0012: RS JWT negative verification

## Objective

Add a verification gate that proves the Resource Server rejects invalid JWTs,
including tokens whose `aud` claim does not include `oidc-reference-api`. The
isolated audience proof comes from `JwtDecoderNegativeTest`; the optional live
smoke proves a running RS returns HTTP 401 for a foreign invalid JWT.

## Linked Spec

- `docs/specs/SPEC-0001-core-oidc-flows.md` — primary threat-model row:
  "Audience confusion"

## Read First

- `AGENTS.md`
- `docs/agents/mandatory-turn-protocol.md`
- `docs/agents/execution-discipline.md`
- `scripts/verify-cross-service.sh` — existing happy-path gate (style model)
- `authorization-server/realm/oidc-reference-realm.json` — client + scope inventory
- `backend-resource-server/src/main/resources/application.yml` — confirms
  `app.audience: oidc-reference-api`

## Owned Paths

- `scripts/verify-rs-negatives.sh` (NEW)
- `scripts/verify-all.sh` (add invocation line only)
- `tasks/active/TASK-0012-rs-wrong-audience-smoke.md` (this file)

## Avoid Paths

- `scripts/verify-cross-service.sh` — happy-path script; do not touch
- `bff/`, `backend-resource-server/`, `frontend/`, `authorization-server/realm/`

## Assumptions

1. **Option A not available.** The realm contains exactly two clients:
   `oidc-reference-bff` (no `serviceAccountsEnabled`, cannot do Client
   Credentials) and `oidc-reference-service` (CC-enabled but carries
   `api.audience` in its default scopes, so its tokens include the correct
   audience).  No second service client without the audience scope exists.

2. **Isolated decoder tests are the audience proof.** A locally-minted
   foreign-key JWT is not valid evidence for audience enforcement because
   Spring Security rejects it at JWKS-signature verification before audience
   validation is reached.

3. **`openssl` and `node` are present** in the standard dev environment (both
   are already required by other scripts and the frontend build chain).

4. **Live gate is opt-in.** `RUN_LIVE_RS_NEGATIVES=1` is required to execute
   the live check.  The static phase (config file contains expected audience
   string) always runs.

5. **`verify-all.sh` owns the invocation.** `verify-full-stack-auth.sh` starts
   the RS as a process; that script already runs `verify-cross-service.sh`.
   It does NOT need to explicitly call `verify-rs-negatives.sh` because
   `verify-all.sh` chains both.  If full-stack live tests are desired, the
   caller sets both `RUN_LIVE_CROSS_SERVICE=1` and `RUN_LIVE_RS_NEGATIVES=1`.

## Ambiguities

- None remaining for this task. The live smoke enforces
  `application/problem+json` when `RUN_LIVE_RS_NEGATIVES=1` is enabled.

## Success Criteria

- `scripts/verify-rs-negatives.sh` is executable and passes shellcheck.
- Static phase: exits 0 when RS config contains `oidc-reference-api` and
  `JwtDecoderNegativeTest` passes.
- Live phase (`RUN_LIVE_RS_NEGATIVES=1`): exits 0 only when RS returns 401 for
  the foreign invalid JWT and emits `application/problem+json`; exits non-zero
  with a clear message otherwise.
- `verify-all.sh` invokes the new script after `verify-cross-service.sh`.
- No changes to any file outside owned paths.

## Plan

```text
1. Read verify-cross-service.sh                -> verify style/env-var conventions
2. Read verify-full-stack-auth.sh              -> verify setup conventions and env vars
3. Read realm JSON                             -> enumerate clients, find Option A viability
4. Read RS application.yml                     -> confirm audience value
5. Write verify-rs-negatives.sh                -> verify: shellcheck, executable bit
6. Edit verify-all.sh (one line)               -> verify: diff shows single addition
7. Write TASK-0012-rs-wrong-audience-smoke.md  -> verify: fields match template
```

## Done Criteria

- [ ] `scripts/verify-rs-negatives.sh` created, executable, passes shellcheck.
- [ ] Static phase always runs; confirms RS config and targeted decoder
  negative suite.
- [ ] Live phase guarded by `RUN_LIVE_RS_NEGATIVES=1`; asserts HTTP 401.
- [ ] Content-Type check is a hard assertion for `application/problem+json`.
- [ ] `scripts/verify-all.sh` chains the new script.
- [ ] Task packet complete.

## Final Report

_Status_: ✅ Done (script + static phase landed; live phase gated by
`RUN_LIVE_RS_NEGATIVES=1` for use against a running RS).

### Tests run

- `sh scripts/verify-rs-negatives.sh` → static audience config check passed;
  `JwtDecoderNegativeTest` passed; live check skipped (correct skip path).
- The live phase is exercised when `RUN_LIVE_RS_NEGATIVES=1` is set
  against a running RS — it mints a foreign-key RS256 JWT, hits the RS,
  asserts 401 and `application/problem+json`.

### Files created/modified
- `scripts/verify-rs-negatives.sh` (NEW)
- `scripts/verify-all.sh` (one line added after `verify-cross-service.sh`)
- `tasks/active/TASK-0012-rs-wrong-audience-smoke.md` (NEW)

Strategy: isolated decoder negative tests plus optional live foreign-token
smoke.

Wrong-audience source: `JwtDecoderNegativeTest` signs with the trusted
in-memory test key and varies only the `aud` claim or omits it.

Blocker note: Option A was investigated and ruled out — no second service
client without `api.audience` exists in the realm.

Risks / follow-ups:
- If a future realm change adds a CC-capable client without the audience scope,
  the live phase can be upgraded to mint a Keycloak-signed wrong-audience token.
