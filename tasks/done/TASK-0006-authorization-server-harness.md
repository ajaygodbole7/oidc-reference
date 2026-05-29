# TASK-0006: Authorization Server Harness

> **SUPERSEDED.** This task referenced an SPA public client
> (`oidc-reference-spa`) and SPA PKCE settings. The project moved to a
> confidential BFF client (`oidc-reference-bff`) and the SPA performs
> no OAuth. The current contract is
> `docs/specs/SPEC-0001-core-oidc-flows.md` and
> `docs/goals/GOAL-0003-authorization-server-keycloak.md`. The body
> below is preserved as historical record only.

## Objective

Create the minimal Keycloak local startup, realm import, and smoke-test harness.

## Linked Spec

- `docs/specs/SPEC-0001-core-oidc-flows.md`
- `docs/goals/GOAL-0003-authorization-server-keycloak.md`

## Read First

- `AGENTS.md`
- `docs/agents/mandatory-turn-protocol.md`
- `docs/agents/execution-discipline.md`
- `docs/testing/red-green-workflow.md`

## Owned Paths

- `authorization-server/`
- `scripts/verify-auth-server.sh`
- Authorization-server-specific docs or task notes

## Avoid Paths

- `frontend/`
- `backend-resource-server/`
- Root build files unless explicitly needed for local orchestration

## Required Workflow

Assumptions:

- Keycloak listens on `http://localhost:8080`.
- Realm name is `oidc-reference`.
- Realm import is source-controlled; generated secrets are not.

Ambiguities:

- Exact Keycloak image version must be selected in the task and documented.

Owned paths:

- Same as `Owned Paths`.

Success criteria:

- `docker compose up -d` starts Keycloak.
- Realm import exists.
- `./scripts/verify-auth-server.sh` validates Compose config and runs smoke
  checks.
- Smoke checks verify discovery issuer, JWKS, SPA PKCE S256 settings, service
  client token issuance, and API audience.

Plan:

```text
1. Add Compose and realm import skeleton -> verify: docker compose config passes
2. Add smoke script for discovery/JWKS -> verify: smoke fails before Keycloak is running or config is complete
3. Complete realm client/scope/audience config -> verify: ./scripts/verify-auth-server.sh passes
```

## Commands

```bash
cd authorization-server
docker compose config
docker compose up -d
tests/smoke.sh
../scripts/verify-auth-server.sh
```

## Local Contract

- Issuer: `http://localhost:8080/realms/oidc-reference`
- Discovery: `http://localhost:8080/realms/oidc-reference/.well-known/openid-configuration`
- JWKS: discovered from the issuer metadata.
- SPA client: `oidc-reference-spa`
- Service client: `oidc-reference-service`
- API audience: `oidc-reference-api`

## Done Criteria

- `compose.yaml` exists.
- Realm import exists.
- Smoke tests exist.
- No generated secret is committed.
- Verification script passes.

## Final Report

Include:

- Assumptions made.
- Files changed.
- Tests run.
- Result.
- Risks or follow-ups.

