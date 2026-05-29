# TASK-0005: Backend Resource Server Scaffold And Harness

## Objective

Create the minimal Java 25 and Spring Boot 4.1 resource-server harness with the
first security tests.

## Linked Spec

- `docs/specs/SPEC-0001-core-oidc-flows.md`
- `docs/goals/GOAL-0002-backend-resource-server.md`

## Read First

- `AGENTS.md`
- `docs/agents/mandatory-turn-protocol.md`
- `docs/agents/execution-discipline.md`
- `docs/testing/red-green-workflow.md`

## Owned Paths

- `backend-resource-server/`
- `scripts/verify-backend.sh`
- Backend-specific docs or task notes

## Avoid Paths

- `frontend/`
- `authorization-server/`
- Root build files unless explicitly needed for backend tooling

## Required Workflow

Assumptions:

- Maven is the initial backend build tool unless a later task changes it.
- Spring Boot target is `4.1.0-RC1` based on current Maven Central availability.
- Java release is 25.

Ambiguities:

- Exact role mapping from Keycloak realm/client roles to Spring authorities must
  be documented before admin endpoint implementation.

Owned paths:

- Same as `Owned Paths`.

Success criteria:

- `./mvnw test` exists and runs backend tests.
- `./scripts/verify-backend.sh` runs backend verification.
- First red/green slice covers `/api/public` plus missing-token rejection on a
  protected endpoint.

Plan:

```text
1. Add Spring Boot Maven scaffold -> verify: ./mvnw test command exists
2. Add public endpoint and first security test -> verify: missing-token test fails before security implementation
3. Implement minimal resource-server security -> verify: ./scripts/verify-backend.sh passes
```

## Commands

```bash
cd backend-resource-server
./mvnw test
./mvnw spring-boot:run
../scripts/verify-backend.sh
```

## Configuration Contract

- `OIDC_ISSUER_URI=http://localhost:8080/realms/oidc-reference`
- `OIDC_AUDIENCE=oidc-reference-api`
- `FRONTEND_ORIGIN=http://localhost:5173`
- `SERVER_PORT=8081`

## Done Criteria

- Maven wrapper and `pom.xml` exist.
- Backend tests exist.
- Public endpoint succeeds without authentication.
- Protected endpoint rejects missing token.
- Verification script passes.

## Final Report

Include:

- Assumptions made.
- Files changed.
- Tests run.
- Result.
- Risks or follow-ups.

