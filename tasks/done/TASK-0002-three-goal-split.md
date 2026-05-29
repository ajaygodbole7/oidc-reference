# TASK-0002: Three Goal Split

> **SUPERSEDED.** This task encoded a three-goal split. The project
> later added GOAL-0004 (BFF) and now operates as four goals. See
> `tasks/backlog.md` and the canonical goals under `docs/goals/`. The
> body below is preserved as historical record only.

## Objective

Split the oidc-reference build into three durable, auditable Codex Goals with
matching subdirectories.

## Linked Docs

- `docs/agents/goals-harness.md`
- `docs/goals/GOAL-0001-frontend-react-pkce.md`
- `docs/goals/GOAL-0002-backend-resource-server.md`
- `docs/goals/GOAL-0003-authorization-server-keycloak.md`

## Owned Paths

- `docs/goals/`
- `frontend/README.md`
- `backend-resource-server/README.md`
- `authorization-server/README.md`
- `AGENTS.md`
- `docs/README.md`
- `docs/agents/ownership-map.md`
- `docs/architecture/overview.md`
- `docs/architecture/architecture-decisions.md`
- `tasks/backlog.md`

## Avoid Paths

- Implementation source files beyond directory README placeholders.

## Required Workflow

Assumptions:

- The three primary build slices are frontend, backend resource server, and
  authorization server.

Ambiguities:

- None for this documentation split.

Owned paths:

- Same as `Owned Paths`.

Success criteria:

- Three Goal docs exist, each mapped to one subdirectory.
- Stale `infra/`, `backend-api/`, and `service-client/` primary-shape references
  are removed.

Plan:

```text
1. Create Goal docs and directory READMEs -> verify: files exist
2. Update coordination docs -> verify: old primary directory names absent
3. Update backlog and task packet -> verify: task protocol fields present
```

## Done Criteria

- Three Goal docs exist and use the full Codex Goal pattern.
- Each Goal maps to one primary subdirectory.
- Project docs name the three primary work slices.
- Backlog reflects implementation work by slice.

## Final Report

Include:

- Assumptions made.
- Files changed.
- Tests run.
- Result.
- Risks or follow-ups.
