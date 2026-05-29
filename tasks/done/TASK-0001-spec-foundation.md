# TASK-0001: Spec Foundation

## Objective

Create the initial documentation and agent workflow foundation for the OIDC
reference project.

## Linked Spec

- `docs/specs/SPEC-0001-core-oidc-flows.md`

## Read First

- `AGENTS.md`
- `docs/references/spec-writing-for-agents.md`
- `docs/references/agentic-engineering-patterns.md`

## Owned Paths

- `AGENTS.md`
- `README.md`
- `docs/`
- `tasks/`

## Avoid Paths

- Future implementation directories unless explicitly created by a later task.

## Required Workflow

Assumptions:

- The project starts spec-first before implementation scaffolding.

Ambiguities:

- None for this completed foundation pass.

Owned paths:

- Same as `Owned Paths`.

Success criteria:

- Core docs exist.
- Future agents can find specs, goals, task templates, and verification docs.

Plan:

```text
1. Create foundation docs -> verify: files exist
2. Link agent workflow docs -> verify: references appear in docs index
3. Add testing workflow docs -> verify: verification gates are documented
```

## Done Criteria

- `AGENTS.md` exists.
- Reference summaries exist for the two external guides.
- Core flow spec exists.
- Agent ownership and task templates exist.
- Testing workflow and planned verification gates exist.

## Final Report

Include:

- Assumptions made.
- Files changed.
- Tests run.
- Result.
- Risks or follow-ups.
