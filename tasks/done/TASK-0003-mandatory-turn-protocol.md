# TASK-0003: Mandatory Turn Protocol

## Objective

Make per-turn execution discipline mandatory and checkable for documentation or
code-changing work.

## Linked Docs

- `AGENTS.md`
- `docs/agents/execution-discipline.md`
- `docs/agents/mandatory-turn-protocol.md`

## Owned Paths

- `AGENTS.md`
- `docs/agents/mandatory-turn-protocol.md`
- `docs/agents/execution-discipline.md`
- `docs/agents/task-template.md`
- `docs/agents/review-checklist.md`
- `docs/README.md`
- `scripts/check-agent-task.sh`
- `tasks/active/`

## Avoid Paths

- `frontend/`
- `backend-resource-server/`
- `authorization-server/`
- Goal docs unless the protocol changes their required fields.

## Required Workflow

Assumptions:

- Docs alone do not enforce behavior; required task fields and a checker make
  skipping visible.

Ambiguities:

- The checker can validate task packet fields, not actual agent behavior.

Owned paths:

- Same as `Owned Paths`.

Success criteria:

- `AGENTS.md` is lean and operational.
- Mandatory turn protocol exists.
- Active task packets contain required protocol fields.
- A local checker fails when required task fields are missing.

Plan:

```text
1. Replace AGENTS.md with operational rules -> verify: file is short and directive
2. Add mandatory protocol doc and checker -> verify: checker runs locally
3. Update active tasks -> verify: checker passes for tasks/active/*.md
```

## Done Criteria

- `AGENTS.md` contains mandatory turn rules.
- `docs/agents/mandatory-turn-protocol.md` exists.
- `scripts/check-agent-task.sh` exists.
- Active task packets pass `scripts/check-agent-task.sh`.

## Final Report

Include:

- Assumptions made.
- Files changed.
- Tests run.
- Result.
- Risks or follow-ups.
