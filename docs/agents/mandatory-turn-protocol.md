# Mandatory Turn Protocol

This protocol is required for every documentation or code-changing turn.

## Before Editing

Record this block in the task packet, working notes, or final report:

```text
Assumptions:
Ambiguities:
Owned paths:
Success criteria:
Plan:
1. Step -> verify: check
2. Step -> verify: check
3. Step -> verify: check
```

If a field cannot be filled, stop and report why before editing.

## During Work

- Edit only owned paths.
- Keep the diff tied to the task.
- For behavior changes, add or update the failing test first where feasible.
- Use the smallest complete secure implementation.
- Fail closed at OAuth/OIDC security boundaries.

## Before Final Report

Run the focused check. Run the broader gate when available.

Final report must include:

```text
Files changed:
Checks run:
Result:
Risks or blockers:
```

## Enforcement

Task packets should be checked with:

```bash
./scripts/check-agent-task.sh tasks/active/TASK-XXXX.md
```

This check does not prove the agent behaved correctly. It prevents task packets
from omitting the required control fields.

