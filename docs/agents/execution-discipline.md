# Execution Discipline

These rules are required for code or documentation changes.

## Think Before Coding

Before implementation, state or record:

- Assumptions.
- Ambiguities.
- Tradeoffs.
- Owned paths.
- Success criteria.
- Verification plan.

Do not silently choose between meaningful interpretations. For security-critical
OAuth/OIDC behavior, stop and ask when the correct choice cannot be discovered
from specs, code, or official docs.

For routine implementation details, inspect the repo first, make the most
conservative assumption that matches the spec, and document it in the task final
report.

## Simplicity First

Build the minimum complete secure slice that satisfies the spec and tests.

- No features beyond the task.
- No abstractions for single-use code.
- No speculative configurability.
- No broad framework changes unless the task calls for them.
- Prefer the smallest readable implementation that preserves security.

Correct, reproducible, secure, tested, and documented beats clever.

## Surgical Changes

Every changed line should trace to the task.

- Touch only owned paths unless the task explicitly allows more.
- Match existing style.
- Do not refactor adjacent code just because it is nearby.
- Remove only unused code introduced by your change.
- Mention unrelated dead code or design issues instead of deleting them.
- Never revert another agent's or user's work without explicit instruction.

## Goal-Driven Execution

Multi-step tasks need a brief plan in this shape:

```text
1. Step -> verify: check
2. Step -> verify: check
3. Step -> verify: check
```

For implementation tasks:

1. Run or identify the current relevant test.
2. Add or update a failing test where feasible.
3. Confirm the red failure.
4. Implement the smallest change.
5. Confirm green.
6. Run the relevant verification gate.

## Security Boundary Rule

Avoid speculative error handling in normal code, but fail closed at security
boundaries.

These are not impossible scenarios:

- Missing token.
- Malformed token.
- Expired token.
- Wrong issuer.
- Wrong audience.
- Missing scope.
- Token with unexpected claim shape.
- Keycloak unavailable.
- CORS request from an unexpected origin.
- Browser callback error.

Handle those cases deliberately and test the important ones.

## Final Report Requirements

Every non-trivial task final report should include:

- Assumptions made.
- Files changed.
- Tests or checks run.
- Evidence of success.
- Known risks or blocked items.
