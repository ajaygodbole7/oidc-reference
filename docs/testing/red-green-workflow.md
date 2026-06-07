# Red/Green TDD Workflow

All behavior changes should follow this loop.

## Red

1. Identify the spec acceptance criterion.
2. Add or update the smallest test that proves the behavior.
3. Run the focused test command.
4. Confirm the test fails for the expected reason.

If the test passes before implementation, the test is not proving the new
behavior. Fix the test before coding.

## Green

1. Implement the smallest production change that should satisfy the test.
2. Run the focused test command.
3. Keep iterating until it passes.

## Refactor

1. Clean up implementation only after tests pass.
2. Keep refactors local to the task.
3. Re-run focused tests after cleanup.

## Verify

Run the relevant broader gate from `verification-gates.md`. If the gate is not
available yet, record the intended command in the task final report.

