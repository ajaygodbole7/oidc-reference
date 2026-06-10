# Documentation Index

This project is spec-first. The docs are the coordination surface for humans
and agents.

The canonical end-to-end flow is in the root `README.md`.

## Start Here

- `start-here.md` — shortest path through the repo.
- `../AGENTS.md` — operating contract for all agents.
- `architecture/overview.md` — architecture orientation.
- `architecture/architecture-decisions.md` — why the architecture choices
  were made and what was rejected.
- `specs/SPEC-0001-core-oidc-flows.md` — the build contract.
- `testing/red-green-workflow.md` — required implementation loop.
- `testing/verification-gates.md` — focused and full gates.

## Harness

- `harnesses/local-verification.md` — local verification steps.

## Operations

- `operations/provider-adapters.md` — provider swap surface and checklist.
- `operations/provider-overlays/okta.md` — non-gating Okta runbook and
  evidence template.
- `operations/production-hardening.md` — what must change before non-local use.

## Project Rhythm

1. Write or update a spec.
2. Convert the spec into task packets.
3. Assign agents to one of the four primary subdirectories.
4. Use red/green TDD.
5. Run verification gates.
6. Update docs when decisions change.
