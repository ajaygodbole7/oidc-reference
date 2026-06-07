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

## Goals

- `goals/GOAL-0001-frontend-react-pkce.md` — frontend SPA (cookie client).
- `goals/GOAL-0002-backend-resource-server.md` — Resource Server (JWT).
- `goals/GOAL-0003-authorization-server-keycloak.md` — Keycloak realm.
- `goals/GOAL-0004-auth-service.md` — Auth Service (OAuth/OIDC client).
- `goals/GOAL-0005-api-gateway.md` — API Gateway (routing + bearer
  injection).

## Agent Process

- `agents/mandatory-turn-protocol.md` — per-turn control fields (enforced
  by `scripts/check-agent-task.sh`).
- `agents/execution-discipline.md` — assumptions, simplicity, surgical
  changes, verification.
- `agents/return-to-login-contract.md` — mandatory `return_to` login entry
  and saved-request replay contract.
- `agents/task-template.md` — task packet template.
- `agents/review-checklist.md` — review checklist.

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
