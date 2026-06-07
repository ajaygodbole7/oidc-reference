# AGENTS.md

This is the operating contract for all agents working in this repo (Claude
Code, Codex, or human). It also doubles as `CLAUDE.md` for Claude Code,
which reads `AGENTS.md` as a fallback.

## Project Goal

Build a local OAuth 2.1 / OIDC reference that uses the Backend-for-Frontend
session pattern in its split-implementation shape: the browser never holds
tokens; a confidential **Auth Service** owns the OAuth/OIDC client role;
an **API Gateway** (APISIX) owns routing and bearer injection; tokens
live in a Redis-compatible server-side state store (Valkey locally).

The canonical end-to-end flow is the Mermaid sequence diagram in the root
`README.md`. The build contract is `docs/specs/SPEC-0001-core-oidc-flows.md`.

Five directories, five goals, no cloud.

- `frontend/` — React SPA, cookie-authenticated, no OIDC library
  (`docs/goals/GOAL-0001-frontend-react-pkce.md`).
- `auth-service/` — Spring Boot Auth Service, OAuth2 confidential client +
  custom Redis-compatible `tx:{state}` and `sess:{sid}` repositories,
  per-session refresh lock, `/internal/refresh` as OAuth Resource Server
  (`docs/goals/GOAL-0004-auth-service.md`).
- `api-gateway/` — APISIX gateway, `/api/**` routing with allowlist,
  tolerant `sess:{sid}` reader, bearer injection, signed CSRF validation,
  Client Credentials to call `/internal/refresh`
  (`docs/goals/GOAL-0005-api-gateway.md`).
- `backend-resource-server/` — Spring Boot Resource Server, JWT validation
  only (`docs/goals/GOAL-0002-backend-resource-server.md`).
- `authorization-server/` — Keycloak realm + Compose
  (`docs/goals/GOAL-0003-authorization-server-keycloak.md`).

## Mandatory Turn Protocol

For every documentation or code-changing turn:

1. Read this file.
2. Identify the active goal or task packet.
3. Before editing, state or record: assumptions, ambiguities, owned paths,
   success criteria, step → verify plan.
4. Edit only task-owned paths.
5. Use red/green TDD for behavior changes.
6. End with evidence: files changed, checks run, result, risks or blockers.

If any item cannot be satisfied, stop and report why before editing.

## Required Workflow

1. Start from a goal doc under `docs/goals/`.
2. Keep changes surgical.
3. Write or update the failing test first when behavior changes.
4. Implement the smallest complete secure slice.
5. Run focused checks.
6. Run the relevant broader gate when available.
7. Update docs only when behavior, commands, security posture, or structure
   changes.

## Ownership

- Frontend Agent: `frontend/`
- Auth Service Agent: `auth-service/`
- API Gateway Agent: `api-gateway/` (APISIX config; not a Spring module)
- Backend Agent: `backend-resource-server/`
- Authorization Server Agent: `authorization-server/`
- Test Agent: verification scripts and cross-service tests
- Security Agent: threat model and negative auth cases
- Docs Agent: docs scoped to the assigned task

Auth Service and API Gateway have separate ownership boundaries: the Auth
Service owns OAuth/OIDC client behavior and writes `tx:{state}` and
`sess:{sid}`; the API Gateway owns routing, the `/api/**` allowlist, and
the tolerant `sess:{sid}` reader. They share only the documented JSON
schema in SPEC-0001 §"`sess:{sid}` schema contract" and the
`/internal/refresh` contract.

Coordinate before editing:

- `AGENTS.md`, root build files, root `compose.yaml`, shared verification
  scripts, Keycloak realm files once other slices depend on them.

## Security Rules

Never:

- commit secrets, tokens, cookies, private keys, generated realm secrets,
  or real user data
- enable OAuth implicit flow or password grant for any reference client
- ship a public-client SPA — the SPA must remain cookie-authenticated
- store any token, code, or claim in `localStorage`, `sessionStorage`,
  IndexedDB, or JS-readable cookies
- disable issuer, audience, expiration, signature, or algorithm validation
- use wildcard redirect URIs or wildcard CORS origins for protected APIs
- hand-roll crypto, PKCE, OIDC discovery, JWKS parsing, callback
  validation, or session encoding when proven libraries exist
- proxy arbitrary upstream URLs through the API Gateway — `/api/**` is allowlisted

Ask first:

- changing Java, Spring Boot, React, Keycloak, or Valkey major versions
- adding a major dependency or framework
- replacing Spring Security OAuth2 Client, the custom Redis-compatible
  transaction/session repositories, or the OIDC library choices
- changing directory ownership
- adding any non-local infrastructure

## Canonical Docs

- `docs/specs/SPEC-0001-core-oidc-flows.md` — the build contract.
- `docs/architecture/overview.md` — architecture orientation.
- `docs/architecture/architecture-decisions.md` — rationale and rejected
  alternatives.
- `docs/goals/GOAL-000{1,2,3,4,5}*.md` — durable per-component goals.
- `docs/testing/red-green-workflow.md`, `docs/testing/verification-gates.md`.
- `docs/agents/task-template.md`, `docs/agents/review-checklist.md`,
  `docs/agents/mandatory-turn-protocol.md`,
  `docs/agents/execution-discipline.md`.
