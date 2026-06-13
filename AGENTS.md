# AGENTS.md

- **What this is:** the operating contract for anyone working in this repo —
  Claude Code, Codex, or human.
- **Who it's for:** contributors making code or doc changes.
- **Where to start:** read this file, then `docs/specs/SPEC-0001-core-oidc-flows.md`
  (the build contract) and the README sequence diagrams (the canonical flows).

## Project Goal

A local OAuth 2.1 / OpenID Connect (OIDC) reference using the Backend-for-Frontend (BFF) session
pattern in its split-implementation shape.

- The browser never holds tokens.
- A confidential Auth Service owns the OAuth/OIDC client role.
- An API Gateway (APISIX) owns routing and bearer injection.
- Tokens live in a Redis-compatible server-side state store (Valkey locally).

The Auth Service and Resource Server are the copyable reference; APISIX,
Keycloak, and Valkey are swappable infrastructure — provider and vendor
specifics live in config, never in Java or Lua.

Five directories, five components, no cloud.

- `frontend/` — React single-page application (SPA), cookie-authenticated, no in-browser OIDC library.
- `auth-service/` — Spring Boot Auth Service, OAuth2 confidential client +
  custom Redis-compatible `tx:{state}` and `sess:{sid}` repositories,
  per-session refresh lock, `/internal/resolve` as OAuth Resource Server.
- `api-gateway/` — APISIX gateway: `/api/**` routing with allowlist, signed CSRF
  validation, bearer injection. Holds no session-store handle — it reads the
  opaque sid from the cookie and resolves it via `/internal/resolve` (Client
  Credentials).
- `backend-resource-server/` — Spring Boot Resource Server, JSON Web Token (JWT) validation
  only.
- `authorization-server/` — Keycloak realm + Compose.

## Ownership

- Frontend Agent: `frontend/`
- Auth Service Agent: `auth-service/`
- API Gateway Agent: `api-gateway/` (APISIX config; not a Spring module)
- Backend Agent: `backend-resource-server/`
- Authorization Server Agent: `authorization-server/`
- Test Agent: verification scripts and cross-service tests
- Security Agent: threat model and negative auth cases
- Docs Agent: docs scoped to the assigned task

Auth Service and API Gateway have separate ownership boundaries:

- The Auth Service owns OAuth/OIDC client behavior and writes `tx:{state}`
  and `sess:{sid}`.
- The API Gateway owns routing, the `/api/**` allowlist, CSRF validation, and
  bearer injection; it holds no store handle and resolves the sid via
  `/internal/resolve`.
- They share only the documented JSON schema in SPEC-0001 §"`sess:{sid}`
  schema contract" and the `/internal/resolve` contract.

Coordinate before editing `AGENTS.md`, root build files, root
`compose.yaml`, shared verification scripts, or Keycloak realm files once
other slices depend on them.

## Security Rules

Never:

- commit secrets, tokens, cookies, private keys, generated realm secrets,
  or real user data
- enable OAuth implicit flow or password grant for any reference client
- ship a public-client SPA — the SPA must remain cookie-authenticated
- store any token, code, or claim in `localStorage`, `sessionStorage`,
  IndexedDB, or JS-readable cookies
- disable issuer, audience, expiration, signature, or algorithm validation
- use wildcard redirect URIs or wildcard Cross-Origin Resource Sharing (CORS) origins for protected APIs
- hand-roll crypto, Proof Key for Code Exchange (PKCE), OIDC discovery, JSON Web Key Set (JWKS) parsing, callback
  validation, or session encoding when proven libraries exist
- proxy arbitrary upstream URLs through the API Gateway — `/api/**` is allowlisted

Ask first:

- changing Java, Spring Boot, React, Keycloak, or Valkey major versions
- adding a major dependency or framework
- replacing Spring Security OAuth2 Client, the custom Redis-compatible
  transaction/session repositories, or the OIDC library choices
- changing directory ownership
- adding any non-local infrastructure

## Verifying changes

A change is done only when the gates pass — never report "green" off a subset.

- Changes to code, config, realm, or compose files must pass the **full live
  e2e battery** before they are done or committed, not just unit tests. Don't
  skip on the grounds that a change "can't affect" a gate.
- Authoritative gate: `RUN_FULL_STACK_AUTH=1 sh scripts/verify-all.sh` (static
  gates — lint, type-check, unit suites, secret scan, contract strings — plus
  the live stack), then `sh scripts/up.sh` → `RUN_LIVE_CONFORMANCE=1 sh
  scripts/e2e-conformance.sh`. The standalone `e2e-*` scripts are subsets that
  skip the static gates.
- Behavior is fixed by `SPEC-0001`; a behavior change updates the spec and its
  gate in the same change, tests-first (red → green).
- `.claude/skills/verify-oidc-reference` runs these gates correctly under Docker
  or Podman; `.claude/skills/extend-oidc-flow` carries the conventions for
  adding a flow.

## Commits

- Conventional-commit prefixes: `feat`, `fix`, `docs`, `test`, `refactor`, `chore`.
- No `Co-Authored-By` trailer for AI assistants.

## Canonical Docs

- `docs/specs/SPEC-0001-core-oidc-flows.md` — the build contract.
- `docs/architecture/overview.md` — architecture orientation.
- `docs/architecture/architecture-decisions.md` — rationale and rejected
  alternatives.
- `docs/testing/red-green-workflow.md`, `docs/testing/verification-gates.md`.
