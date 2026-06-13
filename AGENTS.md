# AGENTS.md

- **What this is:** the operating contract for anyone working in this repo —
  Claude Code, Codex, or human.
- **Who it's for:** contributors making code or doc changes.
- **Where to start:** read this file, then `docs/specs/SPEC-0001-core-oidc-flows.md`
  (the build contract) and the README sequence diagrams (the canonical flows).

## Project Goal

A local OAuth 2.1 / OIDC reference using the Backend-for-Frontend session
pattern in its split-implementation shape.

- The browser never holds tokens.
- A confidential Auth Service owns the OAuth/OIDC client role.
- An API Gateway (APISIX) owns routing and bearer injection.
- Tokens live in a Redis-compatible server-side state store (Valkey locally).

Five directories, five components, no cloud.

- `frontend/` — React SPA, cookie-authenticated, no in-browser OIDC library.
- `auth-service/` — Spring Boot Auth Service, OAuth2 confidential client +
  custom Redis-compatible `tx:{state}` and `sess:{sid}` repositories,
  per-session refresh lock, `/internal/resolve` as OAuth Resource Server.
- `api-gateway/` — APISIX gateway, `/api/**` routing with allowlist,
  tolerant `sess:{sid}` reader, bearer injection, signed CSRF validation,
  Client Credentials to call `/internal/resolve`.
- `backend-resource-server/` — Spring Boot Resource Server, JWT validation
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
- The API Gateway owns routing, the `/api/**` allowlist, and the tolerant
  `sess:{sid}` reader.
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
- `docs/testing/red-green-workflow.md`, `docs/testing/verification-gates.md`.
