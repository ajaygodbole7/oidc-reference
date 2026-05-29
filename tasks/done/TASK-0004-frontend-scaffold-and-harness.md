# TASK-0004: Frontend Scaffold And Harness

> **SUPERSEDED.** This task encoded a public-client SPA architecture
> (`oidc-reference-spa`, in-browser PKCE via `oidc-client-ts`,
> `/callback` route on the SPA). The project moved to the BFF session
> pattern: the frontend is cookie-authenticated, has no in-browser
> OIDC library, and calls only `/auth/*` and `/api/*` endpoints on the
> BFF. The current contract is `docs/specs/SPEC-0001-core-oidc-flows.md`,
> `docs/goals/GOAL-0001-frontend-react-pkce.md`, and the root README
> diagrams. The body below is preserved as historical record only.

## Objective

Create the minimal React, TypeScript, Vite, and Playwright frontend harness for
Authorization Code with PKCE.

## Linked Spec

- `docs/specs/SPEC-0001-core-oidc-flows.md`
- `docs/goals/GOAL-0001-frontend-react-pkce.md`

## Read First

- `AGENTS.md`
- `docs/agents/mandatory-turn-protocol.md`
- `docs/agents/execution-discipline.md`
- `docs/testing/red-green-workflow.md`

## Owned Paths

- `frontend/`
- `scripts/verify-frontend.sh`
- Frontend-specific docs or task notes

## Avoid Paths

- `backend-resource-server/`
- `authorization-server/`
- Root build files unless explicitly needed for frontend tooling

## Required Workflow

Assumptions:

- The frontend is a public OAuth client.
- Tokens must not be stored in `localStorage`.
- Keycloak runs at `http://localhost:8080` unless a task changes the local
  contract.

Ambiguities:

- OIDC client library is not selected yet. Choose one only after checking it
  supports Authorization Code with PKCE, `state`, and OIDC `nonce`.

Owned paths:

- Same as `Owned Paths`.

Success criteria:

- `npm run build`, `npm run test`, and `npm run test:e2e` exist.
- `./scripts/verify-frontend.sh` runs those commands.
- First Playwright test covers unauthenticated landing and login redirect start.
- Test artifacts path is documented.

Plan:

```text
1. Add minimal Vite/React/TS scaffold -> verify: npm run build exists
2. Add unit and Playwright harness -> verify: npm run test and npm run test:e2e exist
3. Add first auth-flow red test -> verify: failing test proves missing PKCE login behavior before implementation
```

## Commands

```bash
cd frontend
npm install
npm run build
npm run test
npm run test:e2e
../scripts/verify-frontend.sh
```

## Environment Contract

- `VITE_OIDC_ISSUER=http://localhost:8080/realms/oidc-reference`
- `VITE_OIDC_CLIENT_ID=oidc-reference-spa`
- `VITE_OIDC_REDIRECT_URI=http://localhost:5173/callback`
- `VITE_OIDC_POST_LOGOUT_REDIRECT_URI=http://localhost:5173/`
- `VITE_API_BASE_URL=http://localhost:8081`

## Done Criteria

- Frontend scaffold exists.
- Playwright config exists.
- Frontend verify script passes or fails only because dependent services are not
  running.
- Token storage test asserts no token is written to `localStorage`.

## Final Report

Include:

- Assumptions made.
- Files changed.
- Tests run.
- Result.
- Risks or follow-ups.

