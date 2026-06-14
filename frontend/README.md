# Frontend

React + TypeScript + Vite SPA. No OAuth/OIDC client library. The BFF
owns the flow.

## How auth works here

- Sign in is a top-level navigation to `/auth/login` (a BFF endpoint).
- After Keycloak login, the browser lands back on the originally-requested
  URL with an `HttpOnly` session cookie set by the BFF. This uses
  saved-request replay; an explicit `/auth/login` defaults to `/`.
- The SPA loads user identity from `/auth/me`.
- All API calls go to `/api/*` with `credentials: "include"`.
- Sign out POSTs `/auth/logout` with the CSRF header, then performs a
  top-level navigation to the BFF-provided logout redirect.

The browser never holds an access, refresh, or ID token.

## Local Contract

- Dev server: `http://127.0.0.1:5173`
- BFF target: `http://localhost:8081` (override via `VITE_BFF_TARGET`)
- Vite proxies `/auth` and `/api` → BFF so the session cookie is same-origin
  in dev.

## Commands

```bash
npm install
npm run dev
npm run build
npm run test                              # Vitest unit tests
npm run test:e2e                          # Playwright anonymous flow (auth.spec.ts)
just e2e-auth                             # Authenticated full-stack proof (reference-flow.spec.ts)
../scripts/verify-frontend.sh
```

## Harness Requirements

- `package.json` defines `build`, `test`, and `test:e2e`.
- `playwright.config.ts` stores traces and screenshots under
  `frontend/test-results/`.
- Tests assert no tokens are written to `localStorage`, `sessionStorage`,
  `document.cookie`, or IndexedDB.
