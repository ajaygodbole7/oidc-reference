# Local Verification Harness

This document describes the local verification harness.

## Goal

A fresh checkout should be able to verify the reference stack without cloud
services.

## Fast Verification

```bash
./scripts/verify-all.sh
```

By default this runs static contract checks plus unit/browser-contract suites.
It does not start the live BFF/Resource Server/Keycloak browser flow.

## Full-Stack Auth Verification

```bash
RUN_FULL_STACK_AUTH=1 ./scripts/verify-all.sh
```

or directly:

```bash
./scripts/verify-full-stack-auth.sh
```

The full-stack script starts root Docker Compose infrastructure
(Postgres, Keycloak, Valkey), starts the Resource Server on `8082`, starts the
BFF on `8081`, verifies live Client Credentials against `/api/jobs`, then runs
Playwright with `E2E_FULL_STACK=1`.

If the Keycloak realm JSON changed and an existing persistent local Postgres
volume is present, reset the imported realm before verifying:

```bash
RESET_KEYCLOAK_REALM=1 ./scripts/verify-full-stack-auth.sh
```

## Harness Steps

1. Build frontend.
2. Build Resource Server.
3. Build BFF.
4. Start Keycloak + Postgres + Valkey via the root `compose.yaml`.
5. Import the realm.
6. Start Resource Server (`backend-resource-server/`).
7. Start BFF (`bff/`); depends on Valkey + Keycloak being reachable.
8. Run OIDC discovery + JWKS smoke tests.
9. Run Resource Server JWT-validation tests (positive + negative).
10. Run Client Credentials E2E (no BFF in path): `curl` AS for a
    service-client token; `curl` RS `/api/jobs` with the bearer token;
    expect `200`.
11. Start frontend dev server (Vite proxies `/auth` and `/api` to the
    BFF with `changeOrigin: false` + `X-Forwarded-*` headers).
12. Run browser saved-request E2E: top-level navigation to a protected
    URL while unauthenticated, Keycloak login automation, browser ends
    on the originally-requested URL with `200`.
13. Run XHR 401 test: `fetch('/api/me')` from the SPA without session
    returns `401` with no `Location`.
14. Run RP-initiated logout E2E: `POST /auth/logout` with CSRF header,
    BFF deletes `sess:{sid}`, Keycloak `end_session_endpoint` reached,
    browser lands back on the SPA root unauthenticated.
15. Run secret scan.
16. Tear down local services.

## Success Criteria

- The full stack starts locally.
- The configured issuer matches Keycloak discovery.
- Protected endpoints enforce expected access.
- Negative auth cases fail closed.
- Saved-request replay leaves the browser on the originally-requested
  URL (not unconditionally `/`).
- XHR `fetch` to `/api/*` without session returns `401` with no
  `Location` header.
- Service-client flow reaches `/api/jobs` end-to-end with no BFF in
  path.
- No secrets are committed.
