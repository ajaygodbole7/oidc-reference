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
It does not start the live Auth Service / Resource Server / Keycloak browser
flow.

## Full-Stack Auth Verification

```bash
RUN_FULL_STACK_AUTH=1 ./scripts/verify-all.sh
```

or directly:

```bash
just test-e2e        # or: sh scripts/test-e2e.sh
```

The live-infra E2E renders the APISIX config and brings up the Compose stack
(Keycloak, Valkey, APISIX). It runs the IdP realm/discovery/token smoke and the
gateway behaviour suite against it, then tears the stack down.

For the full browser login flow, use `just up` + `just dev` and drive the SPA at
`http://127.0.0.1:5173`.

## Canonical Authenticated Proof

```bash
just e2e-auth        # or: sh scripts/e2e-auth.sh
```

`just e2e-auth` is the canonical authenticated local proof. It runs
`frontend/tests/e2e/reference-flow.spec.ts` against the live stack. The test
covers:

- a real Keycloak login through the Auth Service,
- an authenticated `/api/**` call through APISIX, and
- RP-initiated logout through the same-origin `/auth/logout/continue` handle.

It also asserts the token-isolation invariant: no access/refresh/ID token in
browser storage, JS-readable cookies, or SPA-readable bodies.

## Harness Steps

1. Build frontend.
2. Build Resource Server (`backend-resource-server/`).
3. Build Auth Service (`auth-service/`).
4. Render the APISIX route config and start Keycloak, Valkey, Auth Service,
   Resource Server, and APISIX via the root `compose.yaml`. Keycloak uses
   embedded H2; there is no separate database.
5. Import the realm.
6. Wait for Compose health checks: Auth Service and Resource Server stay
   internal-only and are reachable by APISIX through service-name DNS.
7. Run OIDC discovery + JWKS smoke tests.
8. Run Resource Server JWT-validation tests (positive + negative).
9. Run Client Credentials E2E (no Auth Service or API Gateway in path):
   `curl` AS for a service-client token; `curl` RS `/api/jobs` with the
   bearer token; expect `200`.
10. Start the frontend dev server (Vite proxies `/auth/*` to the Auth
    Service `:8081` and `/api/**` to APISIX `:9080` with
    `changeOrigin: false` + `X-Forwarded-*` headers).
11. Run browser saved-request E2E: top-level navigation to a protected
    URL while unauthenticated, Keycloak login automation, browser ends
    on the originally-requested URL with `200`.
12. Run XHR 401 test: `fetch('/api/me')` from the SPA without session
    returns `401` with no `Location`.
13. Run RP-initiated logout E2E: `POST /auth/logout` with CSRF header, the
    Auth Service deletes `sess:{sid}` and returns the same-origin
    `/auth/logout/continue` handle, which redirects through the Keycloak
    `end_session_endpoint`; the browser lands back on the SPA root
    unauthenticated.
14. Run secret scan.
15. Tear down local services.

## Success Criteria

- The full stack starts locally.
- The configured issuer matches Keycloak discovery.
- Protected endpoints enforce expected access.
- Negative auth cases fail closed.
- Saved-request replay leaves the browser on the originally-requested
  URL (not unconditionally `/`).
- XHR `fetch` to `/api/*` without session returns `401` with no
  `Location` header.
- Service-client flow reaches `/api/jobs` end-to-end with neither the
  Auth Service nor the API Gateway in path.
- No secrets are committed.
