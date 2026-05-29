# Verification Gates

These commands will become canonical as the project is implemented. Until then,
task packets should name the closest available command.

## Planned Full Gate

```bash
./scripts/verify-all.sh
```

Expected checks:

- Format check.
- Frontend lint and typecheck.
- Frontend unit tests.
- BFF compile and unit tests.
- Resource Server compile and unit tests.
- Backend (BFF + RS) integration tests.
- Keycloak realm import smoke test (static + real-token issuance).
- OIDC discovery and JWKS tests.
- Browser saved-request E2E: top-level navigation to a protected URL
  while unauthenticated, OAuth round-trip, callback landing page sets a
  Strict session cookie, browser ends on the originally-requested URL with
  `200`.
- XHR 401 test: `fetch('/api/me')` without session returns `401` with
  no `Location` header and does not start the OAuth flow.
- Client Credentials E2E (no BFF in path): real `curl` to AS for a
  service-client token, real `curl` to RS `/api/jobs` with the bearer
  token, expects `200`.
- Secret scan.
- Docs link/check consistency.

## Planned Focused Gates

```bash
./scripts/verify-frontend.sh
./scripts/verify-bff.sh
./scripts/verify-backend.sh
./scripts/verify-auth-server.sh
./scripts/verify-contract-strings.sh
./scripts/verify-cross-service.sh
```

`verify-contract-strings.sh` is a spec-drift guard, not a runtime security
test. It checks that active docs/tasks still name the required BFF/session
contracts and do not regress to the old public-SPA OAuth model.
It also guards the BFF storage decision: custom Redis-compatible `tx:{state}` and
`sess:{sid}` repositories are the contract, not a framework-managed HTTP
session store.

`verify-cross-service.sh` always runs static contract checks for
saved-request replay, callback landing page, XHR/fetch 401, and Client
Credentials. Set
`RUN_LIVE_CROSS_SERVICE=1` with `OIDC_TOKEN_URL`,
`OIDC_SERVICE_CLIENT_ID`, `OIDC_SERVICE_CLIENT_SECRET`, and `RS_JOBS_URL`
to run the live service-client-token-to-RS `/api/jobs` check.

## Gate Rule

Every task final report must include:

- Command run.
- Pass/fail result.
- Any skipped gate and why it was skipped.
