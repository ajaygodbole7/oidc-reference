# Verification Gates

What this is: the test gates, from fastest to most complete, and when to run each.

Use the smallest gate that proves the change, then run the broader gate before
claiming the reference still works end-to-end.

## Fast Gate

```sh
just test
```

Runs component tests without Docker.

## Static Contract Gate

```sh
just check
```

Runs the spec-drift guard and committed-secret scan. The contract-string check
is not a runtime security test; it prevents the docs/tasks from drifting back
to the old public-SPA OAuth shape or framework-session storage.

## Live Infrastructure Gate

```sh
just test-e2e
```

Starts the full Compose topology, runs Keycloak realm/discovery/token smoke
checks, then runs the APISIX gateway behavior suite including real-session
refresh delegation.

## Canonical Authenticated Proof

```sh
just e2e-auth
```

Starts the full Compose topology and runs:

- Browser login through Keycloak.
- `/auth/me` session identity.
- Saved-request replay.
- XHR/fetch 401 behavior.
- Authenticated `/api/**` proxying with no browser bearer token.
- Resource Server role/scope enforcement.
- RP-initiated logout continuation.
- Gateway refresh delegation using a real login-derived `sess:{sid}`.

This is the proof to run before saying the reference implements the target
sequence diagram.

## Hermetic Portability Proof

```sh
just e2e-portability
```

Runs the same full-stack proof against a second Keycloak realm imported into
the same local Keycloak container. The alternate realm differs from the
reference realm in the places that must be configuration-driven:

- roles are emitted as top-level `groups`, not `realm_access.roles`.
- Resource Server audience is `oidc-reference-alt-api`, not
  `oidc-reference-api`.

This gate is the enforced IdP-portability proof because it is re-runnable
without third-party credentials. It does not try to force Keycloak to emit
`scp`. That branch is covered by Resource Server unit tests and by the
provider runbooks for IdPs that emit `scp`.

## Full Local Verification

```sh
just cibuild
RUN_FULL_STACK_AUTH=1 ./scripts/verify-all.sh
```

`just cibuild` runs the default non-browser verification suite. Add
`RUN_FULL_STACK_AUTH=1` when you want the live-infra gate included from
`verify-all.sh`.

## Reporting Rule

Every task final report must include:

- Commands run.
- Pass/fail result.
- Any skipped gate and why it was skipped.
