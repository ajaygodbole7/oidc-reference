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
to the old public-single-page application (SPA) OAuth shape or framework-session storage.

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
- Relying Party (RP)-initiated logout continuation.
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

This gate is the enforced Identity Provider (IdP)-portability proof because it is re-runnable
without third-party credentials. It does not try to force Keycloak to emit
`scp`. Both the array and space-delimited string forms are covered by Resource
Server unit tests. The real decoder suite also accepts compatibility
`typ=JWT` and RFC 9068 `typ=at+JWT`, while rejecting missing and unrelated
types.

## Gateway Boundary Proof

The live gateway suite proves that APISIX replaces the opaque browser session
with exactly one upstream bearer while stripping browser credentials and
hop-by-hop headers. Its test-only Resource Server endpoint never reflects the
bearer: it returns only the Authorization value count, recognized scheme, and a
SHA-256 fingerprint. The harness compares that fingerprint with the resolved
token and separately asserts that the token bytes do not appear in the response.

Forwarding is considered proven only by a deliberate 2xx or 4xx response.
Redirects, transport status `000`, empty status, and 5xx responses fail the
assertion because they can occur before the intended upstream handler receives
the request.

## Distributed Refresh-Lock Proof

```sh
just e2e-distributed-lock
```

Runs two Auth Service replicas against one shared Redis-compatible state store,
with `app.refresh-lock=distributed`, then fires concurrent near-expiry
`/internal/resolve` requests for the same `sid`. Both resolves must return 200:
one replica refreshes, the other re-reads the rotated session. A 409 indicates
cross-instance refresh-token reuse and means the distributed lock path is broken.

It also asserts cross-replica **write**-visibility: the collapsed refresh rotates
`sess:{sid}` → `sess:{sid'}` on whichever replica won the lock, and the harness
then resolves the rotated sid at **both** replicas and requires 200 — proving the
rotation write (not just the read) landed in shared state. The summary line
reports `write-visibility-ok` / `write-visibility-fail`.

Run this targeted gate before changing refresh-token rotation, sid rotation,
`SessionIndexes`, or `DistributedRefreshKeyLock`. It is intentionally separate
from routine E2E because the default reference path remains single-instance.

## Distributed Cross-Replica Browser Proof

```sh
just e2e-distributed-browser
```

Belt-and-suspenders proof of the full real path across two Auth Service replicas:
browser cookie → Vite (`:5173`) → APISIX (`:9080`) → two replicas, under a
deterministic split the driver configures in the rendered gateway config —
`/auth/*` → replica-1 (writes `tx:{state}` + `sess:{sid}`), the gateway's
`/internal/resolve` → replica-2 (reads `sess:{sid}`). So every `/api/user-data`
200 proves replica-2 resolved a session that replica-1 created, off shared
Valkey. The Playwright spec logs in N users (default 4) as isolated browser
contexts, then fires all their `/api` resolves concurrently and asserts each sees
only its own identity — N concurrent cross-replica resolves with no cross-talk.
(Logins are sequential setup; the concurrency under test is the resolve fan-out.) Brings up and tears down its own stack; on-demand /
before-merge, not part of routine E2E (two replicas plus an extra image build
trips APISIX cold-start flakiness). The same-session refresh-collapse contention
case stays in the scripted gate above.

## Full Local Verification

```sh
just cibuild
RUN_FULL_STACK_AUTH=1 ./scripts/verify-all.sh
```

`just cibuild` runs the default non-browser verification suite. Add
`RUN_FULL_STACK_AUTH=1` when you want the live-infra gate included from
`verify-all.sh`.

## Dependency-Bump Re-check

Library defaults move silently across versions. After any Spring Boot, Nimbus,
or Spring Security bump, re-run both Maven suites and specifically re-check the
two validations that used to be inherited from library defaults:

- multi-audience `azp` rejection (auth-service `JwtOidcIdTokenValidator`), and
- JWS `typ` acceptance of `JWT` and RFC 9068 `at+JWT` (Resource Server
  `SecurityConfig`).

The `4.1.0-RC1` → `4.1.0` GA bump silently relaxed both. Both are now enforced
explicitly in code (`JwtTypeValidator("JWT", "at+JWT")` plus an explicit `azp`
rule) rather than delegated to a default validator chain — keep them explicit so
a future bump cannot silently re-break them.

## Reporting Rule

Every task final report must include:

- Commands run.
- Pass/fail result.
- Any skipped gate and why it was skipped.
