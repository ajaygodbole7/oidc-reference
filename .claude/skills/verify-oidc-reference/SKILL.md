---
name: verify-oidc-reference
description: >-
  Run the oidc-reference verification gates (unit suites + verify-all + the
  live e2e-auth / e2e-conformance / e2e-portability stacks) correctly on this
  machine, under EITHER Docker Desktop or Podman. Use whenever asked to verify,
  test, run the gates, or "prove it works" for this repo. The repo's scripts are
  the source of truth for what to run; this skill adds the per-environment setup
  they assume (container runtime wiring, APISIX render, Testcontainers, Node).
---

# Verifying oidc-reference

The repo's scripts define *what* to run: `scripts/verify-all.sh`,
`scripts/e2e-auth.sh`, `scripts/e2e-conformance.sh`, `scripts/e2e-portability.sh`,
and the `Justfile`. Read the script before running it; this skill only adds the
*environment setup* those scripts assume. The scripts call `docker compose`, so
they work as-is on Docker Desktop and work on Podman once `docker compose` is
pointed at the Podman socket.

## Step 1 — pick the container runtime

**Docker Desktop (or any real Docker daemon):** nothing to do — `docker compose`
in the scripts works directly. Skip to Step 2.

**Podman:** the scripts say `docker compose`; point that at the Podman socket so
it doesn't hit Docker (or a shadowing daemon like OrbStack on PATH):
```sh
podman machine start 2>/dev/null || true
export DOCKER_HOST="unix://$(podman machine inspect --format '{{.ConnectionInfo.PodmanSocket.Path}}')"
```
Quick auto-detect either way:
```sh
docker info >/dev/null 2>&1 || \
  export DOCKER_HOST="unix://$(podman machine inspect --format '{{.ConnectionInfo.PodmanSocket.Path}}')"
```

## Step 2 — prerequisites (both runtimes)

1. **APISIX config is rendered before `compose up`.** Compose bind-mounts
   `api-gateway/apisix.yaml.local`. On **both** Docker and Podman, if that path
   does not exist when compose runs, the engine creates it as an empty
   **directory** and APISIX dies on boot. `scripts/*` already render first; only
   relevant if you bring the stack up by hand:
   ```sh
   GATEWAY_CLIENT_SECRET=LOCAL_DEV_GATEWAY_CLIENT_SECRET__CHANGE_BEFORE_DEPLOY \
   CSRF_SIGNING_KEY=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA= \
     sh scripts/render-apisix-config.sh
   ```
   If a bad run already created the directory: bring apisix down, `rm -rf
   api-gateway/apisix.yaml.local`, re-render, then `up --force-recreate apisix`.

2. **Frontend uses the pinned Node** in `frontend/.nvmrc` (Node 20): `cd
   frontend && nvm use`. A much newer Node makes `App.test.tsx` fail under
   jsdom/testing-library — environmental, not a regression.

3. **Manual Playwright runs** (the scripts handle this themselves) route `/auth`
   through APISIX because the Auth Service isn't host-published: set
   `VITE_AUTH_TARGET=http://127.0.0.1:9080`, and `npx playwright install chromium` once.

## Step 3 — runtime-specific quirks

- **Podman only — Testcontainers.** The Java parity test (`RedisStateStoreParityTest`)
  starts a real `valkey` container; Podman's default reaper (Ryuk) fails to
  launch, so export `TESTCONTAINERS_RYUK_DISABLED=true` (alongside `DOCKER_HOST`).
  On Docker Desktop, Testcontainers works out of the box — do **not** set this.
- **Podman only — global prune danger.** Never `podman network prune` / `image
  prune` without scoping; it removes other projects' idle resources. To clean up
  this stack, remove its own objects: `podman compose down -v --remove-orphans`
  then `podman image prune -f` (dangling only).

## Step 4 — gates (identical commands on both runtimes)

- Per-component + secret scan: `sh scripts/verify-all.sh`
- Full stack + gateway suite: `RUN_FULL_STACK_AUTH=1 sh scripts/verify-all.sh`
- Canonical authenticated proof: `just e2e-auth`
- Conformance (C8 trust-id, C9 session-window): `RUN_LIVE_CONFORMANCE=1 sh scripts/e2e-conformance.sh`
- IdP portability (alt-claim realm): `sh scripts/e2e-portability.sh`
- Java unit: `cd auth-service && ./mvnw test`, `cd backend-resource-server && ./mvnw test`
  (Podman: with the Testcontainers env from Step 3)
- Frontend unit: `cd frontend && npx vitest run`

## Reporting

Quote the actual pass/fail counts from the output — never claim green without
the summary line. Separate a real failure from the known environmental ones
(Node-version `App.test.tsx`; Podman Testcontainers-Ryuk) and say which. If you
started a stack, note its final state (`e2e-portability` leaves the alt realm).
