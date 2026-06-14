# Environment setup for the verify gates

The `verify-oidc-reference` gate commands are identical on Docker Desktop and
Podman; this file is the per-environment setup they assume. Do it once before
running any gate. Skipping it is the usual cause of a stack that won't boot.

## 1 — Pick the container runtime

**Docker Desktop (or any real Docker daemon):** nothing to do — `docker compose`
in the scripts works directly.

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

**Exception — `scripts/e2e-distributed-lock.sh` self-detects.** Unlike the other
scripts (which call `docker compose` and rely on the `DOCKER_HOST` redirect above
under Podman), this harness picks the runtime for its Valkey `exec` itself:
whichever runtime actually holds the `oidc-reference-valkey-1` container, else the
first with a reachable engine (override `CONTAINER_RUNTIME=docker|podman`). So it
needs **no `podman→docker` shim on a Docker-only host** and drives `podman exec`
directly under Podman. You still bring its two-replica stack up with your
runtime's `compose` per the SKILL gate.

## 2 — Prerequisites (both runtimes)

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

2. **`ripgrep` (`rg`) on PATH.** The contract gates (`verify-contract-strings`,
   `verify-cross-service`) search with `rg`; without it every `require_present`
   false-fails (rg exits non-zero → "missing contract string"). Install it:
   `brew install ripgrep` / `apt-get install -y ripgrep`.

3. **Node: any version ≥ 20.19** (`frontend/package.json` `engines`, a floor — each
   machine uses its own installed Node, no pin). The suite is Node-version-agnostic:
   `frontend/src/test-setup.ts` binds jsdom's Web Storage so the tests pass on
   whatever Node is installed, including Node 24+ where the native `localStorage`
   global would otherwise shadow jsdom's and break the token-isolation assertions.
   Run `npm install` (or `npm ci`) per machine so the platform/Node-appropriate
   native bindings (e.g. the rolldown prebuilt vitest/vite uses) are fetched and,
   on macOS, ad-hoc signed by the `postinstall` hook.

4. **Manual Playwright runs** (the scripts handle this themselves) route `/auth`
   through APISIX because the Auth Service isn't host-published: set
   `VITE_AUTH_TARGET=http://127.0.0.1:9080`, and `npx playwright install chromium` once.

## 3 — Runtime-specific quirks

- **Podman only — Testcontainers.** The Java parity test (`RedisStateStoreParityTest`)
  starts a real `valkey` container; Podman's default reaper (Ryuk) fails to
  launch, so export `TESTCONTAINERS_RYUK_DISABLED=true` (alongside `DOCKER_HOST`).
  On Docker Desktop, Testcontainers works out of the box — do **not** set this.
- **Podman only — global prune danger.** Never `podman network prune` / `image
  prune` without scoping; it removes other projects' idle resources. To clean up
  this stack, remove its own objects: `podman compose down -v --remove-orphans`
  then `podman image prune -f` (dangling only).
