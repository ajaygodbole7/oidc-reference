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

2. **Frontend uses the pinned Node** in `frontend/.nvmrc` (Node 20): `cd
   frontend && nvm use`. A much newer Node makes `App.test.tsx` fail under
   jsdom/testing-library — environmental, not a regression.

3. **Manual Playwright runs** (the scripts handle this themselves) route `/auth`
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
