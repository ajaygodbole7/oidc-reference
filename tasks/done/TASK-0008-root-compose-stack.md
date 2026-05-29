> **SUPERSEDED 2026-05-25** by RESHAPE-FRAME-B.md. The reshape's Commit 3 (compose + Traefik ingress) and the new TASK-0008-auth-service-spec-to-code / TASK-0009-api-gateway-spec-to-code together cover this task's scope. The `bff/` Dockerfile and combined-BFF cold-start flow this task targeted no longer exist in the target architecture.

# TASK-0008: Root Compose Stack — cold-start E2E

## Objective

Make `docker compose up -d` plus a single cold-start verification command
exercise the entire stack — Keycloak + Postgres + Valkey + BFF + Resource
Server + frontend (dev or static) — without depending on `./mvnw
spring-boot:run` running outside Compose.

## Linked Spec

- `docs/specs/SPEC-0001-core-oidc-flows.md`
- Root `README.md` (canonical sequence diagram is what the cold-start
  flow must satisfy end-to-end)
- Backlog item "Root Compose stack" in `tasks/backlog.md`

## Read First

- `AGENTS.md`
- `docs/agents/mandatory-turn-protocol.md`
- `docs/agents/execution-discipline.md`
- `docs/goals/GOAL-0003-authorization-server-keycloak.md`
- `docs/goals/GOAL-0004-bff.md`
- `docs/goals/GOAL-0002-backend-resource-server.md`
- `compose.yaml` (the comment "A future task may package them as
  containers" is the existing pointer to this task)

## Owned Paths

- `compose.yaml`
- `bff/Dockerfile` (new)
- `backend-resource-server/Dockerfile` (new)
- `frontend/Dockerfile` (new, optional based on slice 4 outcome)
- `scripts/verify-full-stack-auth.sh` (mode switch: in-compose vs
  out-of-compose BFF/RS)
- `scripts/verify-all.sh`
- README / Compose-related docs only when behavior changes

## Avoid Paths

- `bff/src/`, `backend-resource-server/src/`,
  `authorization-server/realm/`, `frontend/src/`,
  `docs/specs/`, `docs/goals/`, `tasks/backlog.md`. Implementation
  code, spec, and goals are the contract — do not edit them to make
  Compose simpler.

## Required Workflow

Before coding, record:

- Assumptions:
  - The local stack stays single-host Docker on macOS/Linux. No
    Kubernetes manifests in this task.
  - The frontend's "dev" mode is a Vite dev-server container. A
    "static" mode is a multi-stage Vite build served by nginx; pick
    one in Slice 4, not both.
- Ambiguities:
  - Whether the BFF/RS containers replace `./mvnw spring-boot:run` or
    coexist with it as an opt-in mode. Tentative: coexist via a
    `COMPOSE_PROFILES=apps` profile so contributors who prefer the
    inner-loop iteration keep it.
- Owned paths: see above.
- Success criteria: mirror the Done Criteria below.

Plan:

```text
1. Add Keycloak service healthcheck so depends_on conditions are
   meaningful across the stack
   -> verify: docker compose up -d ; docker compose ps shows keycloak
      healthy within 90s.

2. Add bff/Dockerfile (Spring Boot layered image via the existing
   spring-boot-maven-plugin; jlink-optional but not required)
   -> verify: docker build -t oidc-reference-bff bff/ succeeds;
      container runs java with non-root user; image size under 350MB.

3. Add backend-resource-server/Dockerfile (same shape as BFF)
   -> verify: docker build -t oidc-reference-rs backend-resource-server/
      succeeds.

4. Decide dev vs static for the frontend container and add
   frontend/Dockerfile accordingly
   -> verify: docker build -t oidc-reference-frontend frontend/
      succeeds; container serves 200 on / and proxies /auth and /api to
      the BFF service hostname (not localhost) when the env var
      BFF_BASE_URL is set.

5. Extend compose.yaml with bff, rs, frontend services under a
   COMPOSE_PROFILES=apps profile. Inter-container hostnames replace
   localhost (BFF -> keycloak:8080, valkey:6379; RS -> keycloak:8080;
   frontend -> bff:8081). Expose 8081, 8082, 5173 on the host
   -> verify: COMPOSE_PROFILES=apps docker compose up -d ; all six
      services report healthy within 180s.

6. Add scripts/verify-cold-start.sh that wraps the above + curls the
   canonical flow start (/auth/login -> 302 to Keycloak authorize URL)
   -> verify: ./scripts/verify-cold-start.sh exits 0 from a fresh
      clone with only Docker installed.

7. Wire the cold-start script into verify-all.sh behind RUN_COLD_START=1
   (mirror the existing RUN_FULL_STACK_AUTH=1 pattern) and update the
   README's "How to run" section
   -> verify: RUN_COLD_START=1 ./scripts/verify-all.sh exits 0.
```

Then, per task discipline:

1. Run the current focused tests.
2. Add a failing test (or a failing verify command) where feasible.
3. Confirm the red failure.
4. Implement the smallest complete change.
5. Confirm green focused tests / verify.
6. Run the relevant verification gate.

## Done Criteria

- Keycloak has a working `healthcheck:` block; other services use
  `depends_on: condition: service_healthy` where it makes sense.
- `bff/Dockerfile` and `backend-resource-server/Dockerfile` produce
  runnable images with non-root users and explicit JVM tuning
  appropriate for containers (heap, MaxRAMPercentage).
- One container shape exists for the frontend (dev or static — not
  both).
- `COMPOSE_PROFILES=apps docker compose up -d` brings up the entire
  stack on inter-container hostnames; no `./mvnw spring-boot:run`
  required.
- `scripts/verify-cold-start.sh` exits 0 from a fresh clone with only
  Docker installed and exercises the canonical OIDC flow start.
- The script is wired into `verify-all.sh` behind `RUN_COLD_START=1`,
  mirroring the existing `RUN_FULL_STACK_AUTH=1` switch.
- No regression in the existing gates:
  `./mvnw test` (BFF + RS), `npm run build && npm run lint && npm test`
  (frontend), and `RESET_KEYCLOAK_REALM=1
  ./scripts/verify-full-stack-auth.sh` (5/5 Playwright).

## Final Report

Include:

- Assumptions made.
- Slices landed vs deferred.
- Files changed.
- Tests / verify commands run (with pass/fail).
- Result.
- Risks or follow-ups (especially anything that suggests a spec gap).
