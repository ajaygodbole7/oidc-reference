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
and the `justfile`. Read the script before running it. The scripts call
`docker compose`, so they work as-is on Docker Desktop and on Podman once
`docker compose` points at the Podman socket.

**Before running any gate, do the one-time environment setup** in
[`references/environments.md`](references/environments.md): container-runtime
wiring (Docker Desktop vs Podman socket), the APISIX-render-before-`compose-up`
gotcha, the host tools (`ripgrep`, Node ≥20.19 — the suite is version-agnostic),
manual-Playwright routing, and the Podman-only Testcontainers / prune quirks.
Skipping it is the usual cause of a stack that won't boot or a false gate failure.

## Gates (identical commands on both runtimes)

**The authoritative "everything green" gate is `RUN_FULL_STACK_AUTH=1 sh
scripts/verify-all.sh` PLUS the conformance run below.** That is the only command
that runs BOTH the static gates (ESLint, type-check, per-module unit suites,
secret scan, contract strings) AND the live e2e stacks. **The individual live e2e
scripts (`e2e-auth`, `e2e-portability`, `e2e-c8-altids`, `test-e2e`) run NO ESLint,
NO type-check, NO per-module units, NO secret scan** — a green live battery has a
static-analysis blind spot (a real feature shipped a frontend
`no-unsafe-member-access` error that passed 19/19 Playwright + every unit suite and
was caught only here). Never report "green" off the live battery alone.

- Per-component + secret scan (static only, no live stack): `sh scripts/verify-all.sh`
- **Everything (static + live, the mandatory gate):** `RUN_FULL_STACK_AUTH=1 sh scripts/verify-all.sh`
- Canonical authenticated proof (subset; no lint): `just e2e-auth`
- Conformance (C8 trust-id, C9 session-window): **needs a stack already up — it
  does NOT bring up its own** (its header says "Requires a running stack (run
  `scripts/up.sh` first)"; it only force-recreates `auth-service --no-deps`).
  Run it as: `sh scripts/up.sh` → `RUN_LIVE_CONFORMANCE=1 sh scripts/e2e-conformance.sh`
  → `docker compose down -v`. Run bare after another gate tore the stack down and
  it hits a dead `:9080` and fails (`rc=1`, zero `[FAIL]` lines — a false failure).
- IdP portability (alt-claim realm): `sh scripts/e2e-portability.sh`
- Distributed refresh-lock proof (NOT in `verify-all`; on-demand): a separate
  TWO-replica stack proving concurrent `/internal/resolve` at both replicas for
  one session collapse to a single upstream refresh. It does NOT bring up its
  own stack — bring it up first, then drive, then tear down:
  `docker compose -f compose.yaml -f compose.distributed-lock.yml up -d --build keycloak valkey auth-service auth-service-2`
  → `bash scripts/e2e-distributed-lock.sh [TRIALS]`
  → `docker compose -f compose.yaml -f compose.distributed-lock.yml down -v`.
  The harness **auto-detects docker vs podman** for its Valkey `exec` (it holds
  no `docker compose` assumption; override with `CONTAINER_RUNTIME=docker|podman`)
  — no `podman→docker` shim needed on a Docker-only host. Judge by the summary
  line, NOT the exit code (it exits 0 even on conflict): PASS is
  `both-200=N  409-conflict=0`; a `409` means the replicas did not share the lock.
- Java unit: `cd auth-service && ./mvnw test`, `cd backend-resource-server && ./mvnw test`
  (Podman: with the Testcontainers env from `references/environments.md`)
- Frontend unit: `cd frontend && npx vitest run`

**Sequencing the full battery.** `e2e-auth`, `e2e-portability`, and `e2e-c8-altids`
each bring up + tear down their own stack; `e2e-conformance` does not (above). Run
the gates **sequentially**, not concurrently — one stack at a time. Do **not** fold
`e2e-portability` into `e2e-auth`: two full stack builds back-to-back trip APISIX
cold-start flakiness (sometimes >240s to bind on a loaded/old Docker, ~10s warm).
Prefer Compose health-gating (`--wait`/healthchecks) over hand-tuned `curl --retry`;
bring the stack up warm, then run against it; avoid rapid `down→up` churn. To
restart a single stopped service mid-suite use `docker compose start <svc>` (NOT
`up` — `up` re-evaluates config against the current shell's env and can recreate
the container with drifted secrets like `CSRF_SIGNING_KEY`).

## Reporting

Quote the actual pass/fail counts from the output — never claim green without
the summary line. Separate a real failure from an environmental one (e.g. Podman
Testcontainers-Ryuk, or a missing host tool like `ripgrep` making the contract
gates false-fail) and say which. If you started a stack, note its final state
(`e2e-portability` leaves the alt realm).
