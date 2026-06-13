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
gotcha, the pinned Node, manual-Playwright routing, and the Podman-only
Testcontainers / prune quirks. Skipping it is the usual cause of a stack that
won't boot.

## Gates (identical commands on both runtimes)

- Per-component + secret scan: `sh scripts/verify-all.sh`
- Full stack + gateway suite: `RUN_FULL_STACK_AUTH=1 sh scripts/verify-all.sh`
- Canonical authenticated proof: `just e2e-auth`
- Conformance (C8 trust-id, C9 session-window): **needs a stack already up — it
  does NOT bring up its own** (its header says "Requires a running stack (run
  `scripts/up.sh` first)"; it only force-recreates `auth-service --no-deps`).
  Run it as: `sh scripts/up.sh` → `RUN_LIVE_CONFORMANCE=1 sh scripts/e2e-conformance.sh`
  → `docker compose down -v`. Run bare after another gate tore the stack down and
  it hits a dead `:9080` and fails (`rc=1`, zero `[FAIL]` lines — a false failure).
- IdP portability (alt-claim realm): `sh scripts/e2e-portability.sh`
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
the summary line. Separate a real failure from the known environmental ones
(Node-version `App.test.tsx`; Podman Testcontainers-Ryuk) and say which. If you
started a stack, note its final state (`e2e-portability` leaves the alt realm).
