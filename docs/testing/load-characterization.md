# Load characterization — does the BFF scale?

**Status:** proposed, awaiting review. Charter for a `just e2e-load` gate; no
harness built yet.

> **Reviewer:** the first question is whether a load characterization belongs in
> this reference at all — challenge the scope before the mechanics. The rest is
> the goal, approach, and pass criteria if it does.

## Why

A reference that calls itself production-shaped owes an honest answer to one
question: **does putting the Auth Service in every request path scale?** The BFF
resolves the opaque cookie to a token on every `/api/**` request (phantom token)
and serializes refresh with a distributed lock — both invite "won't that
bottleneck?" This characterizes the answer and sets the honest expectation:
**a little slower per request, but it scales out and stays correct under load.**

## Claims to demonstrate

1. **Horizontal scaling** — throughput rises when an Auth Service replica is
   added; the resolve path is not a fixed single-instance ceiling.
2. **Correctness under concurrency** — under concurrent refresh of the same
   (hot) sessions across replicas at load, the distributed lock prevents two
   refreshes from racing into refresh-token reuse and killing the session.
   Zero sessions dropped.
3. **Bounded latency** — `/api` p95 stays within a sane envelope as concurrency
   climbs; the resolve round-trip is a near-constant tax, not a latency cliff.

## Non-goals

- Not a capacity benchmark or an SLA. Local single-box numbers are
  *illustrative* — we report the **shape** (scales, holds, bounded), not
  production throughput.
- Not capacity planning for real infrastructure.
- "Fast" is a production-tuning goal, deliberately out of scope. "Scales and
  stays correct" is the property a reference must show.

## Approach

- **Tool:** k6 (real concurrency, no browser). On-demand `just e2e-load`;
  report-first; **not** in the blocking battery.
- **Target:** the two-replica distributed config (`compose.distributed-lock.yml`,
  `APP_REFRESH_LOCK=distributed`, shared Valkey + Keycloak), with the gateway's
  Auth Service upstream round-robining both replicas.
- **Setup:** seed N real sessions (ROPC → `sess:{sid}` + indexes, reusing the
  `e2e-distributed-lock.sh` minting) into `sessions.json`; mint the gateway
  client-credentials bearer.
- **Scenario 1 — scaling:** ramp virtual users hitting `/api/me` through the
  gateway; record req/s and p50/p95. Run at **1 replica vs 2** and compare — the
  delta is the horizontal-scaling evidence.
- **Scenario 2 — lock under load:** concentrate users on a few **near-expiry**
  sessions, forcing concurrent cross-replica refresh; assert sessions survive
  and record the serialization latency.

## Pass criteria (floors, not SLAs)

- `session_dropped` rate `< ~1%` under load — the lock holds.
- Throughput at 2 replicas clearly exceeds 1 replica — it scales.
- `/api` p95 under a generous ceiling — latency is bounded.

## Relationship to existing gates

Complements `scripts/e2e-distributed-lock.sh`, which proves the lock's
*correctness* for a single contended session. This adds the *scale + load*
dimension; it does not replace it.

## Caveats

- Local single box, no real network → illustrative, not a benchmark.
- `sid` cookie over local HTTP (not `__Host-sid`).
- k6 is a new external prerequisite (`brew install k6`).

## Reviewer questions

1. **Scope:** does a load characterization belong in this reference, or is it
   production-capacity work the repo deliberately excludes? (Counter-argument: a
   "production reference" should at least show it scales and the lock holds under
   load.)
2. If yes: are the three claims the right ones, and are the pass criteria honest
   (floors, not SLAs)?
3. Scenario 1 only means anything if the gateway round-robins both replicas —
   acceptable to add that to the distributed compose / APISIX render?
4. Report-only, or keep the two loose thresholds as breakage guards?
5. Standalone doc, or fold into `docs/testing/verification-gates.md`?
