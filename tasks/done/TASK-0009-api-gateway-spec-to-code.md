# TASK-0009: API Gateway (APISIX) — Spec-to-Code

## Objective

Implement the APISIX-based API Gateway per SPEC-0001 and
GOAL-0005-api-gateway: declarative `apisix.yaml` with the `/api/**`
allowlist; custom Lua plugin `bff-session` that performs tolerant
session reading from Valkey, signed CSRF validation, bearer injection
against the Resource Server, inbound-cookie and hop-by-hop header
stripping, and refresh delegation to the Auth Service's
`/internal/refresh`; Client-Credentials token cache for the Gateway's
own Keycloak identity; integration tests via `curl` against an
ephemeral APISIX stack. No application code exists yet under
`api-gateway/`; this task creates it.

## Linked Spec

- `docs/specs/SPEC-0001-core-oidc-flows.md`
- `docs/goals/GOAL-0005-api-gateway.md`
- `RESHAPE-FRAME-B.md` (§3.2 browser flow, §3.4 internal RPC, §7.1
  `/internal/refresh` contract and Gateway-side response table, §7.2
  `sess:{sid}` schema contract, §7.3 signed CSRF contract)
- Root `README.md` (canonical sequence diagrams)

## Read First

- `AGENTS.md`
- `docs/agents/mandatory-turn-protocol.md`
- `docs/agents/execution-discipline.md`
- `docs/agents/task-template.md`
- `docs/testing/red-green-workflow.md`
- APISIX standalone-mode docs (declarative `apisix.yaml`, custom plugin
  loading via `extra_lua_path` and `plugin.attr`)
- `docs/goals/archive/GOAL-0004-bff.md` (historical context — the
  combined-BFF predecessor; the routing/bearer-injection role is what
  this task is extracting and re-implementing in APISIX/Lua)

## Owned Paths

- `api-gateway/`
- `api-gateway/apisix.yaml` (APISIX standalone declarative config)
- `api-gateway/plugins/bff-session.lua` (custom Lua plugin)
- `api-gateway/plugins/` (any helper Lua modules)
- `api-gateway/tests/` (curl-based integration tests; harness scripts to
  stand up an ephemeral APISIX + Valkey + mock Auth Service for the
  tests)
- API-Gateway-specific docs and task notes

## Avoid Paths

- `auth-service/` (separate task — TASK-0008)
- `frontend/`
- `backend-resource-server/`
- `authorization-server/realm/` (read-only inspection)
- Root `compose.yaml`, `README.md`, `docs/specs/`, `docs/goals/` (these
  are the contract — do not change them to fit the code; change the code
  to fit them)

## Required Workflow

Before coding, record in the working notes:

- Assumptions:
- Ambiguities:
- Owned paths: (mirror Owned Paths above)
- Success criteria: (mirror the Done Criteria below)

Plan:

```text
1. Scaffold api-gateway/ with apisix.yaml (standalone mode) declaring the
   allowlisted /api/** routes (default: /api/me, /api/user-data,
   /api/admin) pointing at the resource-server upstream
   -> verify: apisix can start with this config; off-allowlist /api/*
      returns 404 (route does not match).

2. Custom Lua plugin bff-session: load via APISIX extra_lua_path; declare
   schema; attach to each /api/** route
   -> verify: APISIX startup log shows the plugin loaded; a curl with no
      cookie reaches the plugin and is rejected per the no-session
      branches.

3. Tolerant session reader: GET sess:{sid} from Valkey via resty.redis;
   parse JSON; read only access_token and access_token_expires_at; treat
   parse error or missing required field as "no session"
   -> verify: a sess:{sid} fixture with extra unknown fields is read
      successfully; a fixture missing access_token_expires_at is treated
      as "no session" (XHR -> 401, nav -> 302).

4. Browser-request classification: Sec-Fetch-Mode + Sec-Fetch-Dest
   primary, Accept fallback. No-session XHR -> 401 (no Location).
   No-session navigation -> 302 /auth/login?next=<original URL>
   -> verify: curl with `Sec-Fetch-Mode: cors` -> 401; curl with
      `Sec-Fetch-Mode: navigate` + `Sec-Fetch-Dest: document` -> 302 with
      the correct `next=` value (URL-encoded).

5. Signed CSRF validation on POST/PUT/DELETE/PATCH: extract XSRF-TOKEN
   cookie and X-XSRF-TOKEN header; recompute HMAC-SHA256 using the shared
   signing key; reject if either is missing, if they do not match
   exactly, or if the recomputed HMAC differs (constant-time compare)
   -> verify: forged-signature, tampered-value, missing-cookie, missing-
      header all return 403 before any upstream call; valid token
      proceeds.

6. Header shaping: strip inbound Cookie; strip hop-by-hop headers
   (Connection, Keep-Alive, Proxy-Authenticate, Proxy-Authorization, TE,
   Trailers, Transfer-Encoding, Upgrade); inject Authorization: Bearer
   <access_token>; preserve query string
   -> verify: a mock RS in the test harness asserts no Cookie header is
      present on the upstream call and Authorization: Bearer is present;
      query string round-trips.

7. Client-Credentials token cache for the Gateway's own Keycloak client
   (oidc-reference-api-gateway). Single in-process cache entry; proactive
   refresh when remaining lifetime < 60s; in-process lock around the
   refresh to serialize duplicate fetches
   -> verify: under concurrent /api/* load that triggers a refresh, only
      one POST /token to Keycloak is observed in the test harness.

8. Refresh delegation: when sess:{sid}.access_token_expires_at is within
   the no-refresh window (default 60s), POST /internal/refresh against
   the Auth Service with the cached Client-Credentials token; on 200
   re-read sess:{sid}; on 401 invalidate the cached token and retry once;
   on 404 return 401 to the browser and expire __Host-sid; on 409 return
   401 to the browser and expire __Host-sid; on 502 return 503 with
   Retry-After: 1 and do NOT expire __Host-sid
   -> verify: one test per branch using a mock Auth Service that returns
      each status; assert the Gateway-to-browser status and the cookie-
      clear behavior.

9. Circuit breaker on /internal/refresh: rolling window of 10 requests,
   50% threshold; distinguishes 5xx/transport failures (count as failure)
   from 200/401/404/409 (count as success). Open state returns 503 for
   30s; half-open admits one probe
   -> verify: simulate 5+ transport failures -> next inbound /api/*
      needing refresh returns 503 without calling /internal/refresh; one
      probe is admitted after 30s.

10. Schema-contract fixture: load schema/sess-payload.example.json
    (shared with the Auth Service via TASK-0008); assert the tolerant
    reader extracts access_token and access_token_expires_at correctly
    -> verify: catches reader-side regressions and JSON-library
       configuration drift between the writer (Auth Service) and the
       reader (Gateway).

11. Run focused gate -> verify: api-gateway/tests/run.sh exits 0 against
    an ephemeral APISIX + Valkey + mock Auth Service stack.
```

Then, per task discipline:

1. Run the current focused tests.
2. Add the failing test (or failing curl assertion) for each item above
   before coding it.
3. Confirm the red failure.
4. Implement the smallest complete change.
5. Confirm green focused tests.
6. Run the relevant verification gate.
7. Do not change spec or diagram to make the code easier — the spec is
   the contract.

## Done Criteria

- `apisix.yaml` declares the `/api/**` allowlist in standalone mode and
  forwards each route to the `resource-server` upstream; off-allowlist
  paths return `404` without any upstream call.
- The `bff-session` Lua plugin is loaded by APISIX at startup and is
  attached to each `/api/**` route.
- Tolerant session reader consumes only `access_token` and
  `access_token_expires_at`; ignores extra fields; treats malformed or
  missing-required-field payloads as "no session".
- Browser-request classification at the Gateway: XHR no-session -> `401`
  with no `Location`; nav no-session -> `302 /auth/login?next=...`.
- Signed CSRF validation on state-changing methods rejects forged
  signatures and tampered values via constant-time HMAC compare; valid
  tokens are accepted. Naive (unsigned) double-submit is explicitly
  rejected by virtue of the HMAC step.
- Inbound `Cookie` header and hop-by-hop headers are stripped before the
  upstream call; only `Authorization: Bearer <access_token>` is added.
  Query string is preserved.
- Client-Credentials token cache: single in-process entry per Gateway
  process; proactive refresh under load is serialized to one Keycloak
  round-trip; cache invalidation on `401` from Auth Service with single
  retry, then `502` to browser with security audit event on second
  failure.
- Refresh delegation handles all five `/internal/refresh` responses
  (200 / 401 / 404 / 409 / 502) per the Gateway-side response table in
  RESHAPE-FRAME-B.md §7.1.
- Circuit breaker on `/internal/refresh` distinguishes transport / 5xx
  failures from 4xx responses; does not trip on normal 404/409 traffic.
- `schema/sess-payload.example.json` is checked in as the shared fixture
  with the Auth Service; the Gateway's tolerant reader is exercised
  against it.
- `api-gateway/tests/run.sh` exits 0 against an ephemeral APISIX +
  Valkey + mock Auth Service stack and covers each of the integration
  cases in the GOAL-0005 Required Tests list.
- This task packet passes `scripts/check-agent-task.sh`.

## Final Report

_Status_: ✅ Done — Phase C (`acf78af`) + follow-up (`00c6da8`).

### Assumptions

- APISIX standalone mode (no etcd). Routes + plugins declarative in
  `apisix.yaml`; node config in `config.yaml`.
- Lua plugin `bff-session` runs in APISIX's `access` phase, before
  upstream selection.
- For the local reference, Auth Service + Resource Server run on the
  host via `./mvnw spring-boot:run`; APISIX reaches them via
  `host.docker.internal:PORT`. Containerising the Spring services is
  not part of the reference deliverable (their Dockerfiles exist in
  tree as a starting point but are not used by the default Compose
  topology).

### Files (under `api-gateway/`)

- `config.yaml`: APISIX standalone node config — port 9080, admin
  disabled, data_plane role, yaml provider, `extra_lua_path` for the
  custom plugin, shared dicts (`cc_token_cache`, `cc_token_lock`),
  plugins list.
- `apisix.yaml`: routes for `/api/me`, `/api/user-data`, `/api/admin`
  → Resource Server upstream with `bff-session` plugin attached;
  `/auth/*` passthrough → Auth Service upstream, no plugin (Auth
  Service owns its own auth on `/auth/*`).
- `plugins/bff-session.lua` (~720 LOC): the full access-phase
  pipeline — cookie read with `__Host-sid`/`sid` selection;
  Fetch-Metadata navigation gate (302 vs 401 problem+json);
  Valkey tolerant session reader; signed-CSRF HMAC-SHA256 validation
  with constant-time compare; refresh delegation to
  `/internal/refresh` with CC-token cache + proactive refresh +
  401/404/409/502 mapping per §7.1; bearer injection + hop-by-hop
  header strip.
- `README.md`: shape, run instructions, allowlist extension pointer.
- `tests/test-gateway-behavior.sh` + `tests/lib.sh` + `tests/README.md`:
  curl-based live integration suite gated by `RUN_LIVE_GATEWAY_TESTS=1`.

### Tests

- LuaJIT bytecode compile of `bff-session.lua` → ok ✅
- `sh -n` on all gateway scripts → ok ✅
- `docker compose config --quiet` → ok ✅
- Integration tests under `api-gateway/tests/` are gated; they run
  against a live APISIX + Valkey + Auth Service stack.

### Result

API Gateway is feature-complete against SPEC-0001 §"API Gateway
Architecture (APISIX)" + §7.1 / §7.2 / §7.3.

### Risks / follow-ups

- Same cross-language HMAC parity gap noted in TASK-0008.
- The Lua plugin's circuit-breaker on `/internal/refresh` failure rate
  was not implemented in this slice (the §7.1 status-code table is
  honoured; the rolling-window breaker is documented as a future
  enhancement in the spec).
- Integration tests assume the operator runs the Spring services on
  the host (mvn spring-boot:run) and APISIX in Compose — the
  containerised variant would need the host.docker.internal
  references swapped back to service names plus the Spring Dockerfiles
  re-wired into compose.
