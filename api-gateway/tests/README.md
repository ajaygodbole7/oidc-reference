# api-gateway/tests

Live integration tests for the APISIX `bff-session` plugin. The harness
POSTs/GETs against a running APISIX at `127.0.0.1:9080` and seeds session
state directly into Valkey via `docker compose exec valkey valkey-cli`.

## What it is

Black-box `curl` checks for the gateway-side contract documented in:

- `docs/specs/SPEC-0001-core-oidc-flows.md` — §"API Gateway Architecture",
  §"Login Entry Conditions", §7.1, §7.2, §7.3.
- `docs/goals/GOAL-0005-api-gateway.md`.

The harness asserts HTTP status, `Set-Cookie`/`Location` headers, and
`Content-Type` shapes — not Resource Server business logic.

## Prerequisites

- The full compose stack is up:
  `docker compose up -d apisix valkey auth-service resource-server keycloak`.
- APISIX is reachable on `http://127.0.0.1:9080` (preflight pings the
  public listener; `/apisix/status` is admin-only in 3.x standalone and
  is not used).
- `openssl`, `xxd`, `awk`, `python3` (optional, used for JSON field
  extraction; falls back to `sed` for flat JSON).
- `docker compose` available and the `valkey` service reachable via
  `docker compose exec`.

## Required env vars

| Var | Purpose |
|---|---|
| `RUN_LIVE_GATEWAY_TESTS=1` | Gates the whole script. Without this it exits 0 with a skip message. |
| `CSRF_SIGNING_KEY` | Base64-encoded 256-bit HMAC key SHARED with the APISIX `bff-session` plugin's `cookie_signing_key` config AND the Auth Service's `SignedCsrfSupport` key. Without it the CSRF test is skipped. |
| `RUN_REFRESH_TESTS=1` | Opt-in for `test_expiring_session_triggers_refresh_delegation`. Requires the Auth Service to be running and the Keycloak realm imported. |
| `GATEWAY_BASE` | Optional. Defaults to `http://127.0.0.1:9080`. |

## How to run

```sh
# minimal — gateway shape only, CSRF and refresh skipped
RUN_LIVE_GATEWAY_TESTS=1 sh api-gateway/tests/test-gateway-behavior.sh

# with CSRF tests
RUN_LIVE_GATEWAY_TESTS=1 \
  CSRF_SIGNING_KEY="$(cat .local/csrf-signing-key.b64)" \
  sh api-gateway/tests/test-gateway-behavior.sh

# full — CSRF + refresh delegation
RUN_LIVE_GATEWAY_TESTS=1 \
  RUN_REFRESH_TESTS=1 \
  CSRF_SIGNING_KEY="$(cat .local/csrf-signing-key.b64)" \
  sh api-gateway/tests/test-gateway-behavior.sh
```

## Skipped tests

The following tests are skipped without their gating env var or
because they need RS-side instrumentation that does not yet exist:

- `test_expiring_session_triggers_refresh_delegation` — skipped without
  `RUN_REFRESH_TESTS=1`. Needs the Auth Service `/internal/refresh`
  endpoint reachable on the internal Compose network.
- `test_state_changing_method_requires_signed_csrf` — skipped without
  `CSRF_SIGNING_KEY`. The helper computes HMAC-SHA256 with the
  Base64-decoded key bytes over the ASCII bytes of the token-value
  base64url; this must match the Auth Service and gateway HMAC scheme
  exactly. If they diverge (different algorithm, different value
  encoding, different key encoding), update `sign_csrf_token` in
  `lib.sh` in lockstep.
- `test_cookie_strip_does_not_leak_to_upstream`,
  `test_query_string_preserved`, `test_hop_by_hop_headers_stripped` —
  require RS-side request-header echo or access-log inspection. Marked
  as manually verified; revisit when a debug-echo endpoint lands on the
  RS or when the apisix access-log is parsed in-test.
