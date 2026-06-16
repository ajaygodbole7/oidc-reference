# api-gateway/tests

Live integration tests for the APISIX `bff-session` plugin. The harness:

- POSTs/GETs against a running APISIX at `127.0.0.1:9080`.
- Seeds non-refresh session state directly into Valkey via `docker compose exec valkey valkey-cli`.
- Mints a real service token for header/query echo probes.
- Mints a real login-derived session for the refresh-delegation test.

## What it is

Black-box `curl` checks for the gateway-side contract documented in:

- `docs/specs/SPEC-0001-core-oidc-flows.md` — §"API Gateway Architecture",
  §"Login Entry Conditions", §7.1, §7.2, §7.3.

The harness asserts HTTP status, `Set-Cookie`/`Location` headers, and
`Content-Type` shapes — not Resource Server business logic.

## Prerequisites

- The stack is up with `RESOURCE_SERVER_SPRING_PROFILES_ACTIVE=gateway-test`
  via `scripts/test-e2e.sh` or `scripts/e2e-auth.sh`: Compose starts Keycloak,
  Valkey, APISIX, Auth Service, and Resource Server. Auth Service and
  Resource Server are internal-only and reachable by APISIX through
  service-name DNS.
- APISIX is reachable on `http://127.0.0.1:9080` (preflight pings the
  public listener; `/apisix/status` is admin-only in 3.x standalone and
  is not used).
- `openssl`, `xxd`, `awk`, `python3` (required for JSON rewrite paths;
  field extraction falls back to `sed` for flat JSON).
- `docker compose` available and the `valkey` service reachable via
  `docker compose exec`.
- `docker` available for `test-lua-unit.sh`, which runs the Lua unit/parity
  tests inside the pinned APISIX image. The signed-CSRF fixture parity test uses
  OpenResty's `resty` runner so it exercises real `resty.hmac` and
  `ngx.encode_base64`.
- Frontend dev dependencies installed (`cd frontend && npm install`) when
  `RUN_REFRESH_TESTS=1`, because the refresh test uses Playwright to complete a
  real local Keycloak login and obtain a real `sess:{sid}`.

## Required env vars

| Var | Purpose |
|---|---|
| `RUN_LIVE_GATEWAY_TESTS=1` | Gates the whole script. Without this it exits 0 with a skip message. |
| `CSRF_SIGNING_KEY` | Base64-encoded 256-bit HMAC key SHARED with the APISIX `bff-session` plugin's `cookie_signing_key` config AND the Auth Service's `SignedCsrfSupport` key. Without it the CSRF test is skipped. |
| `RUN_REFRESH_TESTS=1` | Opt-in for `test_expiring_session_triggers_refresh_delegation`. Requires the full local stack and frontend Playwright dependency. |
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

The following tests are skipped without their gating env var:

- `test_expiring_session_triggers_refresh_delegation` — skipped without
  `RUN_REFRESH_TESTS=1`. It completes a real Authorization Code + PKCE login
  through APISIX, rewrites only `access_token_expires_at` on the resulting
  `sess:{sid}`, then asserts APISIX delegates refresh to Auth Service and
  re-reads the rotated token. It deliberately does not seed fake refresh-token
  state.
- `test_state_changing_method_requires_signed_csrf` — skipped without
  `CSRF_SIGNING_KEY`. The helper computes HMAC-SHA256 with the
  Base64-decoded key bytes over the ASCII bytes of the token-value
  base64url. This must match the Auth Service and gateway HMAC scheme
  exactly. If they diverge (different algorithm, different value
  encoding, different key encoding), update `sign_csrf_token` in
  `lib.sh` in lockstep.

## Gateway-test echo surface

`test_cookie_strip_does_not_leak_to_upstream`,
`test_query_string_preserved`, `test_hop_by_hop_headers_stripped`, and
`test_client_authorization_header_is_overwritten` use
`/api/_test/echo` on the Resource Server. That endpoint exists only under the
`gateway-test` Spring profile and reflects only the narrow fields the gateway
harness needs. It never echoes `Authorization`; it returns only the header value
count, the recognized scheme, and a SHA-256 fingerprint so the harness can prove
the exact injected bearer, including overwrite of caller-supplied
`Authorization`, without returning a live token to the caller. The
default profile returns 404 for the same path, which is covered by the Resource
Server test suite. Gateway forwarding assertions accept only deliberate 2xx/4xx
responses; redirects, transport failures, and 5xx responses are not treated as
proof that the intended upstream handler received the request.
