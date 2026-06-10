#!/usr/bin/env sh
# test-gateway-behavior.sh — live integration tests for the APISIX
# bff-session plugin.
#
# This script POSTs/GETs against a running APISIX at 127.0.0.1:9080 and
# seeds Valkey state directly via `docker compose exec valkey valkey-cli`.
# It exercises the gateway-side contract documented in:
#   - docs/specs/SPEC-0001-core-oidc-flows.md §"API Gateway Architecture"
#   - docs/specs/SPEC-0001-core-oidc-flows.md §"Login Entry Conditions"
#   - docs/specs/SPEC-0001-core-oidc-flows.md §7.1, §7.2, §7.3
#   - docs/goals/GOAL-0005-api-gateway.md
#
# Gating:
#   RUN_LIVE_GATEWAY_TESTS=1   required; otherwise exits 0 with a skip note
#   RUN_REFRESH_TESTS=1        opt-in for the expiring-session refresh test.
#                              Requires the full local stack: APISIX, Valkey,
#                              Keycloak, Auth Service, and Resource Server.
#   CSRF_SIGNING_KEY           base64-encoded 256-bit HMAC key SHARED with
#                              the APISIX bff-session plugin and Auth Service
#
# Exit code: 0 iff every non-skipped test passed.
#
# POSIX sh, set -eu. Individual assertions use `|| true` patterns so a
# single failure does not abort the whole suite; we still produce
# "N passed, M failed" at the end.

set -eu

# ---------------------------------------------------------------------------
# Gating
# ---------------------------------------------------------------------------

if [ "${RUN_LIVE_GATEWAY_TESTS:-0}" != "1" ]; then
  printf 'skipping; set RUN_LIVE_GATEWAY_TESTS=1 to enable live gateway tests\n'
  exit 0
fi

script_dir="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
repo_root="$(CDPATH= cd -- "$script_dir/../.." && pwd)"

# Run docker compose commands from the repo root so it finds compose.yaml.
cd "$repo_root"

if [ -f "$script_dir/lib.sh" ]; then
  # shellcheck disable=SC1091
  . "$script_dir/lib.sh"
else
  printf 'fatal: %s/lib.sh not found\n' "$script_dir" >&2
  exit 2
fi

GATEWAY_BASE="${GATEWAY_BASE:-http://127.0.0.1:9080}"
BODY_TMP="$(mktemp)"
HEADERS_TMP="$(mktemp)"

cleanup() {
  rm -f "$BODY_TMP" "$HEADERS_TMP" 2>/dev/null || true
  clear_all_tracked_sessions
}
trap cleanup EXIT INT TERM

# ---------------------------------------------------------------------------
# Preflight
# ---------------------------------------------------------------------------

preflight() {
  # /apisix/status is admin-only in 3.x standalone — probe a public route
  # instead. Any 4xx/5xx from the public listener proves APISIX is
  # accepting requests; only "no answer" (HTTP 000) means it's down.
  status="$(curl -s -o /dev/null -w '%{http_code}' \
    "$GATEWAY_BASE/__apisix_preflight__" 2>/dev/null || true)"
  if [ "$status" = "000" ] || [ -z "$status" ]; then
    printf 'fatal: APISIX not reachable at %s (no response)\n' \
      "$GATEWAY_BASE" >&2
    printf 'hint: start the compose stack: docker compose up -d apisix valkey\n' >&2
    exit 2
  fi
  # And Valkey: a SET in setup_session will fail noisily otherwise.
  if ! valkey_exec PING >/dev/null 2>&1; then
    printf 'fatal: cannot exec into valkey via docker compose. is the service up?\n' >&2
    exit 2
  fi
}

preflight

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

test_no_cookie_xhr_returns_401_no_redirect() {
  name="no_cookie_xhr_returns_401_no_redirect"
  status="$(curl -s -o "$BODY_TMP" -D "$HEADERS_TMP" \
    -w '%{http_code}' \
    -H 'Accept: application/json' \
    "$GATEWAY_BASE/api/me" 2>/dev/null || true)"
  assert_status "$name status" 401 "$status"
  # No Location header on XHR 401.
  if grep -i '^Location:' "$HEADERS_TMP" >/dev/null 2>&1; then
    printf '[FAIL] %s expected no Location header but found one\n' "$name"
    FAILED=$((FAILED + 1))
  else
    printf '[PASS] %s no_location_header\n' "$name"
    PASSED=$((PASSED + 1))
  fi
  # Content-Type should be application/problem+json.
  ct="$(grep -i '^Content-Type:' "$HEADERS_TMP" \
    | head -n1 \
    | tr -d '\r' \
    | awk -F': ' '{print $2}' \
    | awk -F';' '{print $1}')"
  assert_status "$name content_type" "application/problem+json" "$ct"
}

test_no_cookie_navigation_returns_302_to_login() {
  name="no_cookie_navigation_returns_302_to_login"
  status="$(curl -s -o "$BODY_TMP" -D "$HEADERS_TMP" \
    -w '%{http_code}' \
    -H 'Sec-Fetch-Mode: navigate' \
    -H 'Sec-Fetch-Dest: document' \
    -H 'Accept: text/html' \
    "$GATEWAY_BASE/api/me" 2>/dev/null || true)"
  assert_status "$name status" 302 "$status"
  location="$(grep -i '^Location:' "$HEADERS_TMP" \
    | head -n1 \
    | tr -d '\r' \
    | awk -F': ' '{print $2}')"
  case "$location" in
    /auth/login\?return_to=*)
      printf '[PASS] %s location_prefix\n' "$name"
      PASSED=$((PASSED + 1))
      ;;
    *)
      printf '[FAIL] %s expected Location to start with /auth/login?return_to= but got: %s\n' \
        "$name" "$location"
      FAILED=$((FAILED + 1))
      ;;
  esac
}

test_x_forwarded_proto_drives_secure_cookie_handling() {
  name="x_forwarded_proto_drives_secure_cookie_handling"
  sid="xfp-secure-1"
  setup_session "$sid" "test-jwt-xfp" 300

  status="$(curl -s -o "$BODY_TMP" -D "$HEADERS_TMP" \
    -w '%{http_code}' \
    -H 'X-Forwarded-Proto: https' \
    -H "Cookie: __Host-sid=$sid" \
    "$GATEWAY_BASE/api/me" 2>/dev/null || true)"
  assert_plugin_forwarded "$name forwarded_https_accepts_host_sid" \
    "$status" "$HEADERS_TMP" "$BODY_TMP"

  status="$(curl -s -o "$BODY_TMP" -D "$HEADERS_TMP" \
    -w '%{http_code}' \
    -H "Cookie: __Host-sid=$sid" \
    "$GATEWAY_BASE/api/me" 2>/dev/null || true)"
  assert_status "$name plaintext_rejects_host_sid" 401 "$status"

  clear_session "$sid"
}

test_unknown_path_returns_404() {
  name="unknown_path_returns_404"
  status="$(curl -s -o /dev/null -w '%{http_code}' \
    "$GATEWAY_BASE/api/this-is-not-allowlisted" 2>/dev/null || true)"
  assert_status "$name status" 404 "$status"
}

# The Auth Service /internal/refresh endpoint is the only way to rotate
# tokens. It is reachable solely from the gateway -> auth-service direction,
# over Client Credentials. External clients MUST NOT be able to route to
# /internal/** through APISIX. This is enforced structurally: apisix.yaml
# declares no /internal/** route, so APISIX falls through to 404 even when
# the caller presents a valid sid cookie or signed CSRF.
test_internal_path_is_not_routable_through_gateway() {
  name="internal_path_is_not_routable_through_gateway"

  # 1. Bare GET /internal/refresh -> 404 (no route, plugin not invoked).
  status="$(curl -s -o /dev/null -w '%{http_code}' \
    "$GATEWAY_BASE/internal/refresh" 2>/dev/null || true)"
  assert_status "$name bare_get_status" 404 "$status"

  # 2. Real method POST /internal/refresh with JSON body -> 404. This is
  #    the contract method; rejecting it at the routing layer (not just
  #    the JWT layer downstream) is what keeps /internal off the public
  #    surface.
  status="$(curl -s -o /dev/null -w '%{http_code}' \
    -X POST \
    -H 'Content-Type: application/json' \
    --data '{"sid":"anything"}' \
    "$GATEWAY_BASE/internal/refresh" 2>/dev/null || true)"
  assert_status "$name post_with_body_status" 404 "$status"

  # 3. Even WITH a seeded session cookie, /internal/** must not become
  #    routable — the absence of a route is the security control, not the
  #    presence/absence of session state.
  sid="internal-probe-1"
  setup_session "$sid" "test-jwt-internal-probe" 300
  status="$(curl -s -o /dev/null -w '%{http_code}' \
    -X POST \
    -H "Cookie: __Host-sid=$sid" \
    -H 'Content-Type: application/json' \
    --data "{\"sid\":\"$sid\"}" \
    "$GATEWAY_BASE/internal/refresh" 2>/dev/null || true)"
  assert_status "$name post_with_session_status" 404 "$status"
  clear_session "$sid"

  # 4. Subpaths under /internal must also 404 — guards against future
  #    accidental `/internal/*` route additions that would expose siblings.
  status="$(curl -s -o /dev/null -w '%{http_code}' \
    "$GATEWAY_BASE/internal/health" 2>/dev/null || true)"
  assert_status "$name subpath_status" 404 "$status"
}

# Differentiator between "plugin short-circuited" and "plugin forwarded":
# the plugin's no-session path always sets `Set-Cookie: sid=; Max-Age=0`
# (orphan cookie eviction; see bff-session.lua expire_session_cookie). When
# the plugin successfully reads sess:{sid} and forwards to RS, it does NOT
# emit that header — RS handles the response. The harness uses that
# eviction header as the sole reliable signal that the gateway did or did
# not short-circuit; a bare `200|401` check was a false positive that
# masked a months-long plugin-load failure (module 'apisix.plugins.bff-
# session' not found). Accept any 2xx/4xx/5xx as long as it didn't come
# from the plugin's no-session path.
assert_plugin_forwarded() {
  name="$1"
  status="$2"
  headers_file="$3"
  body_file="$4"

  # 1. The plugin's no-session response always evicts the orphan cookie.
  #    Absence of the eviction Set-Cookie proves the plugin did NOT
  #    short-circuit on no-session.
  if grep -iE '^Set-Cookie:[[:space:]]*(sid|__Host-sid)=[[:space:]]*;.*Max-Age=0' \
      "$headers_file" >/dev/null 2>&1; then
    printf '[FAIL] %s plugin short-circuited (orphan-cookie eviction Set-Cookie present)\n' \
      "$name"
    FAILED=$((FAILED + 1))
    return 1
  fi

  # 2. The plugin's no-session body is RFC 7807 with the literal "no
  #    session" / "no access token" details. Belt-and-braces in case a
  #    future plugin path returns 401 without eviction.
  if grep -E '"detail"[[:space:]]*:[[:space:]]*"(no session|no access token)"' \
      "$body_file" >/dev/null 2>&1; then
    printf '[FAIL] %s plugin short-circuited (no-session problem+json body)\n' \
      "$name"
    FAILED=$((FAILED + 1))
    return 1
  fi

  printf '[PASS] %s gateway_forwarded (status=%s; passed through plugin to upstream)\n' \
    "$name" "$status"
  PASSED=$((PASSED + 1))
  return 0
}

setup_echo_session() {
  name="$1"
  sid="$2"
  if ! access_token="$(mint_service_access_token 2>"$BODY_TMP")"; then
    detail="$(cat "$BODY_TMP" 2>/dev/null || true)"
    printf '[FAIL] %s could not mint service token for echo probe: %s\n' "$name" "$detail"
    FAILED=$((FAILED + 1))
    return 1
  fi
  if [ -z "$access_token" ]; then
    printf '[FAIL] %s minted empty service token for echo probe\n' "$name"
    FAILED=$((FAILED + 1))
    return 1
  fi
  setup_session "$sid" "$access_token" 300
}

test_valid_session_returns_200_with_bearer_injected() {
  name="valid_session_returns_200_with_bearer_injected"
  sid="valid-1"
  setup_session "$sid" "test-jwt-1" 300
  status="$(curl -s -o "$BODY_TMP" -D "$HEADERS_TMP" -w '%{http_code}' \
    -H "Cookie: __Host-sid=$sid" \
    "$GATEWAY_BASE/api/me" 2>/dev/null || true)"
  # The RS will reject test-jwt-1 as a non-JWT and return its own 401.
  # That is fine — what we verify here is that the bff-session PLUGIN ran
  # and forwarded, not that RS accepted the token. A real integration run
  # would seed a Keycloak-issued JWT and assert 200.
  assert_plugin_forwarded "$name" "$status" "$HEADERS_TMP" "$BODY_TMP"
  clear_session "$sid"
}

test_canonical_fixture_payload_parses_through_plugin() {
  # B8: the gateway's tolerant reader MUST parse the canonical
  # schema/sess-payload.example.json fixture and extract access_token +
  # access_token_expires_at. If a reader-side regression breaks the parse
  # (renamed field, timestamp format drift, JSON library quirk) the plugin
  # short-circuits with a no-session-shaped 401 — caught by the helper.
  name="canonical_fixture_payload_parses_through_plugin"
  sid="contract-fixture-1"
  fixture="$repo_root/schema/sess-payload.example.json"
  if [ ! -f "$fixture" ]; then
    printf '[FAIL] %s: fixture not found at %s\n' "$name" "$fixture"
    FAILED=$((FAILED + 1))
    return 1
  fi
  setup_session_from_fixture "$sid" "$fixture"
  status="$(curl -s -o "$BODY_TMP" -D "$HEADERS_TMP" -w '%{http_code}' \
    -H "Cookie: __Host-sid=$sid" \
    "$GATEWAY_BASE/api/me" 2>/dev/null || true)"
  assert_plugin_forwarded "$name" "$status" "$HEADERS_TMP" "$BODY_TMP"
  clear_session "$sid"
}

test_session_with_extra_fields_is_tolerated() {
  name="session_with_extra_fields_is_tolerated"
  sid="valid-extra-1"
  setup_session_with_extra "$sid" "test-jwt-extra" 300 \
    '"future_field":"some_value","another":42'
  status="$(curl -s -o "$BODY_TMP" -D "$HEADERS_TMP" -w '%{http_code}' \
    -H "Cookie: __Host-sid=$sid" \
    "$GATEWAY_BASE/api/me" 2>/dev/null || true)"
  # If the tolerant reader rejected the extra fields, the plugin would
  # short-circuit with a no-session-shaped 401 — caught by the helper.
  assert_plugin_forwarded "$name" "$status" "$HEADERS_TMP" "$BODY_TMP"
  clear_session "$sid"
}

test_expiring_session_triggers_refresh_delegation() {
  name="expiring_session_triggers_refresh_delegation"
  if [ "${RUN_REFRESH_TESTS:-0}" != "1" ]; then
    skip_test "$name" "set RUN_REFRESH_TESTS=1 (needs full local stack)"
    return 0
  fi

  # A refresh-delegation test cannot seed a synthetic sess:{sid}: the Auth
  # Service calls the real IdP with the stored refresh_token, so fake token
  # material correctly fails with 502. Mint a real session through the local
  # Authorization Code + PKCE login flow, then rewrite ONLY
  # access_token_expires_at to move that real session into the gateway's
  # refresh window.
  if ! sid="$(GATEWAY_BASE="$GATEWAY_BASE" node "$script_dir/mint-real-session.mjs" 2>"$BODY_TMP")"; then
    detail="$(cat "$BODY_TMP" 2>/dev/null || true)"
    printf '[FAIL] %s could not mint real login session: %s\n' "$name" "$detail"
    FAILED=$((FAILED + 1))
    return 1
  fi
  if [ -z "$sid" ]; then
    printf '[FAIL] %s minted empty sid\n' "$name"
    FAILED=$((FAILED + 1))
    return 1
  fi
  track_sid "$sid"
  if ! set_session_access_expiry "$sid" 30; then
    printf '[FAIL] %s could not move real session into refresh window\n' "$name"
    FAILED=$((FAILED + 1))
    clear_session "$sid"
    return 1
  fi

  before_expiry="$(get_session_field "$sid" access_token_expires_at)"
  status="$(curl -s -o "$BODY_TMP" -D "$HEADERS_TMP" -w '%{http_code}' \
    -H "Cookie: __Host-sid=$sid" \
    "$GATEWAY_BASE/api/me" 2>/dev/null || true)"
  after_expiry="$(get_session_field "$sid" access_token_expires_at)"

  # With a real session before and after refresh, the RS should accept the
  # gateway-injected bearer and return 200. A 401 here means either refresh did
  # not happen or the post-refresh token is not accepted by the RS.
  assert_status "$name status" 200 "$status"

  if [ -n "$before_expiry" ] && [ -n "$after_expiry" ] && [ "$after_expiry" \> "$before_expiry" ]; then
    printf '[PASS] %s access_expiry_extended\n' "$name"
    PASSED=$((PASSED + 1))
  else
    printf '[FAIL] %s expected access_token_expires_at to move forward after refresh\n' "$name"
    FAILED=$((FAILED + 1))
  fi
  clear_session "$sid"
}

test_refresh_failure_evicts_session_and_clears_cookie() {
  name="refresh_failure_evicts_session_and_clears_cookie"
  if [ "${RUN_REFRESH_TESTS:-0}" != "1" ]; then
    skip_test "$name" "set RUN_REFRESH_TESTS=1 (needs full local stack)"
    return 0
  fi

  # The refresh-FAILURE half of the SPEC §7.1 gateway response table. The live
  # happy-path test above covers only the 200 branch; the 404/409/401/transport
  # branches are otherwise only the Lua decision-table unit test. Here we drive
  # the real stack into the 409 branch: mint a real session, corrupt its stored
  # refresh_token, and move the access token into the refresh window. The next
  # /api call makes the gateway delegate to /internal/refresh; the auth-service
  # sends the bad refresh token to Keycloak, earns invalid_grant, returns 409,
  # and DELETES sess:{sid}. The gateway must surface 401 to the browser AND
  # evict the session cookie.
  if ! sid="$(GATEWAY_BASE="$GATEWAY_BASE" node "$script_dir/mint-real-session.mjs" 2>"$BODY_TMP")"; then
    detail="$(cat "$BODY_TMP" 2>/dev/null || true)"
    printf '[FAIL] %s could not mint real login session: %s\n' "$name" "$detail"
    FAILED=$((FAILED + 1))
    return 1
  fi
  if [ -z "$sid" ]; then
    printf '[FAIL] %s minted empty sid\n' "$name"
    FAILED=$((FAILED + 1))
    return 1
  fi
  track_sid "$sid"
  if ! corrupt_session_refresh_token "$sid"; then
    printf '[FAIL] %s could not corrupt stored refresh token\n' "$name"
    FAILED=$((FAILED + 1))
    clear_session "$sid"
    return 1
  fi

  status="$(curl -s -o "$BODY_TMP" -D "$HEADERS_TMP" -w '%{http_code}' \
    -H "Cookie: __Host-sid=$sid" \
    "$GATEWAY_BASE/api/me" 2>/dev/null || true)"

  # 1. Browser sees 401 (refresh rejected at the IdP, session invalidated).
  assert_status "$name status" 401 "$status"

  # 2. The gateway evicted the session cookie (Set-Cookie clearing the sid with
  #    Max-Age=0). expire_session_cookie emits "sid=; ...; Max-Age=0" on http.
  if grep -i '^set-cookie:' "$HEADERS_TMP" | grep -qi 'sid=' \
     && grep -i '^set-cookie:' "$HEADERS_TMP" | grep -qi 'max-age=0'; then
    printf '[PASS] %s cookie_evicted\n' "$name"
    PASSED=$((PASSED + 1))
  else
    printf '[FAIL] %s expected a Set-Cookie evicting the session cookie (Max-Age=0)\n' "$name"
    FAILED=$((FAILED + 1))
  fi

  # 3. The auth-service deleted sess:{sid} on the 409 path (no stale session).
  exists="$(valkey_exec EXISTS "sess:$sid" | tr -d '\r')"
  if [ "$exists" = "0" ]; then
    printf '[PASS] %s session_deleted\n' "$name"
    PASSED=$((PASSED + 1))
  else
    printf '[FAIL] %s expected sess:%s deleted after 409 (exists=%s)\n' "$name" "$sid" "$exists"
    FAILED=$((FAILED + 1))
  fi
  clear_session "$sid"
}

test_state_changing_method_requires_signed_csrf() {
  name="state_changing_method_requires_signed_csrf"

  if [ -z "${CSRF_SIGNING_KEY:-}" ]; then
    skip_test "$name" "set CSRF_SIGNING_KEY (base64 of the shared 256-bit HMAC key) to enable"
    return 0
  fi

  sid="csrf-1"
  # CSRF is stateless to validate: the gateway checks cookie ↔ header ↔
  # HMAC(value:sid), not a session-stored value.
  valid_token="$(make_valid_csrf "$sid")"
  setup_session "$sid" "test-jwt-csrf" 300

  # ---- 1. No CSRF cookie/header -> 403 problem+json
  status="$(curl -s -o "$BODY_TMP" -D "$HEADERS_TMP" -w '%{http_code}' \
    -X POST \
    -H "Cookie: __Host-sid=$sid" \
    "$GATEWAY_BASE/api/admin" 2>/dev/null || true)"
  assert_status "$name no_csrf_status" 403 "$status"
  ct="$(grep -i '^Content-Type:' "$HEADERS_TMP" \
    | head -n1 \
    | tr -d '\r' \
    | awk -F': ' '{print $2}' \
    | awk -F';' '{print $1}')"
  assert_status "$name no_csrf_content_type" "application/problem+json" "$ct"

  # ---- 2. Plain unsigned token (cookie == header, no HMAC) -> 403
  plain="plain-csrf-token"
  status="$(curl -s -o /dev/null -w '%{http_code}' \
    -X POST \
    -H "Cookie: __Host-sid=$sid; XSRF-TOKEN=$plain" \
    -H "X-XSRF-TOKEN: $plain" \
    "$GATEWAY_BASE/api/admin" 2>/dev/null || true)"
  assert_status "$name unsigned_plain_status" 403 "$status"

  # ---- 3. Mismatched cookie vs header values -> 403
  other_valid="$(make_valid_csrf "other-sid")"
  status="$(curl -s -o /dev/null -w '%{http_code}' \
    -X POST \
    -H "Cookie: __Host-sid=$sid; XSRF-TOKEN=$valid_token" \
    -H "X-XSRF-TOKEN: $other_valid" \
    "$GATEWAY_BASE/api/admin" 2>/dev/null || true)"
  assert_status "$name mismatched_status" 403 "$status"

  # ---- 4. Forged HMAC (cookie value == header value but HMAC tampered)
  # Take a valid token, flip its last char to create an invalid hmac.
  good="$(make_valid_csrf "$sid")"
  bad="${good%?}X"  # replace last char with X
  status="$(curl -s -o /dev/null -w '%{http_code}' \
    -X POST \
    -H "Cookie: __Host-sid=$sid; XSRF-TOKEN=$bad" \
    -H "X-XSRF-TOKEN: $bad" \
    "$GATEWAY_BASE/api/admin" 2>/dev/null || true)"
  assert_status "$name forged_hmac_status" 403 "$status"

  # ---- 5. Validly signed for a different sid -> 403 even when
  # cookie/header match. This is the session-binding guard.
  other_sid_token="$(make_valid_csrf "sid-that-is-not-$sid")"
  status="$(curl -s -o /dev/null -w '%{http_code}' \
    -X POST \
    -H "Cookie: __Host-sid=$sid; XSRF-TOKEN=$other_sid_token" \
    -H "X-XSRF-TOKEN: $other_sid_token" \
    "$GATEWAY_BASE/api/admin" 2>/dev/null || true)"
  assert_status "$name cross_session_status" 403 "$status"

  # ---- 6. Valid signed CSRF -> 200 (or 401 from RS — gateway forwarded)
  good2="$(make_valid_csrf "$sid")"
  status="$(curl -s -o /dev/null -w '%{http_code}' \
    -X POST \
    -H "Cookie: __Host-sid=$sid; XSRF-TOKEN=$good2" \
    -H "X-XSRF-TOKEN: $good2" \
    "$GATEWAY_BASE/api/admin" 2>/dev/null || true)"
  case "$status" in
    200|401)
      printf '[PASS] %s valid_csrf_forwarded (status=%s)\n' "$name" "$status"
      PASSED=$((PASSED + 1))
      ;;
    403)
      printf '[FAIL] %s valid CSRF was rejected — HMAC scheme mismatch with gateway/auth-service. Check sign_csrf_token in lib.sh.\n' \
        "$name"
      FAILED=$((FAILED + 1))
      ;;
    *)
      printf '[FAIL] %s expected 200/401 but got %s\n' "$name" "$status"
      FAILED=$((FAILED + 1))
      ;;
  esac

  clear_session "$sid"
}

test_api_activity_slides_session_ttl() {
  name="api_activity_slides_session_ttl"
  sid="ttl-slide-1"
  setup_session "$sid" "test-jwt-ttl-slide" 300
  valkey_exec EXPIRE "sess:$sid" 5 >/dev/null

  before="$(valkey_exec TTL "sess:$sid" | tr -d '\r')"
  status="$(curl -s -o "$BODY_TMP" -D "$HEADERS_TMP" -w '%{http_code}' \
    -H "Cookie: __Host-sid=$sid" \
    "$GATEWAY_BASE/api/me" 2>/dev/null || true)"
  assert_plugin_forwarded "$name" "$status" "$HEADERS_TMP" "$BODY_TMP"
  after="$(valkey_exec TTL "sess:$sid" | tr -d '\r')"

  if [ "$after" -gt "$before" ] && [ "$after" -gt 60 ]; then
    printf '[PASS] %s ttl_extended before=%s after=%s\n' "$name" "$before" "$after"
    PASSED=$((PASSED + 1))
  else
    printf '[FAIL] %s expected API activity to extend TTL above %s, got %s\n' \
      "$name" "$before" "$after"
    FAILED=$((FAILED + 1))
  fi
  clear_session "$sid"
}

test_session_past_absolute_ceiling_returns_401() {
  name="session_past_absolute_ceiling_returns_401"
  sid="ceiling-past-1"
  # Session whose absolute ceiling is already in the past, but whose access
  # token is still "fresh". The gateway MUST refuse to slide it and treat it as
  # no session (401) + evict the cookie — never EXPIRE a past-ceiling session
  # back to life. This is the hard upper bound on session lifetime (A4/C14).
  setup_session_absolute "$sid" "test-jwt-ceiling-past" 300 -5 1800
  status="$(curl -s -o "$BODY_TMP" -D "$HEADERS_TMP" -w '%{http_code}' \
    -H "Cookie: __Host-sid=$sid" \
    "$GATEWAY_BASE/api/me" 2>/dev/null || true)"
  assert_status "$name status" 401 "$status"
  if grep -iE '^Set-Cookie:[[:space:]]*(sid|__Host-sid)=[[:space:]]*;.*Max-Age=0' \
      "$HEADERS_TMP" >/dev/null 2>&1; then
    printf '[PASS] %s cookie_evicted\n' "$name"
    PASSED=$((PASSED + 1))
  else
    printf '[FAIL] %s expected Set-Cookie Max-Age=0 eviction on dead session\n' "$name"
    FAILED=$((FAILED + 1))
  fi
  clear_session "$sid"
}

test_ttl_slide_capped_at_absolute_ceiling() {
  name="ttl_slide_capped_at_absolute_ceiling"
  sid="ceiling-cap-1"
  # Absolute ceiling only ~8s away; the Valkey key currently has a much larger
  # TTL (100s). A /api request slides the idle window, but the gateway MUST cap
  # EXPIRE at remaining_absolute (~8s), NOT bump it to the full idle window
  # (1800s). So the post-call TTL proves the cap: it lands near ~8, never ~1800.
  setup_session_absolute "$sid" "test-jwt-cap" 300 8 100
  status="$(curl -s -o "$BODY_TMP" -D "$HEADERS_TMP" -w '%{http_code}' \
    -H "Cookie: __Host-sid=$sid" \
    "$GATEWAY_BASE/api/me" 2>/dev/null || true)"
  assert_plugin_forwarded "$name" "$status" "$HEADERS_TMP" "$BODY_TMP"
  after="$(valkey_exec TTL "sess:$sid" | tr -d '\r')"
  # Capped near remaining_absolute (~8s, allow a little clock slack), and well
  # below the idle window — proving the gateway never extends past the ceiling.
  if [ "$after" -gt 0 ] && [ "$after" -le 12 ]; then
    printf '[PASS] %s ttl_capped_at_ceiling after=%s (<=~remaining, not idle 1800)\n' \
      "$name" "$after"
    PASSED=$((PASSED + 1))
  else
    printf '[FAIL] %s expected TTL capped near remaining_absolute (~8s), got %s\n' \
      "$name" "$after"
    FAILED=$((FAILED + 1))
  fi
  clear_session "$sid"
}

test_cookie_strip_does_not_leak_to_upstream() {
  name="cookie_strip_does_not_leak_to_upstream"
  sid="echo-cookie-1"
  setup_echo_session "$name" "$sid" || return 1

  status="$(curl -s -o "$BODY_TMP" -D "$HEADERS_TMP" -w '%{http_code}' \
    -H "Cookie: __Host-sid=$sid; XSRF-TOKEN=should-not-reach-rs; other=also-strip" \
    "$GATEWAY_BASE/api/_test/echo" 2>/dev/null || true)"
  assert_status "$name status" 200 "$status"

  upstream_cookie="$(json_get "$BODY_TMP" "headers.cookie")"
  assert_status "$name upstream_cookie_header" "" "$upstream_cookie"
  clear_session "$sid"
}

test_query_string_preserved() {
  name="query_string_preserved"
  sid="echo-query-1"
  setup_echo_session "$name" "$sid" || return 1

  status="$(curl -s -o "$BODY_TMP" -D "$HEADERS_TMP" -w '%{http_code}' \
    -H "Cookie: __Host-sid=$sid" \
    "$GATEWAY_BASE/api/_test/echo?alpha=1&encoded=a%20b&repeat=one&repeat=two" \
    2>/dev/null || true)"
  assert_status "$name status" 200 "$status"

  query_string="$(json_get "$BODY_TMP" "queryString")"
  assert_status "$name query_string" \
    "alpha=1&encoded=a%20b&repeat=one&repeat=two" "$query_string"
  clear_session "$sid"
}

test_hop_by_hop_headers_stripped() {
  name="hop_by_hop_headers_stripped"
  base_name="$name"
  sid="echo-hop-1"
  setup_echo_session "$name" "$sid" || return 1

  status="$(curl -s -o "$BODY_TMP" -D "$HEADERS_TMP" -w '%{http_code}' \
    -H "Cookie: __Host-sid=$sid" \
    -H "Connection: keep-alive, X-Should-Strip" \
    -H "Keep-Alive: timeout=5" \
    -H "Proxy-Authorization: Basic should-not-reach-rs" \
    -H "TE: trailers" \
    -H "Trailer: X-Trailer" \
    -H "Upgrade: websocket" \
    -H "X-Should-Strip: listed-by-connection" \
    "$GATEWAY_BASE/api/_test/echo" 2>/dev/null || true)"
  assert_status "$base_name status" 200 "$status"

  for header in connection keep-alive proxy-authorization te trailer transfer-encoding upgrade x-should-strip; do
    observed="$(json_get "$BODY_TMP" "headers.$header")"
    assert_status "$base_name $header" "" "$observed"
  done
  clear_session "$sid"
}

# ---------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------

printf -- '---- gateway integration tests ----\n'
test_no_cookie_xhr_returns_401_no_redirect          || true
test_no_cookie_navigation_returns_302_to_login      || true
test_x_forwarded_proto_drives_secure_cookie_handling || true
test_unknown_path_returns_404                       || true
test_internal_path_is_not_routable_through_gateway  || true
test_valid_session_returns_200_with_bearer_injected || true
test_canonical_fixture_payload_parses_through_plugin || true
test_session_with_extra_fields_is_tolerated         || true
test_expiring_session_triggers_refresh_delegation   || true
test_refresh_failure_evicts_session_and_clears_cookie || true
test_state_changing_method_requires_signed_csrf     || true
test_api_activity_slides_session_ttl                || true
test_session_past_absolute_ceiling_returns_401      || true
test_ttl_slide_capped_at_absolute_ceiling           || true
test_cookie_strip_does_not_leak_to_upstream         || true
test_query_string_preserved                         || true
test_hop_by_hop_headers_stripped                    || true

printf -- '---- summary ----\n'
printf '%d passed, %d failed\n' "$PASSED" "$FAILED"

# Zero-run guard: a suite that asserted nothing (preflight skipped everything, a
# rename dropped the run list, etc.) must FAIL loudly, not exit 0. A green count
# of 0 is a harness break, never a pass.
if [ "$((PASSED + FAILED))" -eq 0 ]; then
  printf 'fatal: no gateway assertions executed — harness/setup error, not a pass\n' >&2
  exit 2
fi

if [ "$FAILED" -gt 0 ]; then
  exit 1
fi
exit 0
