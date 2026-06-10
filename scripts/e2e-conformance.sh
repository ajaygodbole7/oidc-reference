#!/usr/bin/env sh
# e2e-conformance.sh — SPEC-0002 live conformance gates (C8/C9).
#
# These gates close the part the browser suite and the default gateway suite do
# NOT cover: that the session-idle TTL is genuinely CONFIG-DRIVEN and reaches
# BOTH planes with a NON-DEFAULT value — not a constant baked into either side.
#
# Two planes must consume the SAME idle window:
#   - auth-service   app.session-idle-ttl   (env SESSION_IDLE_TTL)
#   - gateway plugin idle_ttl_seconds       (env SESSION_IDLE_TTL via the render)
# If they diverge, the session slides by two different windows depending on which
# door (/auth/me vs /api/**) last touched it. The C9.* checks below prove:
#   C9.1  a non-default SESSION_IDLE_TTL / SESSION_MAX_TTL reaches both planes in
#         the RESOLVED config (docker compose config + rendered apisix.yaml).
#   C9.2  the gateway BEHAVIORALLY uses the configured idle (re-render to a small
#         value, reload APISIX, observe the post-/api TTL land there — not 1800).
#   C9.3  /auth/me is a non-extending liveness read (it must not slide the TTL).
#   C9.4  repeated /api activity keeps the session alive beyond one idle window.
#   C9.5  the absolute session ceiling still wins under repeated /api activity.
#
# Requires a running stack (run scripts/up.sh first). Self-contained: it mutates
# only api-gateway/apisix.yaml.local (gitignored) and bounces APISIX, restoring
# the default render on exit.
#
# Gating: set RUN_LIVE_CONFORMANCE=1.

set -eu
SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
ROOT="$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)"
cd "$ROOT"

if [ "${RUN_LIVE_CONFORMANCE:-0}" != "1" ]; then
  printf 'skipping; set RUN_LIVE_CONFORMANCE=1 to enable live conformance tests\n'
  exit 0
fi

# shellcheck disable=SC1091
. "$ROOT/api-gateway/tests/lib.sh"

DEV_CSRF_KEY='AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='
DEV_GATEWAY_SECRET='LOCAL_DEV_GATEWAY_CLIENT_SECRET__CHANGE_BEFORE_DEPLOY'
GATEWAY_BASE="${GATEWAY_BASE:-http://127.0.0.1:9080}"
BODY_TMP="$(mktemp)"
HEADERS_TMP="$(mktemp)"

# Non-default, compressed values so the override is unmistakably NOT the 1800/
# 28800 defaults.
ALT_IDLE=10
ALT_MAX=45

render_idle() {
  # Render apisix.yaml.local with idle_ttl_seconds=$1, defaults otherwise.
  SESSION_IDLE_TTL="$1" \
    GATEWAY_CLIENT_ID=oidc-reference-api-gateway \
    GATEWAY_CLIENT_SECRET="$DEV_GATEWAY_SECRET" \
    CSRF_SIGNING_KEY="$DEV_CSRF_KEY" \
    sh "$SCRIPT_DIR/render-apisix-config.sh" >/dev/null 2>&1
}

reload_apisix() {
  docker compose restart apisix >/dev/null 2>&1 || true
  i=0
  while [ "$i" -lt 30 ]; do
    s="$(curl -s -o /dev/null -w '%{http_code}' "$GATEWAY_BASE/api/me" 2>/dev/null || true)"
    [ -n "$s" ] && [ "$s" != "000" ] && return 0
    i=$((i + 1)); sleep 2
  done
  printf 'fatal: APISIX did not come back after reload\n' >&2
  exit 2
}

# Restore the default render + a default-idle APISIX on ANY exit, so a failed
# run never leaves the dev stack on the compressed idle window.
restore() {
  _status=$?
  trap - EXIT INT TERM
  render_idle 1800 || true
  reload_apisix || true
  clear_all_tracked_sessions || true
  exit "$_status"
}
trap restore EXIT INT TERM

printf -- '---- SPEC-0002 C8 internal trust-identity gate (live wire) ----\n'
# /internal/refresh is internal-only; its caller-identity + audience checks are
# config-driven (GATEWAY_CLIENT_ID / INTERNAL_REFRESH_AUDIENCE). e2e-portability
# proves the RS API-audience config-driven on the wire; this proves the INTERNAL
# trust identity on the wire, positive AND negative, by minting real Keycloak CC
# tokens and POSTing to auth-service:8081 from inside the compose network.
KC_TOKEN_URL="http://localhost:8080/realms/oidc-reference/protocol/openid-connect/token"

mint_cc() { # $1 client_id  $2 client_secret -> echoes access_token
  curl -fsS -d grant_type=client_credentials -d "client_id=$1" \
    --data-urlencode "client_secret=$2" "$KC_TOKEN_URL" 2>/dev/null \
    | python3 -c 'import json,sys; print(json.load(sys.stdin).get("access_token",""))' 2>/dev/null
}

post_internal_refresh() { # $1 bearer -> echoes HTTP status
  # resource-server container has curl and sits on the compose network with
  # auth-service. /internal/refresh is not routable through APISIX by design.
  docker compose exec -T resource-server curl -s -o /dev/null -w '%{http_code}' \
    -X POST \
    -H "Authorization: Bearer $1" \
    -H "Content-Type: application/json" \
    --data '{"sid":"conformance-nonexistent-sid"}' \
    http://auth-service:8081/internal/refresh 2>/dev/null
}

gw_tok="$(mint_cc oidc-reference-api-gateway "$DEV_GATEWAY_SECRET")"
svc_tok="$(mint_cc oidc-reference-service LOCAL_DEV_SERVICE_CLIENT_SECRET__CHANGE_BEFORE_DEPLOY)"

if [ -z "$gw_tok" ] || [ -z "$svc_tok" ]; then
  printf '[FAIL] C8 could not mint CC tokens (gw_empty=%s svc_empty=%s) — cannot run wire gate\n' \
    "$([ -z "$gw_tok" ] && echo yes || echo no)" "$([ -z "$svc_tok" ] && echo yes || echo no)"
  FAILED=$((FAILED + 1))
else
  gw_code="$(post_internal_refresh "$gw_tok")"
  svc_code="$(post_internal_refresh "$svc_tok")"
  # Configured gateway client: passes the identity+audience check, reaches session
  # lookup -> 404 (bogus sid). Any of 404/409/200 means "accepted past identity".
  case "$gw_code" in
    404|409|200)
      printf '[PASS] C8 configured gateway client passes /internal/refresh identity check (status=%s)\n' "$gw_code"
      PASSED=$((PASSED + 1)) ;;
    401|403)
      printf '[FAIL] C8 configured gateway client was REJECTED at identity check (status=%s) — refresh would never work\n' "$gw_code"
      FAILED=$((FAILED + 1)) ;;
    *)
      printf '[FAIL] C8 configured gateway client unexpected status=%s\n' "$gw_code"
      FAILED=$((FAILED + 1)) ;;
  esac
  # Foreign client (oidc-reference-service): wrong azp/client_id AND wrong
  # audience -> rejected at the identity check, never reaching session logic.
  case "$svc_code" in
    401|403)
      printf '[PASS] C8 foreign client REJECTED at /internal/refresh identity check (status=%s)\n' "$svc_code"
      PASSED=$((PASSED + 1)) ;;
    *)
      printf '[FAIL] C8 foreign client NOT rejected (status=%s; expected 401/403) — trust id not enforced on the wire\n' "$svc_code"
      FAILED=$((FAILED + 1)) ;;
  esac
fi

printf -- '---- SPEC-0002 C9 session-window conformance ----\n'

# --- C9.1 plumbing: non-default value reaches BOTH planes --------------------
cfg="$(SESSION_IDLE_TTL="$ALT_IDLE" SESSION_MAX_TTL="$ALT_MAX" \
  CSRF_SIGNING_KEY="$DEV_CSRF_KEY" docker compose config 2>/dev/null || true)"

# auth-service environment must carry the overridden integers. docker compose
# config renders env as `KEY: "value"` or `KEY: value`; match either.
if printf '%s' "$cfg" | grep -Eq "SESSION_IDLE_TTL: \"?$ALT_IDLE\"?"; then
  printf '[PASS] C9.1 compose forwards SESSION_IDLE_TTL=%s to auth-service\n' "$ALT_IDLE"
  PASSED=$((PASSED + 1))
else
  printf '[FAIL] C9.1 compose did not forward SESSION_IDLE_TTL=%s\n' "$ALT_IDLE"
  FAILED=$((FAILED + 1))
fi
if printf '%s' "$cfg" | grep -Eq "SESSION_MAX_TTL: \"?$ALT_MAX\"?"; then
  printf '[PASS] C9.1 compose forwards SESSION_MAX_TTL=%s to auth-service\n' "$ALT_MAX"
  PASSED=$((PASSED + 1))
else
  printf '[FAIL] C9.1 compose did not forward SESSION_MAX_TTL=%s\n' "$ALT_MAX"
  FAILED=$((FAILED + 1))
fi

# rendered apisix idle_ttl_seconds must track SESSION_IDLE_TTL (the gateway plane)
render_idle "$ALT_IDLE"
rendered_idle="$(grep -m1 'idle_ttl_seconds:' api-gateway/apisix.yaml.local \
  | grep -oE '[0-9]+' | head -1)"
assert_status "C9.1 rendered apisix idle_ttl_seconds tracks SESSION_IDLE_TTL" \
  "$ALT_IDLE" "${rendered_idle:-unset}"

# --- C9.2 gateway behaviorally USES the configured idle (not the 1800 default) -
reload_apisix
sid="conf-idle-1"
# absolute ceiling far in the future so the cap is the IDLE value, not remaining.
setup_session_absolute "$sid" "test-jwt-conf-idle" 300 3600 100
# The plugin slides the TTL in its access phase BEFORE forwarding upstream, so
# the post-call TTL reflects the configured idle regardless of the RS verdict on
# the (fake) bearer. We only require the plugin did NOT short-circuit the request
# as no-session (302/401-no-cookie) or CSRF (403) — any forwarded status proves
# the slide ran. A GET carries no CSRF, so 401-from-RS / 200 are the live cases.
status="$(curl -s -o "$BODY_TMP" -D "$HEADERS_TMP" -w '%{http_code}' \
  -H "Cookie: __Host-sid=$sid" \
  "$GATEWAY_BASE/api/me" 2>/dev/null || true)"
case "$status" in
  302|403|502|000|"")
    printf '[FAIL] C9.2 plugin did not forward /api (status=%s) — slide did not run\n' "$status"
    FAILED=$((FAILED + 1)) ;;
  *)
    printf '[PASS] C9.2 plugin forwarded /api (status=%s; slide ran in access phase)\n' "$status"
    PASSED=$((PASSED + 1)) ;;
esac
after="$(valkey_exec TTL "sess:$sid" | tr -d '\r')"
# With the configured idle=10 the slide lands near 10; with the 1800 default it
# would be ~1800. <=13 proves the gateway read the configured value.
if [ "$after" -gt 0 ] && [ "$after" -le 13 ]; then
  printf '[PASS] C9.2 gateway used configured idle: post-/api TTL=%s (~%s, not 1800)\n' \
    "$after" "$ALT_IDLE"
  PASSED=$((PASSED + 1))
else
  printf '[FAIL] C9.2 expected post-/api TTL ~%s (configured idle), got %s\n' \
    "$ALT_IDLE" "$after"
  FAILED=$((FAILED + 1))
fi
clear_session "$sid"

# --- C9.3 /auth/me is a non-extending liveness read --------------------------
# Seed a full-shaped session (with claims) so /auth/me returns 200, give it a
# known low Valkey TTL, then hit /auth/me and assert the TTL was NOT bumped to
# the idle window — only /api activity slides the session.
sid="conf-noextend-1"
expires_at="$(iso8601_in 300)"
absolute_expires_at="$(iso8601_in 3600)"
payload="$(printf '{"access_token":"at","access_token_expires_at":"%s","absolute_expires_at":"%s","claims":{"sub":"alice","roles":["user"]}}' \
  "$expires_at" "$absolute_expires_at")"
valkey_exec SET "sess:$sid" "$payload" EX 40 >/dev/null
track_sid "$sid"
me_status="$(curl -s -o /dev/null -w '%{http_code}' \
  -H "Cookie: sid=$sid" -H "Cookie: __Host-sid=$sid" \
  "$GATEWAY_BASE/auth/me" 2>/dev/null || true)"
after_me="$(valkey_exec TTL "sess:$sid" | tr -d '\r')"
if [ "$me_status" = "200" ]; then
  # /auth/me accepted the session; it must NOT have slid the TTL toward idle.
  if [ "$after_me" -le 40 ] && [ "$after_me" -gt 0 ]; then
    printf '[PASS] C9.3 /auth/me did NOT extend session TTL (still %s<=40, no slide)\n' "$after_me"
    PASSED=$((PASSED + 1))
  else
    printf '[FAIL] C9.3 /auth/me extended the session TTL to %s (must not slide)\n' "$after_me"
    FAILED=$((FAILED + 1))
  fi
else
  printf '[FAIL] C9.3 /auth/me returned %s on the seeded session (expected 200) — cannot prove no-extend\n' \
    "$me_status"
  FAILED=$((FAILED + 1))
fi
clear_session "$sid"

# --- C9.4 repeated /api activity keeps the session alive past one idle window -
sid="conf-steady-api-1"
setup_session_absolute "$sid" "test-jwt-steady-api" 300 60 "$ALT_IDLE"
status1="$(curl -s -o "$BODY_TMP" -D "$HEADERS_TMP" -w '%{http_code}' \
  -H "Cookie: __Host-sid=$sid" \
  "$GATEWAY_BASE/api/me" 2>/dev/null || true)"
case "$status1" in
  302|403|502|000|"")
    printf '[FAIL] C9.4 first /api did not forward (status=%s)\n' "$status1"
    FAILED=$((FAILED + 1)) ;;
  *)
    sleep 6
    status2="$(curl -s -o "$BODY_TMP" -D "$HEADERS_TMP" -w '%{http_code}' \
      -H "Cookie: __Host-sid=$sid" \
      "$GATEWAY_BASE/api/me" 2>/dev/null || true)"
    sleep 6
    status3="$(curl -s -o "$BODY_TMP" -D "$HEADERS_TMP" -w '%{http_code}' \
      -H "Cookie: __Host-sid=$sid" \
      "$GATEWAY_BASE/api/me" 2>/dev/null || true)"
    exists="$(valkey_exec EXISTS "sess:$sid" | tr -d '\r')"
    ttl="$(valkey_exec TTL "sess:$sid" | tr -d '\r')"
    case "$status2:$status3:$exists" in
      302:*|403:*|502:*|000:*|*:302:*|*:403:*|*:502:*|*:000:*|*:0)
        printf '[FAIL] C9.4 repeated /api did not keep session alive (status2=%s status3=%s exists=%s ttl=%s)\n' \
          "$status2" "$status3" "$exists" "$ttl"
        FAILED=$((FAILED + 1)) ;;
      *)
        printf '[PASS] C9.4 repeated /api kept session alive beyond one idle window (status2=%s status3=%s ttl=%s)\n' \
          "$status2" "$status3" "$ttl"
        PASSED=$((PASSED + 1)) ;;
    esac ;;
esac
clear_session "$sid"

# --- C9.5 absolute ceiling still wins under repeated /api activity ------------
sid="conf-absolute-ceiling-1"
setup_session_absolute "$sid" "test-jwt-absolute-ceiling" 300 11 "$ALT_IDLE"
status1="$(curl -s -o "$BODY_TMP" -D "$HEADERS_TMP" -w '%{http_code}' \
  -H "Cookie: __Host-sid=$sid" \
  "$GATEWAY_BASE/api/me" 2>/dev/null || true)"
sleep 6
status2="$(curl -s -o "$BODY_TMP" -D "$HEADERS_TMP" -w '%{http_code}' \
  -H "Cookie: __Host-sid=$sid" \
  "$GATEWAY_BASE/api/me" 2>/dev/null || true)"
sleep 6
status3="$(curl -s -o "$BODY_TMP" -D "$HEADERS_TMP" -w '%{http_code}' \
  -H "Cookie: __Host-sid=$sid" \
  "$GATEWAY_BASE/api/me" 2>/dev/null || true)"
exists="$(valkey_exec EXISTS "sess:$sid" | tr -d '\r')"
case "$status1:$status2:$status3:$exists" in
  302:*|403:*|502:*|000:*|*:302:*|*:403:*|*:502:*|*:000:*)
    printf '[FAIL] C9.5 setup activity failed before proving ceiling (status1=%s status2=%s status3=%s exists=%s)\n' \
      "$status1" "$status2" "$status3" "$exists"
    FAILED=$((FAILED + 1)) ;;
  *:401:0)
    printf '[PASS] C9.5 absolute ceiling ended session despite repeated /api activity (final status=%s)\n' \
      "$status3"
    PASSED=$((PASSED + 1)) ;;
  *)
    printf '[FAIL] C9.5 expected absolute ceiling to end session; got status1=%s status2=%s status3=%s exists=%s\n' \
      "$status1" "$status2" "$status3" "$exists"
    FAILED=$((FAILED + 1)) ;;
esac
clear_session "$sid"

printf -- '---- summary ----\n'
printf '%d passed, %d failed\n' "$PASSED" "$FAILED"
[ "$FAILED" -eq 0 ]
