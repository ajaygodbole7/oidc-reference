#!/usr/bin/env sh
# e2e-conformance.sh — SPEC-0001 live conformance gates (C8/C9, see §Test Plan).
#
# These gates close the part the browser suite and the default gateway suite do
# NOT cover: that the session-idle TTL is genuinely CONFIG-DRIVEN — the Auth
# Service READS SESSION_IDLE_TTL, it is not a constant baked into the slide.
#
# Under the phantom-token topology the idle slide lives in ONE plane: the Auth
# Service's POST /internal/resolve (env SESSION_IDLE_TTL). The gateway holds no
# store handle and no idle window — every /api/** request resolves the sid via
# the Auth Service, which looks up the session and slides it. The C9.* checks
# below prove:
#   C9.1  a non-default SESSION_IDLE_TTL / SESSION_MAX_TTL reaches the auth-service
#         plane in the RESOLVED config (docker compose config).
#   C9.2  the Auth Service BEHAVIORALLY uses the configured idle (recreate the
#         auth-service at a small value, resolve via /api, observe the post-/api
#         TTL land there — not 1800).
#   C9.3  /auth/me is a non-extending liveness read (it must not slide the TTL).
#   C9.4  repeated /api activity keeps the session alive beyond one idle window.
#   C9.5  the absolute session ceiling still wins under repeated /api activity.
#
# Requires a running stack (run scripts/up.sh first). Self-contained: it
# recreates only the auth-service container at a compressed idle for the
# behavioral checks, restoring the default-idle auth-service on exit.
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

set_auth_idle() {
  # Recreate ONLY the auth-service with SESSION_IDLE_TTL=$1, everything else at
  # its compose dev default (this mirrors how test-e2e.sh brings the stack up:
  # CSRF_SIGNING_KEY pinned, all other auth-service env defaulted via ${VAR:-…}).
  # The idle slide now lives in the Auth Service (POST /internal/resolve), so a
  # behavioral idle change is an auth-service ENV change — NOT an apisix
  # re-render: the gateway no longer knows the idle window. Health-gate on the
  # container healthcheck with --wait (preferred over hand-tuned curl retries).
  # Seeded sessions live in Valkey (untouched by the recreate), so they survive.
  SESSION_IDLE_TTL="$1" CSRF_SIGNING_KEY="$DEV_CSRF_KEY" \
    docker compose up -d --no-deps --force-recreate --wait auth-service \
    >/dev/null 2>&1
}

# Restore the default-idle auth-service on ANY exit, so a failed run never
# leaves the dev stack on the compressed idle window.
restore() {
  _status=$?
  trap - EXIT INT TERM
  set_auth_idle 1800 >/dev/null 2>&1 || true
  clear_all_tracked_sessions || true
  exit "$_status"
}
trap restore EXIT INT TERM

printf -- '---- SPEC-0001 C8 internal trust-identity gate (live wire) ----\n'
# /internal/resolve is internal-only; its caller-identity + audience checks are
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
  # auth-service. /internal/resolve is not routable through APISIX by design.
  docker compose exec -T resource-server curl -s -o /dev/null -w '%{http_code}' \
    -X POST \
    -H "Authorization: Bearer $1" \
    -H "Content-Type: application/json" \
    --data '{"sid":"conformance-nonexistent-sid"}' \
    http://auth-service:8081/internal/resolve 2>/dev/null
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
      printf '[PASS] C8 configured gateway client passes /internal/resolve identity check (status=%s)\n' "$gw_code"
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
      printf '[PASS] C8 foreign client REJECTED at /internal/resolve identity check (status=%s)\n' "$svc_code"
      PASSED=$((PASSED + 1)) ;;
    *)
      printf '[FAIL] C8 foreign client NOT rejected (status=%s; expected 401/403) — trust id not enforced on the wire\n' "$svc_code"
      FAILED=$((FAILED + 1)) ;;
  esac
fi

printf -- '---- SPEC-0001 C9 session-window conformance ----\n'

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

# --- C9.2 the Auth Service behaviorally USES the configured idle (not 1800) ---
# Recreate the auth-service at the compressed idle. The resolve handler reads
# app.session-idle-ttl (env SESSION_IDLE_TTL) and slides to it on every /api
# resolve; if it ignored config and used a hardcoded 1800, the post-/api TTL
# below would land at ~1800 instead of ~10.
if ! set_auth_idle "$ALT_IDLE"; then
  printf 'fatal: auth-service did not become healthy at idle=%s\n' "$ALT_IDLE" >&2
  exit 2
fi
sid="conf-idle-1"
# absolute ceiling far in the future so the cap is the IDLE value, not remaining.
setup_session_absolute "$sid" "test-jwt-conf-idle" 300 3600 100
# The Auth Service slides the TTL inside /internal/resolve BEFORE the gateway
# forwards upstream, so the post-call TTL reflects the configured idle regardless
# of the RS verdict on the (fake) bearer. We only require the gateway did NOT
# short-circuit as no-session (302/401-no-cookie) or CSRF (403) — any forwarded
# status proves resolve ran. A GET carries no CSRF, so 401-from-RS / 200 are the
# live cases.
status="$(curl -s -o "$BODY_TMP" -D "$HEADERS_TMP" -w '%{http_code}' \
  -H "Cookie: __Host-sid=$sid" \
  "$GATEWAY_BASE/api/me" 2>/dev/null || true)"
case "$status" in
  302|403|502|000|"")
    printf '[FAIL] C9.2 gateway did not resolve+forward /api (status=%s) — slide did not run\n' "$status"
    FAILED=$((FAILED + 1)) ;;
  *)
    printf '[PASS] C9.2 gateway resolved+forwarded /api (status=%s; Auth Service slid the session)\n' "$status"
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
# Valkey TTL (40) ABOVE the now-configured idle (10), then hit /auth/me and
# assert the TTL was NOT slid down to the idle window — only /api activity (the
# resolve path) slides the session. A wrongful slide here would drop 40 -> ~10.
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
  # No slide keeps it near the seeded 40; a slide would drop it to ~10 (the
  # configured idle). >20 cleanly separates the two outcomes.
  if [ "$after_me" -gt 20 ] && [ "$after_me" -le 40 ]; then
    printf '[PASS] C9.3 /auth/me did NOT slide session TTL (still %s, not dropped to ~%s)\n' \
      "$after_me" "$ALT_IDLE"
    PASSED=$((PASSED + 1))
  else
    printf '[FAIL] C9.3 /auth/me slid the session TTL to %s (must not slide; expected ~40)\n' "$after_me"
    FAILED=$((FAILED + 1))
  fi
else
  printf '[FAIL] C9.3 /auth/me returned %s on the seeded session (expected 200) — cannot prove no-extend\n' \
    "$me_status"
  FAILED=$((FAILED + 1))
fi
clear_session "$sid"

# --- C9.4 repeated /api activity keeps the session alive past one idle window -
# De-flaked (C3): instead of two fixed `sleep 6` against idle=10 (4s of margin a
# slow host can drift past), poll /api at gaps well UNDER the idle window across
# MORE than one window. Each call slides the idle TTL; because no inter-call gap
# approaches the window, a slow host only delays the test — it cannot flip it to
# a false failure. Without the slide the session would expire at one idle window;
# we assert it still EXISTS with a live TTL at the end.
sid="conf-steady-api-1"
setup_session_absolute "$sid" "test-jwt-steady-api" 300 60 "$ALT_IDLE"
gap=$(( ALT_IDLE / 3 ))
[ "$gap" -lt 2 ] && gap=2
alive=1
calls=0
while [ "$calls" -lt 6 ]; do   # 6 calls, 5 gaps -> >= ~1.6 idle windows elapsed
  status="$(curl -s -o "$BODY_TMP" -D "$HEADERS_TMP" -w '%{http_code}' \
    -H "Cookie: __Host-sid=$sid" \
    "$GATEWAY_BASE/api/me" 2>/dev/null || true)"
  case "$status" in 302|403|502|000|"") alive=0; break ;; esac
  calls=$((calls + 1))
  [ "$calls" -lt 6 ] && sleep "$gap"
done
exists="$(valkey_exec EXISTS "sess:$sid" | tr -d '\r')"
ttl="$(valkey_exec TTL "sess:$sid" | tr -d '\r')"; ttl="${ttl:-0}"
if [ "$alive" = 1 ] && [ "$exists" != 0 ] && [ "$ttl" -gt 0 ]; then
  printf '[PASS] C9.4 repeated /api kept session alive beyond one idle window (calls=%s exists=%s ttl=%s)\n' \
    "$calls" "$exists" "$ttl"
  PASSED=$((PASSED + 1))
else
  printf '[FAIL] C9.4 repeated /api did not keep session alive (alive=%s exists=%s ttl=%s)\n' \
    "$alive" "$exists" "$ttl"
  FAILED=$((FAILED + 1))
fi
clear_session "$sid"

# --- C9.5 absolute ceiling still wins under repeated /api activity ------------
# De-flaked (C3): the absolute ceiling (11s) must end the session despite the
# idle slide that continuous /api activity applies. Poll /api to a deadline well
# past the ceiling and detect death by EXISTS=0 — NOT by status: a non-JWT token
# yields RS 401 while the session is alive AND the gateway yields 401 once it is
# gone, so only EXISTS distinguishes "alive" from "ended".
sid="conf-absolute-ceiling-1"
setup_session_absolute "$sid" "test-jwt-absolute-ceiling" 300 11 "$ALT_IDLE"
status1="$(curl -s -o "$BODY_TMP" -D "$HEADERS_TMP" -w '%{http_code}' \
  -H "Cookie: __Host-sid=$sid" \
  "$GATEWAY_BASE/api/me" 2>/dev/null || true)"
died=0
iter=0
while [ "$iter" -lt 14 ]; do   # 14 * 2s = 28s, well past the 11s ceiling
  exists="$(valkey_exec EXISTS "sess:$sid" | tr -d '\r')"
  [ "$exists" = 0 ] && { died=1; break; }
  sleep 2
  curl -s -o /dev/null -H "Cookie: __Host-sid=$sid" \
    "$GATEWAY_BASE/api/me" 2>/dev/null || true
  iter=$((iter + 1))
done
case "$status1" in
  302|403|502|000|"")
    printf '[FAIL] C9.5 setup /api did not forward (status1=%s) — cannot prove ceiling\n' "$status1"
    FAILED=$((FAILED + 1)) ;;
  *)
    if [ "$died" = 1 ]; then
      printf '[PASS] C9.5 absolute ceiling ended session despite repeated /api activity (iters=%s)\n' "$iter"
      PASSED=$((PASSED + 1))
    else
      printf '[FAIL] C9.5 expected absolute ceiling to end session; still alive past deadline\n'
      FAILED=$((FAILED + 1))
    fi ;;
esac
clear_session "$sid"

printf -- '---- summary ----\n'
printf '%d passed, %d failed\n' "$PASSED" "$FAILED"
[ "$FAILED" -eq 0 ]
