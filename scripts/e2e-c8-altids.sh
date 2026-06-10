#!/usr/bin/env sh
# e2e-c8-altids.sh — SPEC-0001 C8 NON-DEFAULT trust-identity gate (end-to-end).
#
# The default-config C8 (in e2e-conformance.sh) proves /internal/refresh enforces
# the SHIPPED trust ids. This gate proves the ENV KNOBS are genuinely read, not
# constants: it boots the stack with auth-service configured for NON-DEFAULT
# values and shows the wire behavior flips accordingly.
#
# Non-default values reuse the existing oidc-reference-service client
# (azp=oidc-reference-service, aud=oidc-reference-api) — both distinct from the
# shipped oidc-reference-api-gateway / oidc-reference-auth-internal defaults — so
# no extra realm client is needed.
#
#   GATEWAY_CLIENT_ID=oidc-reference-service
#   INTERNAL_REFRESH_AUDIENCE=oidc-reference-api
#
# Asserts on the wire (POST to auth-service:8081/internal/refresh from inside the
# compose network, /internal/** is not routable through APISIX by design):
#   - config reaches the plane: `docker compose config` shows the overrides;
#   - POSITIVE: a token matching the NON-DEFAULT config (oidc-reference-service)
#     passes the identity check -> 404 (bogus sid), proving the knobs are read;
#   - NEGATIVE: the DEFAULT gateway client now MISMATCHES -> 401, proving a
#     one-sided value change breaks /internal/refresh.

set -eu
SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
. "$SCRIPT_DIR/lib/common.sh"
ROOT="$(repo_root "$SCRIPT_DIR")"
cd "$ROOT"

require_cmd docker "Install Docker Desktop or Colima."
require_cmd python3 "Install Python 3."

DEV_CSRF_KEY='AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='
DEV_GATEWAY_SECRET='LOCAL_DEV_GATEWAY_CLIENT_SECRET__CHANGE_BEFORE_DEPLOY'
DEV_SERVICE_SECRET='LOCAL_DEV_SERVICE_CLIENT_SECRET__CHANGE_BEFORE_DEPLOY'
ALT_GATEWAY_CLIENT_ID='oidc-reference-service'
ALT_INTERNAL_AUDIENCE='oidc-reference-api'
KC_TOKEN_URL='http://localhost:8080/realms/oidc-reference/protocol/openid-connect/token'

LOCK="$ROOT/.local/e2e-c8-altids.lock"
mkdir -p "$ROOT/.local"
if ! mkdir "$LOCK" 2>/dev/null; then
  die "another C8-altids run is active (lock: $LOCK)"
fi

cleanup() {
  _status=$?
  trap - EXIT INT TERM
  sh "$SCRIPT_DIR/down.sh" >/dev/null 2>&1 || true
  rmdir "$LOCK" 2>/dev/null || rm -rf "$LOCK" 2>/dev/null || true
  exit "$_status"
}
trap cleanup EXIT INT TERM

info "tearing down any existing stack for a clean slate"
sh "$SCRIPT_DIR/down.sh" >/dev/null 2>&1 || true

# Render APISIX with the DEFAULT gateway client: this gate posts to
# /internal/refresh directly with minted tokens, so the gateway's own client is
# irrelevant — only the auth-service env is reconfigured.
info "rendering APISIX (default gateway client)"
GATEWAY_CLIENT_SECRET="$DEV_GATEWAY_SECRET" CSRF_SIGNING_KEY="$DEV_CSRF_KEY" \
  sh "$SCRIPT_DIR/render-apisix-config.sh"

info "starting stack with NON-DEFAULT auth-service trust ids"
GATEWAY_CLIENT_ID="$ALT_GATEWAY_CLIENT_ID" \
  INTERNAL_REFRESH_AUDIENCE="$ALT_INTERNAL_AUDIENCE" \
  CSRF_SIGNING_KEY="$DEV_CSRF_KEY" \
  RESOURCE_SERVER_SPRING_PROFILES_ACTIVE=gateway-test \
  docker compose up -d --build keycloak valkey auth-service resource-server apisix

wait_http       "Keycloak" "http://localhost:8080/realms/oidc-reference/.well-known/openid-configuration" 60
wait_responding "APISIX"   "http://127.0.0.1:9080/api/me" 120

PASSED=0
FAILED=0

printf -- '---- SPEC-0001 C8 non-default trust-id gate (end-to-end) ----\n'

# Config reaches the plane.
cfg="$(GATEWAY_CLIENT_ID="$ALT_GATEWAY_CLIENT_ID" \
  INTERNAL_REFRESH_AUDIENCE="$ALT_INTERNAL_AUDIENCE" \
  docker compose config 2>/dev/null || true)"
if printf '%s' "$cfg" | grep -Eq "GATEWAY_CLIENT_ID: \"?$ALT_GATEWAY_CLIENT_ID\"?"; then
  printf '[PASS] compose forwards non-default GATEWAY_CLIENT_ID=%s\n' "$ALT_GATEWAY_CLIENT_ID"
  PASSED=$((PASSED + 1))
else
  printf '[FAIL] compose did not forward GATEWAY_CLIENT_ID=%s\n' "$ALT_GATEWAY_CLIENT_ID"
  FAILED=$((FAILED + 1))
fi
if printf '%s' "$cfg" | grep -Eq "INTERNAL_REFRESH_AUDIENCE: \"?$ALT_INTERNAL_AUDIENCE\"?"; then
  printf '[PASS] compose forwards non-default INTERNAL_REFRESH_AUDIENCE=%s\n' "$ALT_INTERNAL_AUDIENCE"
  PASSED=$((PASSED + 1))
else
  printf '[FAIL] compose did not forward INTERNAL_REFRESH_AUDIENCE=%s\n' "$ALT_INTERNAL_AUDIENCE"
  FAILED=$((FAILED + 1))
fi

mint_cc() { # $1 client_id  $2 secret
  curl -fsS -d grant_type=client_credentials -d "client_id=$1" \
    --data-urlencode "client_secret=$2" "$KC_TOKEN_URL" 2>/dev/null \
    | python3 -c 'import json,sys; print(json.load(sys.stdin).get("access_token",""))' 2>/dev/null
}

post_internal_refresh() { # $1 bearer -> echoes HTTP status
  docker compose exec -T resource-server curl -s -o /dev/null -w '%{http_code}' \
    -X POST \
    -H "Authorization: Bearer $1" \
    -H "Content-Type: application/json" \
    --data '{"sid":"c8-altids-nonexistent-sid"}' \
    http://auth-service:8081/internal/refresh 2>/dev/null
}

alt_tok="$(mint_cc "$ALT_GATEWAY_CLIENT_ID" "$DEV_SERVICE_SECRET")"
default_tok="$(mint_cc oidc-reference-api-gateway "$DEV_GATEWAY_SECRET")"

if [ -z "$alt_tok" ] || [ -z "$default_tok" ]; then
  printf '[FAIL] could not mint CC tokens (alt_empty=%s default_empty=%s)\n' \
    "$([ -z "$alt_tok" ] && echo yes || echo no)" "$([ -z "$default_tok" ] && echo yes || echo no)"
  FAILED=$((FAILED + 1))
else
  alt_code="$(post_internal_refresh "$alt_tok")"
  default_code="$(post_internal_refresh "$default_tok")"
  # POSITIVE: token matching the NON-DEFAULT config passes identity -> 404 bogus sid.
  case "$alt_code" in
    404|409|200)
      printf '[PASS] non-default-configured client (%s) PASSES identity check (status=%s) — knobs read end-to-end\n' \
        "$ALT_GATEWAY_CLIENT_ID" "$alt_code"
      PASSED=$((PASSED + 1)) ;;
    *)
      printf '[FAIL] non-default-configured client REJECTED (status=%s) — env knobs not honored\n' "$alt_code"
      FAILED=$((FAILED + 1)) ;;
  esac
  # NEGATIVE: the DEFAULT gateway client now mismatches -> 401.
  case "$default_code" in
    401|403)
      printf '[PASS] DEFAULT gateway client now REJECTED under non-default config (status=%s) — one-sided change breaks refresh\n' "$default_code"
      PASSED=$((PASSED + 1)) ;;
    *)
      printf '[FAIL] default gateway client NOT rejected (status=%s; expected 401/403) — config not enforced\n' "$default_code"
      FAILED=$((FAILED + 1)) ;;
  esac
fi

printf -- '---- summary ----\n'
printf '%d passed, %d failed\n' "$PASSED" "$FAILED"
[ "$FAILED" -eq 0 ]
