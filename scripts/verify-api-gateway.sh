#!/usr/bin/env sh
set -eu

# Verify script for the APISIX-based API Gateway.
#
# Two layers, mirroring the verify-rs-negatives split:
#
#   1. Static (always runs): assert api-gateway/apisix.yaml declares the
#      expected routes and the bff-session Lua plugin file is non-empty.
#      Pure POSIX grep -F lookups so the gate runs without ripgrep.
#
#   2. Live (opt-in via RUN_LIVE_API_GATEWAY=1): hit APISIX on :9080 and
#      assert the no-session / CSRF / route-allowlist behaviour matches
#      the spec. Assumes the Compose stack is already up
#      (`docker compose up -d`); does not start it.

cd "$(dirname "$0")/.."

fail() {
  echo "api-gateway verification failed: $1" >&2
  exit 1
}

# ---- Static check ----

# The tracked source of truth is the template; the rendered .local file
# is gitignored and produced by scripts/render-apisix-config.sh on
# `compose up`. Static structural checks run against the template so
# this gate is meaningful in a clean checkout.
apisix_yaml="api-gateway/apisix.yaml.template"
plugin_lua="api-gateway/plugins/bff-session.lua"

[ -f "$apisix_yaml" ] || fail "$apisix_yaml not present"

grep -F -q "/api/me" "$apisix_yaml" \
  || fail "$apisix_yaml missing /api/me route"
grep -F -q "/api/user-data" "$apisix_yaml" \
  || fail "$apisix_yaml missing /api/user-data route"
grep -F -q "/api/admin" "$apisix_yaml" \
  || fail "$apisix_yaml missing /api/admin route"
grep -F -q "/auth" "$apisix_yaml" \
  || fail "$apisix_yaml missing /auth passthrough route"

if [ ! -s "$plugin_lua" ]; then
  fail "$plugin_lua missing or empty (gateway-agent's Lua plugin must land here)"
fi

# ---- Live check (opt-in) ----

if [ "${RUN_LIVE_API_GATEWAY:-0}" = "1" ]; then
  base="${APISIX_BASE_URL:-http://127.0.0.1:9080}"

  expect_status() {
    name="$1"
    expected="$2"
    shift 2
    status="$(curl -o /dev/null -s -w '%{http_code}' "$@" || true)"
    if [ "$status" != "$expected" ]; then
      fail "$name: expected HTTP $expected, got $status"
    fi
  }

  # XHR fetch with no session: plugin short-circuits 401.
  expect_status "api-me unauthenticated XHR" "401" \
    -H "Sec-Fetch-Mode: cors" -H "Sec-Fetch-Dest: empty" \
    "$base/api/me"

  # Navigation request with no session: plugin issues a 302 to
  # /auth/login?return_to=... so the browser sees a clean redirect into
  # the OIDC flow rather than a 401 JSON body. The contract migrated
  # from `next` to `return_to` in commit fda5ef1 — assert the new name.
  status="$(curl -o /dev/null -s -w '%{http_code}' \
    -H "Sec-Fetch-Mode: navigate" -H "Sec-Fetch-Dest: document" \
    "$base/api/me" || true)"
  if [ "$status" != "302" ]; then
    fail "api-me navigation: expected 302 to /auth/login?return_to=..., got $status"
  fi
  location="$(curl -o /dev/null -s -D - \
    -H "Sec-Fetch-Mode: navigate" -H "Sec-Fetch-Dest: document" \
    "$base/api/me" | awk 'tolower($1)=="location:" {print $2}' | tr -d '\r')"
  case "$location" in
    */auth/login*return_to=*) ;;
    *) fail "api-me navigation: Location '$location' missing /auth/login?return_to=" ;;
  esac

  # Off-allowlist path: APISIX has no matching route, so it returns 404
  # before any plugin runs. This is the allowlist enforcement.
  expect_status "api-not-in-allowlist" "404" \
    "$base/api/not-in-allowlist"

  # POST /api/admin with no session: the no-session check fires first,
  # before any CSRF validation. Expect 401.
  expect_status "api-admin no-session POST" "401" \
    -X POST "$base/api/admin"
fi

echo "api-gateway checks passed"
