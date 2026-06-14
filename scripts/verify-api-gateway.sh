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

# Phantom-token invariant: the gateway holds NO session store handle. It resolves
# the opaque sid via the Auth Service (POST /internal/resolve) and must NOT speak
# Redis/Valkey directly. This guards against a regression that reintroduces a
# store client or the gateway-side idle window — see
# docs/architecture/phantom-token-session-resolution.md.
if grep -E -q 'require.*resty\.redis|valkey_host|valkey_port|valkey_password|idle_ttl_seconds' "$plugin_lua"; then
  fail "$plugin_lua speaks to a session store (resty.redis/valkey_*) — the gateway must resolve via /internal/resolve, not read the store"
fi
grep -F -q "/internal/resolve" "$plugin_lua" \
  || fail "$plugin_lua missing the /internal/resolve back-channel call"
if grep -E -q 'valkey_host|valkey_port|valkey_password|idle_ttl_seconds' "$apisix_yaml"; then
  fail "$apisix_yaml still wires Valkey into the bff-session plugin — remove valkey_*/idle_ttl_seconds"
fi

# ---- Sentinel guard (render-apisix-config.sh fails closed on dev secrets) ----
# REQUIRE_NONDEV_SECRETS=1 must REFUSE a dev-sentinel GATEWAY_CLIENT_SECRET /
# CSRF_SIGNING_KEY — the gateway's render-time analogue of the Auth Service's
# SecretSentinelValidator (APISIX check_schema cannot fail a route load, so the
# Lua guard only WARNs). The refuse path exits before envsubst, so this gate
# needs no envsubst: we assert rc==3 for sentinels and rc!=3 for real secrets.
render_local="api-gateway/apisix.yaml.local"
guard_backup=
[ -f "$render_local" ] && { guard_backup="$(mktemp)"; cp "$render_local" "$guard_backup"; }

assert_render_rc() { # label  eq|ne  expected_rc  ENV=VAL...
  arc_label="$1"; arc_cmp="$2"; arc_rc="$3"; shift 3
  arc_got=0
  env "$@" sh scripts/render-apisix-config.sh >/dev/null 2>&1 || arc_got=$?
  case "$arc_cmp" in
    eq) [ "$arc_got" -eq "$arc_rc" ] || fail "sentinel-guard $arc_label: want rc=$arc_rc got $arc_got" ;;
    ne) [ "$arc_got" -ne "$arc_rc" ] || fail "sentinel-guard $arc_label: want rc!=$arc_rc got $arc_got" ;;
  esac
}

DEV_GW='LOCAL_DEV_GATEWAY_CLIENT_SECRET__CHANGE_BEFORE_DEPLOY'
DEV_CSRF='AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='
REAL_GW='render-test-nondev-gateway-placeholder'
# Valid base64, 32 bytes (256-bit), and NOT the all-A dev sentinel.
REAL_CSRF='BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB='

assert_render_rc "refuses dev gateway secret" eq 3 \
  REQUIRE_NONDEV_SECRETS=1 GATEWAY_CLIENT_SECRET="$DEV_GW" CSRF_SIGNING_KEY="$REAL_CSRF"
assert_render_rc "refuses dev csrf key" eq 3 \
  REQUIRE_NONDEV_SECRETS=1 GATEWAY_CLIENT_SECRET="$REAL_GW" CSRF_SIGNING_KEY="$DEV_CSRF"
assert_render_rc "allows real secrets under prod flag" ne 3 \
  REQUIRE_NONDEV_SECRETS=1 GATEWAY_CLIENT_SECRET="$REAL_GW" CSRF_SIGNING_KEY="$REAL_CSRF"
assert_render_rc "dev path unaffected (no prod flag)" ne 3 \
  GATEWAY_CLIENT_SECRET="$DEV_GW" CSRF_SIGNING_KEY="$DEV_CSRF"

# ---- CSRF key shape (render-time analogue of the Auth Service boot check) ----
# CSRF_SIGNING_KEY is HMAC material for the signed double-submit token (the
# gateway verifies it in Lua with the same key). It must be base64-decodable and
# >= 32 bytes (256-bit) or the HMAC is silently weak/wrong. Validated on EVERY
# render — the dev sentinel is valid 32-byte base64, so the dev path is unchanged.
assert_render_rc "refuses non-base64 csrf key" eq 3 \
  GATEWAY_CLIENT_SECRET="$DEV_GW" CSRF_SIGNING_KEY='not_valid_base64_!!!'
assert_render_rc "refuses short (<256-bit) csrf key" eq 3 \
  GATEWAY_CLIENT_SECRET="$DEV_GW" CSRF_SIGNING_KEY='c2hvcnQ='

# ---- Test-only route is excluded from a production-intent render ----
# /api/_test/echo is a test-harness surface (the RS endpoint is gateway-test
# profile only, 404 in prod). A production render (REQUIRE_NONDEV_SECRETS=1)
# must omit the route entirely; the default dev/test render keeps it for the
# gateway behaviour suite.
# Match the route definition (id: api-test-echo), not the header doc comment
# that also mentions /api/_test/echo.
env REQUIRE_NONDEV_SECRETS=1 GATEWAY_CLIENT_SECRET="$REAL_GW" CSRF_SIGNING_KEY="$REAL_CSRF" \
  sh scripts/render-apisix-config.sh >/dev/null 2>&1 || fail "prod-intent render failed"
grep -q 'id: api-test-echo' "$render_local" && fail "prod render must omit the test echo route"
env GATEWAY_CLIENT_SECRET="$DEV_GW" CSRF_SIGNING_KEY="$DEV_CSRF" \
  sh scripts/render-apisix-config.sh >/dev/null 2>&1 || fail "dev render failed"
grep -q 'id: api-test-echo' "$render_local" || fail "dev render must include the test echo route"

if [ -n "$guard_backup" ]; then mv "$guard_backup" "$render_local"; else rm -f "$render_local"; fi
echo "sentinel-guard checks passed"

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
