#!/usr/bin/env sh
set -eu

cd "$(dirname "$0")/.."

fail() {
  echo "cross-service verification failed: $1" >&2
  exit 1
}

require_present() {
  pattern="$1"
  shift
  # Use grep -REn (portable POSIX-ish) instead of rg so the gate works on
  # machines without ripgrep installed.
  if ! grep -REn "$pattern" "$@" >/dev/null; then
    fail "missing cross-service contract: $pattern in $*"
  fi
}

# Static contract guard. Runtime versions of these checks live in the
# frontend, Auth Service, API Gateway, RS, and auth-server test suites as
# those slices are implemented.
require_present "saved-request E2E|saved-request replay|saved request" docs scripts tasks README.md
require_present "XHR 401|fetch 401|returns.*401|without session.*401" docs scripts tasks README.md
require_present "/api/jobs" README.md docs tasks
require_present "no BFF in path|Client Credentials.*internal RPC|Client Credentials.*RPC|internal RPC.*Client Credentials" README.md docs tasks

# Frame B split: the combined BFF is replaced by an Auth Service plus an
# APISIX-based API Gateway, with an internal /internal/refresh RPC between
# them authenticated via Client Credentials.
require_present "[Aa]uth [Ss]ervice" README.md docs
require_present "[Aa]pi [Gg]ateway|API Gateway|api-gateway" README.md docs
require_present "/internal/refresh" README.md docs
require_present "[Cc]lient [Cc]redentials" README.md docs

# Live cross-service smoke. With the new topology the Resource Server has
# no host port — only services on the oidc-internal Compose network can
# reach it. We therefore run the curl invocations from inside the
# `apisix` container (its Dockerfile installs curl). The token call to
# Keycloak still goes via host :8080 (Keycloak stays host-exposed).
if [ "${RUN_LIVE_CROSS_SERVICE:-0}" = "1" ]; then
  : "${OIDC_TOKEN_URL:?set OIDC_TOKEN_URL}"
  : "${OIDC_SERVICE_CLIENT_ID:?set OIDC_SERVICE_CLIENT_ID}"
  : "${OIDC_SERVICE_CLIENT_SECRET:?set OIDC_SERVICE_CLIENT_SECRET}"
  : "${RS_JOBS_URL:?set RS_JOBS_URL}"

  # Refuse to proceed if the stack isn't up. `docker compose ps -q apisix`
  # returns a container id only when apisix is created; empty means no
  # stack. Clear message + exit so a contributor knows to bring it up.
  if ! docker compose ps -q apisix >/dev/null 2>&1; then
    fail "docker compose not detected; bring the stack up with 'docker compose up -d' first"
  fi
  apisix_id="$(docker compose ps -q apisix 2>/dev/null || true)"
  if [ -z "$apisix_id" ]; then
    fail "apisix container not running; bring the stack up with 'docker compose up -d' first"
  fi

  token_response="$(curl -fsS \
    -d grant_type=client_credentials \
    -d client_id="$OIDC_SERVICE_CLIENT_ID" \
    -d client_secret="$OIDC_SERVICE_CLIENT_SECRET" \
    "$OIDC_TOKEN_URL")"

  access_token="$(TOKEN_RESPONSE="$token_response" node -e 'try { const body = JSON.parse(process.env.TOKEN_RESPONSE ?? ""); if (typeof body.access_token === "string") process.stdout.write(body.access_token); } catch {}')"
  [ -n "$access_token" ] || fail "token response did not include access_token"

  # Run the RS POST from inside the apisix container so it can resolve
  # `resource-server` via Compose DNS. Pass the bearer through env to
  # avoid leaking it into the container's argv.
  docker compose exec -T \
    -e ACCESS_TOKEN="$access_token" \
    -e RS_JOBS_URL="$RS_JOBS_URL" \
    apisix sh -c 'curl -fsS -X POST -H "Authorization: Bearer $ACCESS_TOKEN" "$RS_JOBS_URL" >/dev/null' \
    || fail "RS /api/jobs call via apisix container failed"
fi

echo "cross-service contract checks passed"
