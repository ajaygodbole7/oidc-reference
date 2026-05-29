#!/usr/bin/env sh
set -eu

# Full-stack auth verification for the Frame B split shape.
#
# Brings the full Compose topology up (keycloak, valkey, resource-server,
# auth-service, apisix), waits for every service to
# report healthy, and exercises the browser-facing ingress at
# http://127.0.0.1:9080.
#
# Inner-loop dev (./mvnw spring-boot:run) is NOT the path this script
# takes any more — that's covered by the per-module verify-*.sh scripts.
# This script asserts the integrated topology behaves like the spec says.
#
# Env knobs:
#   RESET_KEYCLOAK_REALM=1   docker compose down -v before up, so the
#                            realm JSON re-imports cleanly.
#   FULL_STACK_LOG_DIR=...   override the log dir for compose logs.

root_dir="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
log_dir="${FULL_STACK_LOG_DIR:-$root_dir/.local/full-stack-logs}"
issuer="${OIDC_ISSUER_URI:-http://localhost:8080/realms/oidc-reference}"
compose_up_started=0

mkdir -p "$log_dir"

fail() {
  echo "full-stack auth verification failed: $1" >&2
  if [ "$compose_up_started" = "1" ]; then
    docker compose -f "$root_dir/compose.yaml" logs --no-color \
      >"$log_dir/compose.log" 2>&1 || true
    echo "compose logs: $log_dir/compose.log" >&2
  fi
  echo "log dir: $log_dir" >&2
  exit 1
}

cleanup() {
  if [ "$compose_up_started" = "1" ]; then
    docker compose -f "$root_dir/compose.yaml" down --remove-orphans \
      >>"$log_dir/compose-cleanup.log" 2>&1 || true
  fi
}
trap cleanup EXIT INT TERM

# Wait for every Compose service to report `healthy`. Polls
# `docker compose ps` per service rather than relying on
# `docker compose ps --format json`, which is missing on older docker
# CLIs. Times out after 180s.
wait_for_compose_healthy() {
  deadline=$(( $(date +%s) + 180 ))
  services="keycloak valkey resource-server auth-service apisix"
  while :; do
    all_healthy=1
    for svc in $services; do
      status="$(docker compose -f "$root_dir/compose.yaml" ps \
        --format '{{.Health}}' "$svc" 2>/dev/null | head -n1)"
      # `--format` is supported on modern docker compose v2; for older
      # versions, fall back to the human-readable column.
      if [ -z "$status" ]; then
        status="$(docker compose -f "$root_dir/compose.yaml" ps "$svc" \
          2>/dev/null | awk 'NR>1 {print $0}' | grep -oE '\(healthy\)|\(unhealthy\)|\(starting\)' \
          | head -n1 | tr -d '()')"
      fi
      case "$status" in
        healthy) ;;
        *) all_healthy=0 ;;
      esac
    done
    if [ "$all_healthy" = "1" ]; then
      return 0
    fi
    if [ "$(date +%s)" -ge "$deadline" ]; then
      docker compose -f "$root_dir/compose.yaml" ps >&2 || true
      fail "compose services did not all become healthy within 180s"
    fi
    sleep 3
  done
}

wait_for_discovery() {
  for _ in $(seq 1 90); do
    if curl -fsS "$issuer/.well-known/openid-configuration" >/dev/null 2>&1; then
      return 0
    fi
    sleep 2
  done
  fail "Keycloak discovery did not become ready at $issuer"
}

# Assert an HTTP status code from a URL. Uses the no-body curl idiom so
# we don't dump response bodies into logs by default.
expect_status() {
  name="$1"
  url="$2"
  expected="$3"
  shift 3
  status="$(curl -o /dev/null -s -w '%{http_code}' "$@" "$url" || true)"
  if [ "$status" != "$expected" ]; then
    fail "$name: expected HTTP $expected at $url, got $status"
  fi
}

# Assert a 302 to a redirect Location matching a substring.
expect_redirect_contains() {
  name="$1"
  url="$2"
  needle="$3"
  shift 3
  headers="$(curl -o /dev/null -s -D - -w '%{http_code}\n' "$@" "$url" || true)"
  status="$(printf '%s' "$headers" | tail -n1)"
  location="$(printf '%s' "$headers" | awk 'tolower($1)=="location:" {print $2}' | tr -d '\r')"
  if [ "$status" != "302" ]; then
    fail "$name: expected 302 at $url, got $status"
  fi
  case "$location" in
    *"$needle"*) ;;
    *) fail "$name: Location header '$location' did not contain '$needle'" ;;
  esac
}

cd "$root_dir"

if [ "${RESET_KEYCLOAK_REALM:-0}" = "1" ]; then
  docker compose down -v >>"$log_dir/compose-reset.log" 2>&1 || true
fi

# Build images and start the full stack. `--build` ensures any local
# Dockerfile changes get picked up. Compose's depends_on:service_healthy
# wiring drives the start order.
docker compose up -d --build >"$log_dir/compose-up.log" 2>&1 || \
  fail "docker compose up failed (see $log_dir/compose-up.log)"
compose_up_started=1

wait_for_discovery
wait_for_compose_healthy

# Seed the service-account ROPC user / service client config used by the
# downstream smoke. Same call as the old script — Keycloak is still on
# host :8080 so this is unchanged.
OIDC_ISSUER="$issuer" \
  SERVICE_CLIENT_SECRET="${SERVICE_CLIENT_SECRET:-LOCAL_DEV_SERVICE_CLIENT_SECRET__CHANGE_BEFORE_DEPLOY}" \
  "$root_dir/authorization-server/tests/smoke.sh"

# Ingress probes. Everything goes through APISIX on :9080 — the old BFF
# host port (:8081) no longer exists.

# /auth/login is the OIDC kickoff. The Auth Service answers with a 302
# whose Location is the Keycloak authorize endpoint.
expect_redirect_contains "auth-login redirect" \
  "http://127.0.0.1:9080/auth/login" \
  "/realms/oidc-reference/protocol/openid-connect/auth"

# /api/me with no cookie is a 401 problem+json from the gateway plugin
# (no-session short-circuit, before any RS hit).
expect_status "api-me unauthenticated" \
  "http://127.0.0.1:9080/api/me" \
  "401"

# Cross-service Client-Credentials smoke now runs inside the Compose
# network (RS is no longer host-exposed). verify-cross-service.sh
# handles the `docker compose exec apisix` plumbing.
RUN_LIVE_CROSS_SERVICE=1 \
  OIDC_TOKEN_URL="$issuer/protocol/openid-connect/token" \
  OIDC_SERVICE_CLIENT_ID="oidc-reference-service" \
  OIDC_SERVICE_CLIENT_SECRET="${SERVICE_CLIENT_SECRET:-LOCAL_DEV_SERVICE_CLIENT_SECRET__CHANGE_BEFORE_DEPLOY}" \
  RS_JOBS_URL="http://resource-server:8082/api/jobs" \
  "$root_dir/scripts/verify-cross-service.sh"

# Playwright e2e drives the SPA through Vite's dev proxy (5173 →
# 127.0.0.1:9080 for /auth and /api). No SPA-config change needed; the
# stack-up just has to be live first, which we've ensured above.
(
  cd "$root_dir/frontend"
  E2E_FULL_STACK=1 npm run test:e2e
)

echo "full-stack auth verification passed"
