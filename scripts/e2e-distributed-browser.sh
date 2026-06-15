#!/usr/bin/env sh
set -eu
SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
. "$SCRIPT_DIR/lib/common.sh"
ROOT="$(repo_root "$SCRIPT_DIR")"
cd "$ROOT"

# Distributed cross-replica BROWSER gate (on-demand; NOT in verify-all/e2e-auth).
#
# Belt-and-suspenders proof of the FULL real path across TWO auth-service
# replicas, under a DETERMINISTIC split:
#
#   browser cookie -> Vite (:5173) -> APISIX (:9080) ->
#     /auth/*          -> auth-service   (replica-1): writes tx:{state}+sess:{sid}
#     /api/** resolve  -> auth-service-2 (replica-2): reads sess:{sid} CROSS-REPLICA
#
# The split is config: the bff-session plugin's auth_service_base is the gateway's
# DIRECT /internal/resolve target (it bypasses the APISIX upstream), so pointing
# it at replica-2 forces every /api resolve to cross replicas, while /auth/* keeps
# using the `auth-service` upstream (replica-1). Then frontend/tests/e2e/
# distributed-cross-replica.spec.ts runs N parallel users and asserts each sees
# only its own identity — so a 200 from /api/user-data proves replica-2 resolved a
# replica-1 session off shared Valkey, with no cross-talk under concurrency.
#
# Kept separate from e2e-auth because two replicas + an extra image build trips
# the documented APISIX cold-start flakiness; this is a before-merge / on-demand
# gate, not part of every routine run. The same-session refresh-collapse
# contention case stays in the scripted gate (scripts/e2e-distributed-lock.sh).

require_cmd docker "Install Docker Desktop or Colima."
require_cmd node   "Install Node 20+ (e.g. via nvm)."
require_cmd curl

warn_low_disk 4

DEV_CSRF_KEY='AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='
DEV_GATEWAY_SECRET='LOCAL_DEV_GATEWAY_CLIENT_SECRET__CHANGE_BEFORE_DEPLOY'
APISIX_IDP_TOKEN_URL="${APISIX_IDP_TOKEN_URL:-http://keycloak:8080/realms/oidc-reference/protocol/openid-connect/token}"
RENDERED="$ROOT/api-gateway/apisix.yaml.local"
# The two-replica overlay already defines auth-service-2 in distributed-lock mode;
# reuse it (both replicas get app.refresh-lock=distributed).
COMPOSE_FILES="-f compose.yaml -f compose.distributed-lock.yml"

# Single-run lock: the stack binds fixed host ports, so two runs collide.
LOCK="$ROOT/.local/e2e-distributed-browser.lock"
mkdir -p "$ROOT/.local"
if ! mkdir "$LOCK" 2>/dev/null; then
  die "another distributed-browser run is active (lock: $LOCK) — wait or remove it"
fi

VITE_PID=""
cleanup() {
  _status=$?
  trap - EXIT INT TERM
  if [ -n "$VITE_PID" ]; then kill "$VITE_PID" 2>/dev/null || true; fi
  lsof -nP -iTCP:5173 -sTCP:LISTEN -t 2>/dev/null | xargs -r kill 2>/dev/null || true
  if [ "$_status" -ne 0 ]; then
    warn "distributed-browser gate failed; diagnostics (apisix, both replicas) follow"
    # shellcheck disable=SC2086
    docker compose $COMPOSE_FILES logs --no-color --tail=100 apisix 2>/dev/null \
      | grep 'bff-session.lua' || true
    # shellcheck disable=SC2086
    docker compose $COMPOSE_FILES logs --no-color --tail=80 auth-service 2>/dev/null || true
    # shellcheck disable=SC2086
    docker compose $COMPOSE_FILES logs --no-color --tail=80 auth-service-2 2>/dev/null || true
  fi
  # shellcheck disable=SC2086
  docker compose $COMPOSE_FILES down -v --remove-orphans >/dev/null 2>&1 || true
  rmdir "$LOCK" 2>/dev/null || rm -rf "$LOCK" 2>/dev/null || true
  exit "$_status"
}
trap cleanup EXIT INT TERM

info "tearing down any existing stack for a clean slate"
# shellcheck disable=SC2086
docker compose $COMPOSE_FILES down -v --remove-orphans >/dev/null 2>&1 || true

info "rendering APISIX route config"
GATEWAY_CLIENT_SECRET="$DEV_GATEWAY_SECRET" CSRF_SIGNING_KEY="$DEV_CSRF_KEY" \
  APISIX_IDP_TOKEN_URL="$APISIX_IDP_TOKEN_URL" \
  sh "$SCRIPT_DIR/render-apisix-config.sh"

# Pin the gateway's /internal/resolve target to replica-2. -i.bak is portable
# across BSD (macOS) and GNU sed. apisix.yaml.local is gitignored and re-rendered
# by the next up.sh, so this edit is ephemeral to this run.
info "pinning the gateway resolve to replica-2 (auth-service-2); /auth/* stays on replica-1"
sed -i.bak 's#auth_service_base: http://auth-service:8081#auth_service_base: http://auth-service-2:8081#' "$RENDERED"
rm -f "$RENDERED.bak"
if ! grep -q 'auth_service_base: http://auth-service-2:8081' "$RENDERED"; then
  die "could not pin auth_service_base to replica-2 in $RENDERED (template drift?)"
fi
if grep -q 'auth_service_base: http://auth-service:8081' "$RENDERED"; then
  die "a replica-1 auth_service_base remained in $RENDERED (unexpected extra occurrence)"
fi
info "split verified in $RENDERED: /auth/* -> auth-service (replica-1); /internal/resolve -> auth-service-2 (replica-2)"

info "starting two-replica full stack (keycloak, valkey, auth-service, auth-service-2, resource-server, apisix)"
# shellcheck disable=SC2086
CSRF_SIGNING_KEY="$DEV_CSRF_KEY" docker compose $COMPOSE_FILES up -d --build \
  keycloak valkey auth-service auth-service-2 resource-server apisix

info "waiting for Keycloak + APISIX + both auth replicas"
wait_http       "Keycloak" "http://localhost:8080/realms/oidc-reference/.well-known/openid-configuration" 60
wait_responding "APISIX"   "http://127.0.0.1:9080/api/me" 120
# Both replicas publish a loopback port (8091/8092) under the overlay; a 401 from
# /auth/me means the app is up. Best-effort (APISIX + a resolve already imply up).
for hp in 8091 8092; do
  wait_responding "auth replica :$hp" "http://127.0.0.1:$hp/auth/me" 60 || true
done

info "starting persistent Vite dev server (SPA origin :5173)"
lsof -nP -iTCP:5173 -sTCP:LISTEN -t 2>/dev/null | xargs -r kill 2>/dev/null || true
(
  cd "$ROOT/frontend"
  VITE_AUTH_TARGET=http://127.0.0.1:9080 VITE_API_TARGET=http://127.0.0.1:9080 \
    npm run dev >"$ROOT/.local/e2e-distributed-browser-vite.log" 2>&1
) &
VITE_PID=$!
wait_responding "Vite SPA origin" "http://127.0.0.1:5173/" 60

info "running parallel-user cross-replica browser spec (Playwright)"
(
  cd "$ROOT/frontend"
  E2E_FULL_STACK=1 \
    VITE_AUTH_TARGET=http://127.0.0.1:9080 \
    VITE_API_TARGET=http://127.0.0.1:9080 \
    npx playwright test tests/e2e/distributed-cross-replica.spec.ts --workers=1
)

success "distributed cross-replica browser gate passed — N parallel replica-1 sessions resolved cross-replica on replica-2, no identity cross-talk"
