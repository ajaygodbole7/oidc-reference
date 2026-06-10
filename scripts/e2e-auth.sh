#!/usr/bin/env sh
set -eu
SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
. "$SCRIPT_DIR/lib/common.sh"
ROOT="$(repo_root "$SCRIPT_DIR")"
cd "$ROOT"

# Authenticated full-stack E2E gate — the run that actually exercises login →
# callback → /auth/me (roles) → API call → logout, and asserts NO token reaches
# the browser. This is the gate that catches the class of bug a mock-heavy unit
# suite misses (e.g. realm-claim-vs-code mismatches, id_token leaking to JS).
#
# It brings the WHOLE stack up from a clean slate (so a changed realm re-imports),
# runs the Playwright authenticated suite against real Keycloak, then tears down.
# Unlike verify-frontend.sh's Playwright run, the authenticated tests are NOT
# skipped here — E2E_FULL_STACK=1 is set.
require_cmd docker "Install Docker Desktop or Colima."
require_cmd node   "Install Node 20+ (e.g. via nvm)."

DEV_CSRF_KEY='AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='

# Local single-run lock. The whole stack binds fixed host ports (9080, Keycloak,
# Valkey, …), so two concurrent authenticated runs would collide. mkdir of a lock
# DIR is the atomic primitive: it fails if the dir already exists (POSIX-atomic),
# so there is no check-then-create race. .local/ is gitignored.
LOCK="$ROOT/.local/e2e-auth.lock"
mkdir -p "$ROOT/.local"
if ! mkdir "$LOCK" 2>/dev/null; then
  die "another authenticated E2E run is active (lock: $LOCK) — wait for it or remove the lock"
fi

# Teardown is deterministic: tear the stack down AND release the lock on any exit
# (success, failure, or signal). Order: Vite first, then stack, then lock, so
# the port-owning run is fully gone before the lock frees.
VITE_PID=""
cleanup() {
  _status=$?
  trap - EXIT INT TERM
  if [ -n "$VITE_PID" ]; then
    kill "$VITE_PID" 2>/dev/null || true
  fi
  # npm run dev spawns vite as a child; reclaim the port directly so no stray
  # dev server survives this run (the next run's start-time kill is a backstop).
  lsof -nP -iTCP:5173 -sTCP:LISTEN -t 2>/dev/null | xargs -r kill 2>/dev/null || true
  if [ "$_status" -ne 0 ]; then
    # On failure, dump the diagnostics that actually localize a live e2e break:
    # the gateway plugin (CSRF/TTL/refresh), the Auth Service (login/logout/
    # back-channel/validator reasons), and Keycloak (issuer/back-channel-delivery
    # errors such as the UnknownHostException that masqueraded as a validator bug).
    warn "authenticated E2E failed; service diagnostics follow (apisix, auth-service, keycloak)"
    docker compose logs --no-color --tail=220 apisix 2>/dev/null \
      | grep 'bff-session.lua' || true
    docker compose logs --no-color --tail=150 auth-service 2>/dev/null || true
    docker compose logs --no-color --tail=120 keycloak 2>/dev/null \
      | grep -iE 'error|warn|backchannel|logout|UnknownHost' || true
  fi
  sh "$SCRIPT_DIR/down.sh" >/dev/null 2>&1 || true
  rmdir "$LOCK" 2>/dev/null || rm -rf "$LOCK" 2>/dev/null || true
  exit "$_status"
}
trap cleanup EXIT INT TERM

# Clean slate first so a changed Keycloak realm is re-imported (the container is
# removed on down, and KC_DB=dev-file rebuilds from the mounted realm on up).
info "tearing down any existing stack for a clean slate"
sh "$SCRIPT_DIR/down.sh" >/dev/null 2>&1 || true

RESOURCE_SERVER_SPRING_PROFILES_ACTIVE=gateway-test sh "$SCRIPT_DIR/up.sh"

# The Auth Service pins the OAuth redirect_uri to the SPA origin
# (APP_BASE_URL=http://127.0.0.1:5173, the Vite dev server), so login + callback
# traverse :5173. The browser suite AND the gateway refresh tests (which mint a
# real session via mint-real-session.mjs) therefore both need :5173 up — so we
# start ONE persistent Vite here, reused by Playwright (reuseExistingServer) and
# alive for the gateway phase, and kill it in cleanup. (Running the gateway
# phase after Playwright's own webServer had already exited is what previously
# left mint without a :5173 origin.)
info "starting persistent Vite dev server (SPA origin :5173) for both phases"
# Reclaim :5173 from any stale dev server so we never reuse a wrongly-configured one.
lsof -nP -iTCP:5173 -sTCP:LISTEN -t 2>/dev/null | xargs -r kill 2>/dev/null || true
(
  cd "$ROOT/frontend"
  VITE_AUTH_TARGET=http://127.0.0.1:9080 VITE_API_TARGET=http://127.0.0.1:9080 \
    npm run dev >"$ROOT/.local/e2e-vite.log" 2>&1
) &
VITE_PID=$!
wait_responding "Vite SPA origin" "http://127.0.0.1:5173/" 60

info "running authenticated browser E2E (Playwright, full stack)"
# Run ONLY the dedicated reference suite (login → callback → /auth/me → API →
# logout, and the no-token-in-browser assertion). --workers=1 keeps it serial:
# the suite drives one shared real stack, not parallel isolated workers.
# Playwright reuses the persistent Vite above (reuseExistingServer / when
# E2E_FULL_STACK=1) rather than starting/stopping its own.
(
  cd "$ROOT/frontend"
  E2E_FULL_STACK=1 \
    VITE_AUTH_TARGET=http://127.0.0.1:9080 \
    VITE_API_TARGET=http://127.0.0.1:9080 \
    npx playwright test tests/e2e/reference-flow.spec.ts --workers=1
)

info "running gateway refresh-delegation proof (real login session via :5173)"
RUN_LIVE_GATEWAY_TESTS=1 RUN_REFRESH_TESTS=1 CSRF_SIGNING_KEY="$DEV_CSRF_KEY" \
  E2E_APP_ORIGIN=http://127.0.0.1:5173 \
  sh "$ROOT/api-gateway/tests/test-gateway-behavior.sh"

success "authenticated full-stack E2E passed"
