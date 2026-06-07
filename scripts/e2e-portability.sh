#!/usr/bin/env sh
set -eu
SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
. "$SCRIPT_DIR/lib/common.sh"
ROOT="$(repo_root "$SCRIPT_DIR")"
cd "$ROOT"

# Hermetic IdP-portability proof. This uses the same Keycloak container but
# switches the running stack to a second realm whose token shape differs from
# the default reference realm:
#   - roles are emitted as top-level `groups`, not realm_access.roles
#   - API audience is oidc-reference-alt-api, not oidc-reference-api
#
# It is intentionally separate from e2e-auth.sh so routine dev does not pay
# for two full browser runs, while the portability proof remains re-runnable
# without third-party IdP credentials.

require_cmd docker "Install Docker Desktop or Colima."
require_cmd node   "Install Node 20+ (e.g. via nvm)."

DEV_CSRF_KEY='AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='
DEV_GATEWAY_SECRET='LOCAL_DEV_GATEWAY_CLIENT_SECRET__CHANGE_BEFORE_DEPLOY'
ALT_REALM='oidc-reference-alt'
ALT_ISSUER="http://localhost:8080/realms/$ALT_REALM"
ALT_TOKEN_URL="http://keycloak:8080/realms/$ALT_REALM/protocol/openid-connect/token"

LOCK="$ROOT/.local/e2e-portability.lock"
mkdir -p "$ROOT/.local"
if ! mkdir "$LOCK" 2>/dev/null; then
  die "another portability E2E run is active (lock: $LOCK) — wait for it or remove the lock"
fi

compose_portability() {
  docker compose -f compose.yaml -f compose.portability.yml "$@"
}

cleanup() {
  _status=$?
  trap - EXIT INT TERM
  if [ "$_status" -ne 0 ]; then
    warn "portability E2E failed; recent APISIX plugin diagnostics follow"
    compose_portability logs --no-color --tail=220 apisix 2>/dev/null \
      | grep 'bff-session.lua' || true
  fi
  compose_portability down --remove-orphans >/dev/null 2>&1 || true
  rmdir "$LOCK" 2>/dev/null || rm -rf "$LOCK" 2>/dev/null || true
  exit "$_status"
}
trap cleanup EXIT INT TERM

info "tearing down any existing stack for a clean slate"
compose_portability down --remove-orphans >/dev/null 2>&1 || true

info "rendering APISIX route config for $ALT_REALM"
GATEWAY_CLIENT_SECRET="$DEV_GATEWAY_SECRET" \
  CSRF_SIGNING_KEY="$DEV_CSRF_KEY" \
  APISIX_IDP_TOKEN_URL="$ALT_TOKEN_URL" \
  sh "$SCRIPT_DIR/render-apisix-config.sh"

info "starting compose stack with alt-claim realm config"
export CSRF_SIGNING_KEY="$DEV_CSRF_KEY"
export RESOURCE_SERVER_SPRING_PROFILES_ACTIVE=gateway-test
compose_portability up -d --build keycloak valkey auth-service resource-server apisix

info "waiting for alt realm + APISIX"
wait_http       "Keycloak alt realm" "$ALT_ISSUER/.well-known/openid-configuration" 60
wait_responding "APISIX"             "http://127.0.0.1:9080/api/me" 120

info "IdP smoke for alt-claim realm"
OIDC_ISSUER="$ALT_ISSUER" \
  REALM_FILE="$ROOT/authorization-server/realm/oidc-reference-alt-realm.json" \
  EXPECTED_REALM="$ALT_REALM" \
  EXPECTED_API_AUDIENCE=oidc-reference-alt-api \
  EXPECTED_ROLES_CLAIM=groups \
  sh "$ROOT/authorization-server/tests/smoke.sh"

info "authenticated browser E2E against alt-claim realm"
(
  cd "$ROOT/frontend"
  E2E_FULL_STACK=1 \
    E2E_REALM_NAME="$ALT_REALM" \
    VITE_AUTH_TARGET=http://127.0.0.1:9080 \
    VITE_API_TARGET=http://127.0.0.1:9080 \
    npx playwright test tests/e2e/reference-flow.spec.ts --workers=1
)

info "gateway refresh-delegation proof against alt-claim realm"
RUN_LIVE_GATEWAY_TESTS=1 \
  RUN_REFRESH_TESTS=1 \
  CSRF_SIGNING_KEY="$DEV_CSRF_KEY" \
  OIDC_TOKEN_ENDPOINT="http://localhost:8080/realms/$ALT_REALM/protocol/openid-connect/token" \
  E2E_REALM_NAME="$ALT_REALM" \
  sh "$ROOT/api-gateway/tests/test-gateway-behavior.sh"

success "hermetic IdP-portability E2E passed"
