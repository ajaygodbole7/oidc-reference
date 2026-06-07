#!/usr/bin/env sh
set -eu
SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
. "$SCRIPT_DIR/lib/common.sh"
ROOT="$(repo_root "$SCRIPT_DIR")"
cd "$ROOT"

# Live-infra E2E: brings up the compose stack with Keycloak, Valkey, APISIX,
# Auth Service, and Resource Server, runs the IdP smoke and gateway behaviour
# suite, then tears down. For the full browser login flow, use e2e-auth.sh.
require_cmd docker "Install Docker Desktop or Colima."
require_cmd node   "Install Node 20+ (e.g. via nvm)."

DEV_CSRF_KEY='AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='
DEV_GATEWAY_SECRET='LOCAL_DEV_GATEWAY_CLIENT_SECRET__CHANGE_BEFORE_DEPLOY'
APISIX_IDP_TOKEN_URL="${APISIX_IDP_TOKEN_URL:-http://keycloak:8080/realms/oidc-reference/protocol/openid-connect/token}"

cleanup() {
  docker compose down --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

info "rendering APISIX route config"
GATEWAY_CLIENT_SECRET="$DEV_GATEWAY_SECRET" CSRF_SIGNING_KEY="$DEV_CSRF_KEY" \
  APISIX_IDP_TOKEN_URL="$APISIX_IDP_TOKEN_URL" \
  sh "$SCRIPT_DIR/render-apisix-config.sh"

info "starting compose stack"
CSRF_SIGNING_KEY="$DEV_CSRF_KEY" RESOURCE_SERVER_SPRING_PROFILES_ACTIVE=gateway-test \
  docker compose up -d --build \
  keycloak valkey auth-service resource-server apisix

info "waiting for Keycloak + APISIX"
wait_http       "Keycloak" "http://localhost:8080/realms/oidc-reference/.well-known/openid-configuration" 60
wait_responding "APISIX"   "http://127.0.0.1:9080/api/me" 120

info "IdP smoke (realm + discovery + client-credentials token)"
OIDC_ISSUER="http://localhost:8080/realms/oidc-reference" \
  sh "$ROOT/authorization-server/tests/smoke.sh"

info "gateway behaviour suite (live APISIX + Valkey + bff-session plugin)"
RUN_LIVE_GATEWAY_TESTS=1 RUN_REFRESH_TESTS=1 CSRF_SIGNING_KEY="$DEV_CSRF_KEY" \
  sh "$ROOT/api-gateway/tests/test-gateway-behavior.sh"

success "live-infra E2E passed"
