#!/usr/bin/env sh
set -eu
SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
. "$SCRIPT_DIR/lib/common.sh"
ROOT="$(repo_root "$SCRIPT_DIR")"
cd "$ROOT"

# Bring up the full local reference stack for development:
#   - Browser ingress: APISIX (:9080)
#   - Authorization Server: Keycloak (:8080)
#   - Internal only: Auth Service, Resource Server, Valkey
# Afterwards run `just dev` for the SPA (Vite, :5173). `just down` tears down.
#
# The dev secrets below are the loud CHANGE_BEFORE_DEPLOY sentinels — safe only
# because every port binds loopback (see SECURITY.md + SecretSentinelValidator).

require_cmd docker "Install Docker Desktop or Colima."
require_cmd node   "Install Node 20+ (e.g. via nvm)."
require_cmd curl

warn_low_disk 3

DEV_CSRF_KEY='AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='
DEV_GATEWAY_SECRET='LOCAL_DEV_GATEWAY_CLIENT_SECRET__CHANGE_BEFORE_DEPLOY'
APISIX_IDP_TOKEN_URL="${APISIX_IDP_TOKEN_URL:-http://keycloak:8080/realms/oidc-reference/protocol/openid-connect/token}"

info "rendering APISIX route config"
GATEWAY_CLIENT_SECRET="$DEV_GATEWAY_SECRET" CSRF_SIGNING_KEY="$DEV_CSRF_KEY" \
  APISIX_IDP_TOKEN_URL="$APISIX_IDP_TOKEN_URL" \
  sh "$SCRIPT_DIR/render-apisix-config.sh"

info "starting compose stack"
CSRF_SIGNING_KEY="$DEV_CSRF_KEY" docker compose up -d --build \
  keycloak valkey auth-service resource-server apisix

info "waiting for Keycloak + APISIX"
wait_http       "Keycloak" "http://localhost:8080/realms/oidc-reference/.well-known/openid-configuration" 60
wait_responding "APISIX"   "http://127.0.0.1:9080/api/me" 120

success "stack is up"
cat <<EOF
  Gateway (browser ingress) : http://127.0.0.1:9080
  Keycloak                  : http://localhost:8080  (admin/admin)
  Auth Service              : internal service auth-service:8081
  Resource Server           : internal service resource-server:8082
  Valkey                    : internal service valkey:6379

  Next: 'just dev'  (or: cd frontend && npm run dev)  ->  http://127.0.0.1:5173
  Stop: 'just down'
EOF
