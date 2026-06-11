#!/usr/bin/env sh
set -eu

cd "$(dirname "$0")/.."

fail() {
  echo "contract-string verification failed: $1" >&2
  exit 1
}

require_absent() {
  pattern="$1"
  shift
  if rg -n --hidden --glob '!.git/**' --glob '!frontend/node_modules/**' \
      --glob '!frontend/dist/**' --glob '!backend-resource-server/target/**' \
      --glob '!auth-service/target/**' --glob '!tasks/done/**' \
      --glob '!docs/sessions/**' \
      "$pattern" "$@" >/tmp/oidc-reference-security-rg.out 2>/dev/null; then
    cat /tmp/oidc-reference-security-rg.out >&2
    fail "forbidden pattern found: $pattern"
  fi
}

require_present() {
  pattern="$1"
  shift
  if ! rg -n "$pattern" "$@" >/dev/null; then
    fail "required contract string missing: $pattern in $*"
  fi
}

require_present "saved_request" README.md docs
require_present "tx:\\{state\\}" README.md docs
require_present "sess:\\{sid\\}" README.md docs
require_present "custom Redis-compatible .*session|custom .*state-store session|state-store session repository|Redis-compatible .*sess" docs AGENTS.md
require_present "Client Credentials.*no BFF|no BFF in path|Client Credentials.*internal RPC|Client Credentials.*RPC|internal RPC.*Client Credentials" README.md docs
require_present "returns.*401|401.*without session|without session.*401" docs

# Architecture pins: split-BFF cookie + scope + audience strings.
require_present "SameSite=Lax" README.md docs
require_present "__Host-sid" README.md docs
require_present "XSRF-TOKEN|X-XSRF-TOKEN" README.md docs
require_present "oidc-reference-api-gateway" README.md docs
require_present "auth\\.internal" README.md docs
require_present "oidc-reference-auth-internal" README.md docs
require_present "oidc-reference-auth" README.md docs
require_present "/internal/resolve" README.md docs

# Deprecated identifiers — must stay out of active docs.
old_spa_client='oidc-reference-''spa'
old_spa_env='VITE_''OIDC_'
require_absent "$old_spa_client" AGENTS.md README.md RFC9700-compliance.md docs
require_absent "$old_spa_env" AGENTS.md README.md RFC9700-compliance.md docs
require_absent "Spring Session Data Redis" AGENTS.md README.md RFC9700-compliance.md docs

# return_to is the current login-entry query parameter; the prior `?next=`
# form is forbidden in active docs/code.
require_present "return_to" docs/specs/SPEC-0001-core-oidc-flows.md
require_present "return_to" README.md
require_absent "\\?next=" AGENTS.md README.md RFC9700-compliance.md docs

# Auth Service ↔ SPA wire-contract pins. A rename of any cookie name,
# header name, or path prefix below silently breaks the SPA; these
# assertions make that drift fail the gate instead.

auth_controller="auth-service/src/main/java/com/example/oidcreference/authservice/AuthController.java"
csrf_support="auth-service/src/main/java/com/example/oidcreference/authservice/SignedCsrfSupport.java"
gateway_plugin="api-gateway/plugins/bff-session.lua"
spa_auth_client="frontend/src/auth.ts"
spa_app="frontend/src/App.tsx"

# Cookie names emitted by the Auth Service.
require_present 'sessionCookieName' "$auth_controller"
require_present '"XSRF-TOKEN"' "$auth_controller"
require_present 'OAuthTxBinding.cookieName\(state\)' "$auth_controller"
require_present 'COOKIE_PREFIX = "oauth_tx_"' auth-service/src/main/java/com/example/oidcreference/authservice/OAuthTxBinding.java

# Signed CSRF cookie + header on both ends.
require_present "XSRF-TOKEN" "$spa_auth_client"
require_present "X-XSRF-TOKEN" "$csrf_support"
require_present "X-XSRF-TOKEN" "$spa_auth_client"

# /auth/* path prefix on both ends.
require_present '@RequestMapping\("/auth"\)' "$auth_controller"
require_present "/auth/login" "$spa_auth_client"
require_present "/auth/me" "$spa_auth_client"
require_present "/auth/logout" "$spa_auth_client"
require_present "/auth/callback" "$auth_controller"

# /api/** allowlist is owned by the API Gateway (APISIX route table), not
# a Java controller. The Lua plugin is attached per-route in apisix.yaml.
require_present "bff-session" api-gateway/apisix.yaml.template
require_present "/api/" "$spa_app"

# /internal/resolve is the gateway → Auth Service back-channel.
require_present "/internal/resolve" "$gateway_plugin"

echo "contract-string checks passed"
