#!/usr/bin/env sh
set -eu

cd "$(dirname "$0")/.."

fail() {
  echo "contract-string verification failed: $1" >&2
  exit 1
}

require_absent() {
  pattern="$1"
  path="$2"
  if rg -n --hidden --glob '!.git/**' --glob '!frontend/node_modules/**' \
      --glob '!frontend/dist/**' --glob '!backend-resource-server/target/**' \
      --glob '!auth-service/target/**' --glob '!tasks/done/**' \
      --glob '!docs/sessions/**' \
      "$pattern" "$path" >/tmp/oidc-reference-security-rg.out 2>/dev/null; then
    cat /tmp/oidc-reference-security-rg.out >&2
    fail "forbidden pattern found: $pattern"
  fi
}

require_present() {
  pattern="$1"
  path="$2"
  if ! rg -n "$pattern" "$path" >/dev/null; then
    fail "required contract string missing: $pattern in $path"
  fi
}

require_present "saved_request" README.md docs tasks
require_present "tx:\\{state\\}" README.md docs tasks
require_present "sess:\\{sid\\}" README.md docs tasks
require_present "custom Redis-compatible .*session|custom .*state-store session|state-store session repository|Redis-compatible .*sess" docs tasks AGENTS.md
require_present "Client Credentials.*no BFF|no BFF in path|Client Credentials.*internal RPC|Client Credentials.*RPC|internal RPC.*Client Credentials" README.md docs tasks
require_present "returns.*401|401.*without session|without session.*401" docs tasks

# Frame B architecture strings. Auth Service + API Gateway are the split
# replacement for the combined BFF; signed double-submit replaces naive
# CSRF; SameSite=Lax replaces SameSite=Strict on the session cookie.
require_present "SameSite=Lax" README.md docs
require_present "__Host-sid" README.md docs
require_present "signed" README.md docs
require_present "XSRF-TOKEN|X-XSRF-TOKEN" README.md docs
require_present "oidc-reference-api-gateway" README.md docs
require_present "auth\\.internal" README.md docs
require_present "oidc-reference-auth-internal" README.md docs
require_present "oidc-reference-auth" README.md docs
require_present "/internal/refresh" README.md docs

# SameSite=Strict on the SESSION cookie was the prior contract. It must
# not appear in active docs. (The XSRF cookie is Strict; that's the
# different cookie name and not what this guard matches.) SUPERSEDED task
# packets under tasks/done/ retain it in "what-was-rejected" context.
require_absent "SameSite=Strict" README.md docs tasks/active tasks/backlog.md AGENTS.md RFC9700-compliance.md

old_spa_client='oidc-reference-''spa'
old_spa_env='VITE_''OIDC_'
require_absent "$old_spa_client" AGENTS.md README.md RFC9700-compliance.md docs tasks/active tasks/backlog.md
require_absent "$old_spa_env" AGENTS.md README.md RFC9700-compliance.md docs tasks/active tasks/backlog.md
require_absent "Spring Session Data Redis" AGENTS.md README.md RFC9700-compliance.md docs tasks/active tasks/backlog.md

# return_to migration: the browser-facing login-entry query parameter is
# `return_to`. The prior `?next=` form is forbidden in active docs/code.
# Historical references in tasks/done/ and session changelogs are excluded
# by require_absent's glob list above.
require_present "return_to" docs/specs/SPEC-0001-core-oidc-flows.md
require_present "return_to" README.md
require_present "return_to" docs/agents/return-to-login-contract.md
require_absent "\\?next=" AGENTS.md README.md RFC9700-compliance.md docs tasks/active tasks/backlog.md

# BFF <-> SPA wire-contract pins. A rename of any cookie name, header name,
# or path prefix below silently breaks the SPA; these assertions make that
# kind of drift fail the gate instead.

bff_auth_controller="bff/src/main/java/com/example/oidcreference/bff/AuthController.java"
bff_api_proxy="bff/src/main/java/com/example/oidcreference/bff/ApiProxyController.java"
bff_csrf_support="bff/src/main/java/com/example/oidcreference/bff/CsrfSupport.java"
spa_auth_client="frontend/src/auth.ts"
spa_app="frontend/src/App.tsx"

# Cookie names emitted by the BFF.
require_present 'ResponseCookie\.from\("sid"' "$bff_auth_controller"
require_present 'ResponseCookie\.from\("XSRF-TOKEN"' "$bff_auth_controller"
require_present 'ResponseCookie\.from\("oauth_tx"' "$bff_auth_controller"

# CSRF double-submit cookie + header on both ends.
require_present "XSRF-TOKEN" "$spa_auth_client"
require_present "X-XSRF-TOKEN" "$bff_csrf_support"
require_present "X-XSRF-TOKEN" "$spa_auth_client"

# /auth/* path prefix on both ends.
require_present '@RequestMapping\("/auth"\)' "$bff_auth_controller"
require_present "/auth/login" "$spa_app"
require_present "/auth/me" "$spa_auth_client"
require_present "/auth/logout" "$spa_auth_client"
require_present "/auth/callback" "$bff_auth_controller"

# /api/** proxy prefix on both ends. The SPA invokes /api/* paths in App.tsx
# (auth.ts exposes a generic callApi that takes the path as a parameter, so
# the literal lives in the caller, not the client).
require_present '@RequestMapping\("/api/\*\*"\)' "$bff_api_proxy"
require_present "/api/" "$spa_app"

echo "contract-string checks passed"
