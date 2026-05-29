#!/usr/bin/env sh
#
# Authorization-server smoke test.
#
# Environment flags:
#   OIDC_ISSUER              Issuer URL. Default http://localhost:8080/realms/oidc-reference.
#   SERVICE_CLIENT_SECRET    Secret for oidc-reference-service. Default dev placeholder.
#   API_GATEWAY_CLIENT_SECRET Secret for oidc-reference-api-gateway. Default dev placeholder.
#   SMOKE_SKIP_DISCOVERY=1   Skip live discovery/JWKS/token checks.
#   SMOKE_SKIP_TOKEN=1       Skip live token issuance checks only.
#   SMOKE_API_GATEWAY_CHECK=1 Enable optional Client Credentials live check for
#                             oidc-reference-api-gateway. Asserts the issued
#                             access token carries aud=oidc-reference-auth-internal.
#                             Off by default so a missing secret does not break
#                             the smoke in environments that haven't provisioned it.
#
set -eu

issuer="${OIDC_ISSUER:-http://localhost:8080/realms/oidc-reference}"
script_dir="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
project_dir="$(CDPATH= cd -- "$script_dir/.." && pwd)"
realm_file="$project_dir/realm/oidc-reference-realm.json"
service_secret="${SERVICE_CLIENT_SECRET:-LOCAL_DEV_SERVICE_CLIENT_SECRET__CHANGE_BEFORE_DEPLOY}"
api_gateway_secret="${API_GATEWAY_CLIENT_SECRET:-LOCAL_DEV_GATEWAY_CLIENT_SECRET__CHANGE_BEFORE_DEPLOY}"

fail() {
  echo "authorization-server smoke failed: $1" >&2
  exit 1
}

[ -f "$realm_file" ] || fail "missing $realm_file"

node - "$realm_file" <<'NODE'
const fs = require("fs");
const path = process.argv[2];
const realm = JSON.parse(fs.readFileSync(path, "utf8"));
const clients = new Map(realm.clients.map((c) => [c.clientId, c]));
const scopes = new Map((realm.clientScopes || []).map((s) => [s.name, s]));
const users = new Map((realm.users || []).map((u) => [u.username, u]));
const realmRoles = new Set(((realm.roles || {}).realm || []).map((r) => r.name));
const auth = clients.get("oidc-reference-auth");
const apiGateway = clients.get("oidc-reference-api-gateway");
const service = clients.get("oidc-reference-service");
const audScope = scopes.get("api.audience");
const authInternalScope = scopes.get("auth.internal");
const rolesScope = scopes.get("roles");

function assert(cond, msg) {
  if (!cond) { console.error(msg); process.exit(1); }
}

assert(realm.realm === "oidc-reference", "realm name mismatch");
assert(realm.revokeRefreshToken === true, "refresh token rotation must be enabled");
assert(realm.refreshTokenMaxReuse === 0, "refresh token reuse must be zero");

for (const role of ["user", "admin", "auditor"]) {
  assert(realmRoles.has(role), `missing realm role ${role}`);
}

const alice = users.get("alice");
const admin = users.get("admin");
assert(alice && alice.enabled === true, "missing enabled alice user");
assert(admin && admin.enabled === true, "missing enabled admin user");
assert((alice.realmRoles || []).includes("user"), "alice must have user role");
assert((admin.realmRoles || []).includes("user"), "admin must have user role");
assert((admin.realmRoles || []).includes("admin"), "admin must have admin role");

assert(auth, "missing Auth Service client (oidc-reference-auth)");
assert(auth.publicClient === false, "Auth Service client must be confidential");
assert(auth.standardFlowEnabled === true, "Auth Service standard flow must be enabled");
assert(auth.implicitFlowEnabled === false, "Auth Service implicit flow must be disabled");
assert(auth.directAccessGrantsEnabled === false, "Auth Service direct grants must be disabled");
assert(auth.serviceAccountsEnabled === false, "Auth Service service accounts must be disabled");
assert(auth.attributes["pkce.code.challenge.method"] === "S256", "Auth Service PKCE must require S256");
assert(auth.redirectUris.includes("http://127.0.0.1:5173/auth/callback/idp"),
       "Auth Service redirect URI must point to SPA origin (Vite proxies to Auth Service); registration name is the generic 'idp'");
assert(Array.isArray(auth.webOrigins) && auth.webOrigins.length === 0,
       "Auth Service webOrigins must be empty (browser never calls Keycloak from JS)");
for (const scope of ["openid", "profile", "email", "roles", "api.audience", "api.read"]) {
  assert(auth.defaultClientScopes.includes(scope), `Auth Service default scopes must include ${scope}`);
}
for (const scope of ["api.write", "admin.read"]) {
  assert((auth.optionalClientScopes || []).includes(scope), `Auth Service optional scopes must include ${scope}`);
}

assert(apiGateway, "missing API Gateway client (oidc-reference-api-gateway)");
assert(apiGateway.publicClient === false, "API Gateway client must be confidential");
assert(apiGateway.serviceAccountsEnabled === true, "API Gateway service accounts (Client Credentials) must be enabled");
assert(apiGateway.standardFlowEnabled === false, "API Gateway standard flow must be disabled");
assert(apiGateway.implicitFlowEnabled === false, "API Gateway implicit flow must be disabled");
assert(apiGateway.directAccessGrantsEnabled === false, "API Gateway direct access grants must be disabled");
assert((apiGateway.defaultClientScopes || []).includes("auth.internal"),
       "API Gateway default scopes must include auth.internal");

assert(authInternalScope, "missing auth.internal client scope");
const authInternalMapper = (authInternalScope.protocolMappers || []).find(
  (m) => m.protocolMapper === "oidc-audience-mapper"
);
assert(authInternalMapper, "auth.internal scope missing oidc-audience-mapper");
assert(authInternalMapper.config["included.custom.audience"] === "oidc-reference-auth-internal",
       "auth.internal audience mapper must add oidc-reference-auth-internal");
assert(authInternalMapper.config["access.token.claim"] === "true",
       "auth.internal audience mapper must add to access token");
assert(authInternalMapper.config["id.token.claim"] === "false",
       "auth.internal audience mapper must NOT add to id token");

assert(service, "missing service client");
assert(service.publicClient === false, "service client must be confidential");
assert(service.serviceAccountsEnabled === true, "service accounts must be enabled");
assert(service.implicitFlowEnabled === false, "service implicit flow must be disabled");
assert(service.standardFlowEnabled === false, "service standard flow must be disabled");
assert(service.directAccessGrantsEnabled === false, "service direct grants must be disabled");
assert(service.defaultClientScopes.includes("api.audience"),
       "service default scopes must include api.audience");
assert(service.defaultClientScopes.includes("service.jobs"),
       "service default scopes must include service.jobs");

assert(audScope, "missing api.audience client scope");
const audMapper = (audScope.protocolMappers || []).find(
  (m) => m.protocolMapper === "oidc-audience-mapper"
);
assert(audMapper, "api.audience scope missing oidc-audience-mapper");
assert(audMapper.config["included.custom.audience"] === "oidc-reference-api",
       "audience mapper must add oidc-reference-api");
assert(audMapper.config["access.token.claim"] === "true",
       "audience mapper must add to access token");

assert(rolesScope, "missing roles client scope");
const realmRoleMapper = (rolesScope.protocolMappers || []).find(
  (m) => m.protocolMapper === "oidc-usermodel-realm-role-mapper"
);
assert(realmRoleMapper, "roles scope missing oidc-usermodel-realm-role-mapper");
assert(realmRoleMapper.config["claim.name"] === "realm_access.roles",
       "realm role mapper must emit realm_access.roles");
assert(realmRoleMapper.config["access.token.claim"] === "true",
       "realm role mapper must add to access token");

console.log("realm static checks passed");
NODE

if [ "${SMOKE_SKIP_DISCOVERY:-}" = "1" ]; then
  exit 0
fi

discovery_json="$(mktemp)"
jwks_json="$(mktemp)"
token_json="$(mktemp)"
gateway_token_json="$(mktemp)"
trap 'rm -f "$discovery_json" "$jwks_json" "$token_json" "$gateway_token_json"' EXIT

# Wait for Keycloak. Realm import on cold start typically completes in
# 20-60s; without a wait, `verify-all.sh` races startup.
ready=""
for i in $(seq 1 60); do
  if curl -fsS "$issuer/.well-known/openid-configuration" >"$discovery_json" 2>/dev/null; then
    ready="1"
    break
  fi
  sleep 2
done
[ -n "$ready" ] || fail "discovery did not become ready at $issuer/.well-known/openid-configuration within 120s"

node - "$issuer" "$discovery_json" <<'NODE'
const fs = require("fs");
const issuer = process.argv[2];
const d = JSON.parse(fs.readFileSync(process.argv[3], "utf8"));
if (d.issuer !== issuer) { console.error(`issuer mismatch: ${d.issuer}`); process.exit(1); }
if (!d.jwks_uri) { console.error("missing jwks_uri"); process.exit(1); }
if (!d.token_endpoint) { console.error("missing token_endpoint"); process.exit(1); }
if (!d.end_session_endpoint) { console.error("missing end_session_endpoint"); process.exit(1); }
console.log("discovery checks passed");
NODE

jwks_uri="$(node -e 'const fs = require("fs"); const d = JSON.parse(fs.readFileSync(process.argv[1], "utf8")); process.stdout.write(d.jwks_uri);' "$discovery_json")"
curl -fsS "$jwks_uri" >"$jwks_json" || fail "JWKS endpoint not reachable at $jwks_uri"
node - "$jwks_json" <<'NODE'
const fs = require("fs");
const jwks = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));
if (!Array.isArray(jwks.keys) || jwks.keys.length === 0) {
  console.error("JWKS contains no keys");
  process.exit(1);
}
console.log("JWKS checks passed");
NODE

if [ "${SMOKE_SKIP_TOKEN:-}" = "1" ]; then
  exit 0
fi

if ! curl -fsS \
    -d "grant_type=client_credentials" \
    -d "client_id=oidc-reference-service" \
    --data-urlencode "client_secret=${service_secret}" \
    "$issuer/protocol/openid-connect/token" >"$token_json"; then
  fail "service client_credentials token issuance failed (check SERVICE_CLIENT_SECRET)"
fi

node - "$issuer" "$token_json" <<'NODE'
const fs = require("fs");
const issuer = process.argv[2];
const t = JSON.parse(fs.readFileSync(process.argv[3], "utf8"));
if (!t.access_token) { console.error("missing access_token"); process.exit(1); }
const parts = t.access_token.split(".");
if (parts.length < 2) { console.error("malformed JWT"); process.exit(1); }
const payload = JSON.parse(Buffer.from(parts[1].replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf8"));
if (payload.iss !== issuer) {
  console.error(`token iss mismatch: ${payload.iss}`);
  process.exit(1);
}
const aud = Array.isArray(payload.aud) ? payload.aud : (payload.aud ? [payload.aud] : []);
if (!aud.includes("oidc-reference-api")) {
  console.error(`token aud missing oidc-reference-api: ${JSON.stringify(aud)}`);
  process.exit(1);
}
const scopes = (payload.scope || "").split(" ");
if (!scopes.includes("service.jobs")) {
  console.error(`token scope missing service.jobs: ${payload.scope}`);
  process.exit(1);
}
console.log("real-token claim checks passed (iss, aud, scope)");
NODE

# Optional: live-token check for oidc-reference-api-gateway via Client Credentials.
# Gated by SMOKE_API_GATEWAY_CHECK=1 so environments without a provisioned secret
# do not break the smoke. Asserts the issued token carries
# aud=oidc-reference-auth-internal (the audience the Auth Service /internal/*
# endpoints will accept).
if [ "${SMOKE_API_GATEWAY_CHECK:-}" = "1" ]; then
  if ! curl -fsS \
      -d "grant_type=client_credentials" \
      -d "client_id=oidc-reference-api-gateway" \
      --data-urlencode "client_secret=${api_gateway_secret}" \
      "$issuer/protocol/openid-connect/token" >"$gateway_token_json"; then
    fail "api-gateway client_credentials token issuance failed (check API_GATEWAY_CLIENT_SECRET)"
  fi

  node - "$issuer" "$gateway_token_json" <<'NODE'
const fs = require("fs");
const issuer = process.argv[2];
const t = JSON.parse(fs.readFileSync(process.argv[3], "utf8"));
if (!t.access_token) { console.error("missing access_token (api-gateway)"); process.exit(1); }
const parts = t.access_token.split(".");
if (parts.length < 2) { console.error("malformed JWT (api-gateway)"); process.exit(1); }
const payload = JSON.parse(Buffer.from(parts[1].replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf8"));
if (payload.iss !== issuer) {
  console.error(`api-gateway token iss mismatch: ${payload.iss}`);
  process.exit(1);
}
const aud = Array.isArray(payload.aud) ? payload.aud : (payload.aud ? [payload.aud] : []);
if (!aud.includes("oidc-reference-auth-internal")) {
  console.error(`api-gateway token aud missing oidc-reference-auth-internal: ${JSON.stringify(aud)}`);
  process.exit(1);
}
console.log("api-gateway real-token claim checks passed (iss, aud=oidc-reference-auth-internal)");
NODE
fi
