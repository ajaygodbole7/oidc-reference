#!/usr/bin/env sh
set -eu

cd "$(dirname "$0")/../authorization-server"

fail() {
  echo "authorization-server verification failed: $1" >&2
  exit 1
}

[ -f compose.yaml ] || fail "missing compose.yaml"
[ -f realm/oidc-reference-realm.json ] || fail "missing realm/oidc-reference-realm.json"
[ -d tests ] || fail "missing tests/"
[ -x tests/smoke.sh ] || fail "missing executable tests/smoke.sh"

docker compose config >/dev/null

# Static security assertions on the standalone compose. Keycloak must bind to
# loopback (not 0.0.0.0) so the admin console + realm are never LAN-reachable,
# and the bootstrap admin password must be env-overridable rather than a baked-in
# literal. Mirrors the loopback posture the root compose.yaml already documents.
# The password check is behavioral: we override KC_BOOTSTRAP_ADMIN_PASSWORD with a
# probe and assert the rendered config reflects it (a hardcoded value would not).
probe_pw="__sentinel_probe__"
rendered_cfg="$(mktemp)"
trap 'rm -f "$rendered_cfg"' EXIT
KC_BOOTSTRAP_ADMIN_PASSWORD="$probe_pw" docker compose config --format json >"$rendered_cfg"
node - "$rendered_cfg" "$probe_pw" <<'NODE'
const fs = require("fs");
const c = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));
const probe = process.argv[3];
const kc = c.services && c.services.keycloak;
function fail(m) {
  console.error("authorization-server compose security check failed: " + m);
  process.exit(1);
}
if (!kc) fail("missing keycloak service");
const pub = (kc.ports || []).find((p) => String(p.target) === "8080");
if (!pub) fail("keycloak must publish container port 8080");
if (pub.host_ip !== "127.0.0.1") {
  fail(`keycloak port 8080 must bind loopback 127.0.0.1, got host_ip=${pub.host_ip || "(unset => 0.0.0.0, LAN-reachable)"}`);
}
if ((kc.environment || {}).KC_BOOTSTRAP_ADMIN_PASSWORD !== probe) {
  fail("KC_BOOTSTRAP_ADMIN_PASSWORD must be env-overridable (use ${KC_BOOTSTRAP_ADMIN_PASSWORD:-admin})");
}
console.log("authorization-server compose security checks passed (loopback bind + overridable admin password)");
NODE

SMOKE_SKIP_DISCOVERY=1 tests/smoke.sh
docker compose up -d
tests/smoke.sh
