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
SMOKE_SKIP_DISCOVERY=1 tests/smoke.sh
docker compose up -d
tests/smoke.sh
