#!/usr/bin/env sh
set -eu

# Verify script for the Auth Service module.
#
# Mirrors the verify-backend.sh idiom: assert layout, then run the module's
# Maven test phase. The BFF is split into the Auth Service (this module) and
# the APISIX-based API Gateway (verified by verify-api-gateway.sh) — see
# docs/architecture/architecture-decisions.md §A6.

cd "$(dirname "$0")/../auth-service"

fail() {
  echo "auth-service verification failed: $1" >&2
  exit 1
}

[ -f pom.xml ] || fail "missing pom.xml"
[ -d src/main/java ] || fail "missing src/main/java"
[ -d src/test/java ] || fail "missing src/test/java"

./mvnw -B -q test
