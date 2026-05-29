#!/usr/bin/env sh
set -eu

# Verify script for the Auth Service module.
#
# Mirrors the verify-backend.sh idiom (and the now-retired verify-bff.sh):
# assert layout, then run the module's Maven test phase. The combined BFF
# has been split per RESHAPE-FRAME-B into the Auth Service (this module)
# and the APISIX-based API Gateway (verified by verify-api-gateway.sh).

cd "$(dirname "$0")/../auth-service"

fail() {
  echo "auth-service verification failed: $1" >&2
  exit 1
}

[ -f pom.xml ] || fail "missing pom.xml"
[ -d src/main/java ] || fail "missing src/main/java"
[ -d src/test/java ] || fail "missing src/test/java"

./mvnw -B -q test
