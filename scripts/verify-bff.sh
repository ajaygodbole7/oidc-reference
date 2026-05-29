#!/usr/bin/env sh
set -eu

cd "$(dirname "$0")/../bff"

fail() {
  echo "bff verification failed: $1" >&2
  exit 1
}

[ -f pom.xml ] || fail "missing pom.xml"
[ -d src/main/java ] || fail "missing src/main/java"
[ -d src/test/java ] || fail "missing src/test/java"

./mvnw test
