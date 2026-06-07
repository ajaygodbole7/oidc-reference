#!/usr/bin/env sh
set -eu

cd "$(dirname "$0")/../frontend"

fail() {
  echo "frontend verification failed: $1" >&2
  exit 1
}

[ -f package.json ] || fail "missing package.json"
[ -f playwright.config.ts ] || fail "missing playwright.config.ts"
[ -d src ] || fail "missing src/"
[ -d tests ] || fail "missing tests/"

npm run lint
npm run typecheck
npm run test
npm run build
npm run check:bundle
npm run test:e2e

