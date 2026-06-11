#!/bin/sh
# Lua unit tests for the bff-session plugin, run inside the same pinned
# APISIX image the stack deploys (compose.yaml) so the LuaJIT runtime matches
# production exactly. The plugin no longer parses timestamps or touches the
# session store — session lookup/slide/refresh live behind the Auth Service's
# /internal/resolve — so the only branch-logic left to unit-test here is the
# resolve decision table.
set -eu

APISIX_IMAGE="${APISIX_IMAGE:-apache/apisix:3.16.0-debian}"
GATEWAY_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
LUAJIT=/usr/local/openresty/luajit/bin/luajit

command -v docker >/dev/null 2>&1 || {
  echo "test-lua-unit: docker is required (runs the pinned APISIX image)" >&2
  exit 1
}

status=0

# resolve_session: the failure-branch decision table (404/409 eviction, 401
# CC-token retry, transport→503, malformed-200→502) — untestable against the
# live stack because the failures are not deterministically orchestratable.
echo "== resolve-flow decision table =="
if ! docker run --rm \
    -v "$GATEWAY_DIR:/gateway:ro" -w /gateway \
    "$APISIX_IMAGE" "$LUAJIT" tests/test-resolve-flow.lua plugins/bff-session.lua; then
  status=1
fi

if [ "$status" -ne 0 ]; then
  echo "test-lua-unit: FAIL" >&2
else
  echo "test-lua-unit: PASS (resolve-flow)"
fi
exit $status
