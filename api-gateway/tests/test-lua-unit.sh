#!/bin/sh
# Lua unit tests for the bff-session plugin, run inside the same pinned
# APISIX image the stack deploys (compose.yaml) so the LuaJIT runtime and
# os.time/os.date semantics match production exactly. The TZ matrix guards
# the parse_iso8601_utc UTC-correctness contract that compose's TZ=UTC pin
# would otherwise silently mask: the parser must be correct in any zone,
# including one with DST.
set -eu

APISIX_IMAGE="${APISIX_IMAGE:-apache/apisix:3.16.0-debian}"
GATEWAY_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
LUAJIT=/usr/local/openresty/luajit/bin/luajit

command -v docker >/dev/null 2>&1 || {
  echo "test-lua-unit: docker is required (runs the pinned APISIX image)" >&2
  exit 1
}

status=0

# parse_iso8601_utc: correctness across a TZ matrix (the parser must not
# depend on the compose TZ=UTC pin).
for tz in UTC Asia/Kolkata America/Los_Angeles; do
  echo "== iso8601-parse: TZ=$tz =="
  if ! docker run --rm -e "TZ=$tz" \
      -v "$GATEWAY_DIR:/gateway:ro" -w /gateway \
      "$APISIX_IMAGE" "$LUAJIT" tests/test-iso8601-parse.lua plugins/bff-session.lua; then
    status=1
  fi
done

# refresh_session: the failure-branch decision table (404/409 eviction,
# 401 CC-token retry, transport→503) — untestable against the live stack.
echo "== refresh-flow decision table =="
if ! docker run --rm \
    -v "$GATEWAY_DIR:/gateway:ro" -w /gateway \
    "$APISIX_IMAGE" "$LUAJIT" tests/test-refresh-flow.lua plugins/bff-session.lua; then
  status=1
fi

if [ "$status" -ne 0 ]; then
  echo "test-lua-unit: FAIL" >&2
else
  echo "test-lua-unit: PASS (iso8601 x3 TZ + refresh-flow)"
fi
exit $status
