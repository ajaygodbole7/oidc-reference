#!/usr/bin/env sh
set -eu
SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
. "$SCRIPT_DIR/lib/common.sh"
ROOT="$(repo_root "$SCRIPT_DIR")"

# Fast inner-loop tests: JVM unit/component suites + frontend vitest, run in
# parallel. No Docker, no live infra, no browser e2e. The full frontend verify
# (lint / typecheck / build / playwright) and the live-infra checks live in
# `verify-all.sh` and `test-e2e.sh` respectively.
require_cmd node "Install Node 20+ (e.g. via nvm)."

info "running module suites in parallel: auth-service, resource-server, frontend"
logdir="$(mktemp -d)"
trap 'rm -rf "$logdir"' EXIT

sh "$SCRIPT_DIR/verify-auth-service.sh" >"$logdir/auth.log" 2>&1 & p_auth=$!
sh "$SCRIPT_DIR/verify-backend.sh"      >"$logdir/rs.log"   2>&1 & p_rs=$!
( cd "$ROOT/frontend" && npm run test ) >"$logdir/fe.log"   2>&1 & p_fe=$!

rc=0
wait "$p_auth" || { rc=1; warn "auth-service suite FAILED:";      tail -40 "$logdir/auth.log"; }
wait "$p_rs"   || { rc=1; warn "resource-server suite FAILED:";   tail -40 "$logdir/rs.log"; }
wait "$p_fe"   || { rc=1; warn "frontend suite FAILED:";          tail -40 "$logdir/fe.log"; }

[ "$rc" -eq 0 ] || die "fast suites failed (see output above)"
success "fast suites passed: auth-service, resource-server, frontend"
