# common.sh — shared helpers for oidc-reference dev/CI scripts.
#
# SOURCE this file; do not execute it. POSIX sh (the repo standard: every
# script uses `#!/usr/bin/env sh` + `set -eu`, no bashisms). Typical header:
#
#   #!/usr/bin/env sh
#   set -eu
#   SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
#   . "$SCRIPT_DIR/lib/common.sh"
#   cd "$(repo_root "$SCRIPT_DIR")"
#
# Provides: info/success/warn/die logging, require_cmd preflight, repo_root.

# Colors only when stdout is a TTY (keeps CI logs clean).
if [ -t 1 ]; then
  C_RED='\033[0;31m'; C_GRN='\033[0;32m'; C_YEL='\033[1;33m'; C_CYA='\033[0;36m'; C_NC='\033[0m'
else
  C_RED=''; C_GRN=''; C_YEL=''; C_CYA=''; C_NC=''
fi

info()    { printf '%b==>%b %s\n'   "$C_CYA" "$C_NC" "$*"; }
success() { printf '%b[ok]%b %s\n'  "$C_GRN" "$C_NC" "$*"; }
warn()    { printf '%b[warn]%b %s\n' "$C_YEL" "$C_NC" "$*" >&2; }
die()     { printf '%b[error]%b %s\n' "$C_RED" "$C_NC" "$*" >&2; exit 1; }

# warn_low_disk [min_gb] — WARN (never block) when free disk is under the
# threshold (default 3 GB). Repeated full-stack image rebuilds can exhaust the
# host disk, and an ENOSPC mid-run surfaces as a confusing test failure rather
# than an infra problem. A heads-up here points at the real cause + fix.
warn_low_disk() {
  _min_gb="${1:-3}"
  _avail_kb="$(df -Pk . 2>/dev/null | awk 'NR==2 {print $4}')"
  [ -n "$_avail_kb" ] || return 0
  _avail_gb=$(( _avail_kb / 1024 / 1024 ))
  if [ "$_avail_gb" -lt "$_min_gb" ]; then
    warn "low disk: ~${_avail_gb}GB free (< ${_min_gb}GB). Full-stack rebuilds may hit ENOSPC (looks like a test failure); free space with 'docker system prune -af'."
  fi
}

# repo_root <script_dir> — echo the repo root (scripts/ lives one level down,
# scripts/lib/ two). Callers pass their own resolved SCRIPT_DIR so this works
# regardless of the invoking cwd.
repo_root() {
  CDPATH= cd -- "$1/.." && pwd
}

# require_cmd <cmd> [install hint] — fail fast with a clear message + hint when
# a hard dependency is missing. `set -u` does NOT catch a missing binary; this
# does. Fixes the class of "script silently needs a tool not on PATH" bugs.
require_cmd() {
  _cmd="$1"; _hint="${2:-}"
  command -v "$_cmd" >/dev/null 2>&1 || die "required command '$_cmd' not found.${_hint:+ $_hint}"
}

# wait_http <name> <url> [tries] — poll a URL until it returns 2xx, using
# curl's own retry (no `sleep` loop). Each try waits ~2s; default ~45 tries
# (~90s). The URL MUST be one that returns 200 when ready (e.g. an actuator
# health or discovery endpoint), since -f treats non-2xx as not-ready.
wait_http() {
  _name="$1"; _url="$2"; _tries="${3:-45}"
  curl -fsS --retry "$_tries" --retry-delay 2 --retry-connrefused --retry-all-errors \
    -o /dev/null "$_url" 2>/dev/null \
    || die "$_name did not become ready at $_url"
}

# wait_responding <name> <url> [tries] — poll until the URL answers HTTP with
# ANY status (a 404/401 still means the server is up). Use for endpoints that
# do not return 2xx when ready, e.g. an APISIX gateway with no public health
# route. Retries only on connection failure, not on HTTP status.
wait_responding() {
  _name="$1"; _url="$2"; _tries="${3:-45}"
  curl -sS --retry "$_tries" --retry-delay 2 --retry-connrefused --retry-all-errors \
    -o /dev/null "$_url" 2>/dev/null \
    || die "$_name not responding at $_url"
}
