#!/usr/bin/env sh
set -eu

cd "$(dirname "$0")/.."

fail() {
  echo "secret scan failed: $1" >&2
  exit 1
}

scan_absent() {
  name="$1"
  pattern="$2"
  tmp_file="$(mktemp)"
  if git grep -InE -e "$pattern" -- \
      ':!.git' \
      ':!**/node_modules/**' \
      ':!**/target/**' \
      ':!**/dist/**' \
      ':!**/test-results/**' \
      ':!**/playwright-report/**' \
      ':!scripts/test-verify-secret-scan.sh' \
      ':!frontend/package-lock.json' \
      >"$tmp_file"; then
    cat "$tmp_file" >&2
    rm -f "$tmp_file"
    fail "matched $name"
  fi
  rm -f "$tmp_file"
}

scan_absent "private key material" '-----BEGIN ((RSA|EC|OPENSSH|DSA) )?PRIVATE KEY-----'
scan_absent "AWS access key id" 'AKIA[0-9A-Z]{16}'
scan_absent "Google API key" 'AIza[0-9A-Za-z_-]{35}'
scan_absent "GitHub token" 'gh[pousr]_[0-9A-Za-z_]{36,}'
scan_absent "Slack token" 'xox[baprs]-[0-9A-Za-z-]{10,}'
scan_absent "Stripe secret key" 'sk_(live|test)_[0-9A-Za-z]{16,}'

echo "secret scan passed"
