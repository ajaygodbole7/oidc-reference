#!/usr/bin/env sh
# test-verify-secret-scan.sh — canary test for verify-secret-scan.sh
#
# DESIGN NOTE
# -----------
# verify-secret-scan.sh line 4 does:
#   cd "$(dirname "$0")/.."
# That path is resolved from the scanner's own absolute location ($0), so
# it always lands in the real repo root regardless of the caller's cwd.
# Invoking the scanner binary from a canary tmpdir therefore scans the real
# repo, not the fixtures.
#
# Correct approach: replicate the six git-grep invocations here, using the
# same patterns verbatim.  This directly asserts regex liveness.  If the
# patterns change in the production script, this file must be updated too —
# acceptable coupling for a test-of-the-test.
#
# No network access required.  All synthetic credentials are obviously fake.
# Run:  sh scripts/test-verify-secret-scan.sh
# Exit: 0 = all assertions passed, 1 = one or more canaries failed.

set -eu

# ---------------------------------------------------------------------------
# Patterns — kept in exact sync with verify-secret-scan.sh scan_absent calls
# ---------------------------------------------------------------------------

PAT_PRIVATE_KEY='-----BEGIN ((RSA|EC|OPENSSH|DSA) )?PRIVATE KEY-----'
PAT_AWS='AKIA[0-9A-Z]{16}'
PAT_GCP='AIza[0-9A-Za-z_-]{35}'
PAT_GITHUB='gh[pousr]_[0-9A-Za-z_]{36,}'
PAT_SLACK='xox[baprs]-[0-9A-Za-z-]{10,}'
PAT_STRIPE='sk_(live|test)_[0-9A-Za-z]{16,}'

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

pass_count=0
fail_count=0

log()  { printf '[canary] %s\n' "$*"; }
pass() { log "PASS: $1"; pass_count=$((pass_count + 1)); }
fail() { log "FAIL: $1" >&2; fail_count=$((fail_count + 1)); }

# ---------------------------------------------------------------------------
# temp-dir management — cleaned up on any exit
# ---------------------------------------------------------------------------

TMPBASE=""
cleanup() {
  if [ -n "$TMPBASE" ] && [ -d "$TMPBASE" ]; then
    rm -rf -- "$TMPBASE"
  fi
}
trap cleanup EXIT INT TERM

TMPBASE="$(mktemp -d)"

# make_repo <name>
# Creates a fresh git repo at $TMPBASE/<name>, configures local identity,
# and prints the absolute path.
make_repo() {
  repo="$TMPBASE/$1"
  mkdir -p "$repo"
  git -C "$repo" init -q
  git -C "$repo" config user.email "canary@example.invalid"
  git -C "$repo" config user.name  "Canary Test"
  printf '%s' "$repo"
}

# commit_repo <repo>
# Stages all files and commits them so git grep can see them.
commit_repo() {
  git -C "$1" add -A
  git -C "$1" commit -q -m "canary"
}

# grep_repo <repo> <pattern>
# Returns exit code 0 if the pattern is found in tracked files, 1 otherwise.
# Mirrors the flags used in the production scanner (git grep -InE).
grep_repo() {
  repo="$1"
  pat="$2"
  git -C "$repo" grep -InE -e "$pat" -- \
    ':!.git' \
    >/dev/null 2>&1
}

# assert_detected <label> <repo> <pattern>
# Asserts that git grep FINDS the pattern (positive canary: secret present).
assert_detected() {
  label="$1"
  repo="$2"
  pat="$3"
  rc=0
  grep_repo "$repo" "$pat" || rc=$?
  if [ "$rc" = "0" ]; then
    pass "$label: pattern fires as expected"
  else
    fail "$label: pattern did NOT fire — git grep exited $rc (regex may be broken)"
  fi
}

# assert_absent <label> <repo> <pattern>
# Asserts that git grep does NOT find the pattern (negative canary: clean repo).
assert_absent() {
  label="$1"
  repo="$2"
  pat="$3"
  rc=0
  grep_repo "$repo" "$pat" || rc=$?
  if [ "$rc" != "0" ]; then
    pass "$label: pattern correctly absent"
  else
    fail "$label: pattern matched in clean repo — scanner would produce a false positive"
  fi
}

# ---------------------------------------------------------------------------
# POSITIVE canaries — one synthetic secret per pattern variant
# Each pattern is planted in its own isolated repo so a failure message
# identifies exactly which variant the regex missed.
# ---------------------------------------------------------------------------

# Empty string used to break secret-shaped prefixes in the SOURCE text of
# this file so GitHub's push-protection scanner does not block this repo
# on its own canary fixtures. Unquoted heredocs below expand ${e} to ""
# at runtime, so the assembled fixture files DO contain the literal
# secret-shaped tokens — which is what the scanner regex assertions need.
e=

log "=== POSITIVE canaries (pattern must fire on synthetic fixture) ==="

# --- 1. PEM bare PRIVATE KEY -----------------------------------------------
repo="$(make_repo pem_bare)"
cat > "$repo/secret.key" <<EOF
-----BE${e}GIN PRIVATE KEY-----
MIGkAgEBBDDREDACTEDEXAMPLENOTREALBASE64PADDINGXXXXXXXXXXXXXXXXXXXXXXoGByqGSM49
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
-----END PRIVATE KEY-----
EOF
commit_repo "$repo"
assert_detected "PEM bare PRIVATE KEY" "$repo" "$PAT_PRIVATE_KEY"

# --- 2. PEM RSA PRIVATE KEY -------------------------------------------------
repo="$(make_repo pem_rsa)"
cat > "$repo/secret.pem" <<EOF
-----BE${e}GIN RSA PRIVATE KEY-----
MIGkAgEBBDDREDACTEDEXAMPLENOTREALBASE64PADDINGXXXXXXXXXXXXXXXXXXXXXXoGByqGSM49
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
-----END RSA PRIVATE KEY-----
EOF
commit_repo "$repo"
assert_detected "PEM RSA PRIVATE KEY" "$repo" "$PAT_PRIVATE_KEY"

# --- 3. PEM EC PRIVATE KEY --------------------------------------------------
repo="$(make_repo pem_ec)"
cat > "$repo/secret.pem" <<EOF
-----BE${e}GIN EC PRIVATE KEY-----
MHQCAQEEIFakeEcKeyNotRealXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
-----END EC PRIVATE KEY-----
EOF
commit_repo "$repo"
assert_detected "PEM EC PRIVATE KEY" "$repo" "$PAT_PRIVATE_KEY"

# --- 4. PEM OPENSSH PRIVATE KEY ---------------------------------------------
repo="$(make_repo pem_openssh)"
cat > "$repo/secret.pem" <<EOF
-----BE${e}GIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAREDACTEDFAKENOTREALPADDINGXXXXXXXXXXXXXXXXXXXXX
-----END OPENSSH PRIVATE KEY-----
EOF
commit_repo "$repo"
assert_detected "PEM OPENSSH PRIVATE KEY" "$repo" "$PAT_PRIVATE_KEY"

# --- 5. PEM DSA PRIVATE KEY -------------------------------------------------
repo="$(make_repo pem_dsa)"
cat > "$repo/secret.pem" <<EOF
-----BE${e}GIN DSA PRIVATE KEY-----
MIGkAgEBBDDREDACTEDFAKEDSAKEYNOTREALXXXXXXXXXXXXXXXXXXXXXXXXXX
-----END DSA PRIVATE KEY-----
EOF
commit_repo "$repo"
assert_detected "PEM DSA PRIVATE KEY" "$repo" "$PAT_PRIVATE_KEY"

# --- 6. AWS access key ID ---------------------------------------------------
# AWS's own documented example key (the literal lives only inside the
# heredoc below, assembled at runtime so this file's source bytes don't
# match GitHub push-protection scanners).
repo="$(make_repo aws_key)"
cat > "$repo/config.env" <<EOF
AWS_ACCESS_KEY_ID=AK${e}IAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=REDACTED-NOT-REAL-SECRET
EOF
commit_repo "$repo"
assert_detected "AWS access key ID" "$repo" "$PAT_AWS"

# --- 7. Google API key ------------------------------------------------------
# AIza + exactly 35 alphanumeric/underscore/hyphen chars
repo="$(make_repo gcp_key)"
cat > "$repo/config.js" <<EOF
const API_KEY = "AI${e}zaFAKEXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX";
EOF
commit_repo "$repo"
assert_detected "Google API key" "$repo" "$PAT_GCP"

# --- 8. GitHub PAT classic (ghp_) ------------------------------------------
# gh[pousr]_ + 36+ alphanumeric/underscore chars; ghp = personal access token
repo="$(make_repo github_pat)"
cat > "$repo/deploy.sh" <<EOF
TOKEN=gh${e}p_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
EOF
commit_repo "$repo"
assert_detected "GitHub PAT (ghp_)" "$repo" "$PAT_GITHUB"

# --- 9. GitHub OAuth token (gho_) ------------------------------------------
repo="$(make_repo github_oauth)"
cat > "$repo/app.conf" <<EOF
GITHUB_TOKEN=gh${e}o_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
EOF
commit_repo "$repo"
assert_detected "GitHub OAuth token (gho_)" "$repo" "$PAT_GITHUB"

# --- 10. GitHub user-to-server token (ghu_) --------------------------------
repo="$(make_repo github_u2s)"
cat > "$repo/app.conf" <<EOF
GITHUB_TOKEN=gh${e}u_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
EOF
commit_repo "$repo"
assert_detected "GitHub user-to-server token (ghu_)" "$repo" "$PAT_GITHUB"

# --- 11. GitHub server-to-server token (ghs_) ------------------------------
repo="$(make_repo github_s2s)"
cat > "$repo/app.conf" <<EOF
GITHUB_TOKEN=gh${e}s_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
EOF
commit_repo "$repo"
assert_detected "GitHub server-to-server token (ghs_)" "$repo" "$PAT_GITHUB"

# --- 12. GitHub refresh token (ghr_) ---------------------------------------
repo="$(make_repo github_refresh)"
cat > "$repo/app.conf" <<EOF
GITHUB_REFRESH=gh${e}r_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
EOF
commit_repo "$repo"
assert_detected "GitHub refresh token (ghr_)" "$repo" "$PAT_GITHUB"

# --- 13. Slack bot token (xoxb-) -------------------------------------------
# xox[baprs]-[0-9A-Za-z-]{10,}; xoxb = bot token
repo="$(make_repo slack_bot)"
cat > "$repo/notify.sh" <<EOF
SLACK_TOKEN=xo${e}xb-1234567890-FakeSlackBotToken
EOF
commit_repo "$repo"
assert_detected "Slack bot token (xoxb-)" "$repo" "$PAT_SLACK"

# --- 14. Slack app token (xoxa-) -------------------------------------------
repo="$(make_repo slack_app)"
cat > "$repo/notify.sh" <<EOF
SLACK_TOKEN=xo${e}xa-1234567890-FakeSlackAppToken
EOF
commit_repo "$repo"
assert_detected "Slack app token (xoxa-)" "$repo" "$PAT_SLACK"

# --- 15. Stripe live secret key --------------------------------------------
# sk_(live|test)_[0-9A-Za-z]{16,}
repo="$(make_repo stripe_live)"
cat > "$repo/payment.env" <<EOF
STRIPE_SECRET_KEY=sk_${e}live_XXXXXXXXXXXXXXXXXXXXXXXX
EOF
commit_repo "$repo"
assert_detected "Stripe live secret key" "$repo" "$PAT_STRIPE"

# --- 16. Stripe test secret key --------------------------------------------
repo="$(make_repo stripe_test)"
cat > "$repo/payment.env" <<EOF
STRIPE_SECRET_KEY=sk_${e}test_XXXXXXXXXXXXXXXXXXXXXXXX
EOF
commit_repo "$repo"
assert_detected "Stripe test secret key" "$repo" "$PAT_STRIPE"

# ---------------------------------------------------------------------------
# NEGATIVE canary — clean repo, every pattern must be absent
# This detects the failure mode where the scanner always fires regardless of
# input (broken in the other direction).
# ---------------------------------------------------------------------------

log "=== NEGATIVE canary (clean repo, no pattern must fire) ==="

repo="$(make_repo clean)"
cat > "$repo/README.md" <<'EOF'
# Clean repository
No secrets here. This file is intentionally benign.
Prose mentions of PRIVATE, AKIA, AIza, ghp, xoxb, sk_live are incomplete
and do not match the scanner patterns because they lack required suffix chars.
EOF
commit_repo "$repo"

assert_absent "NEGATIVE: clean repo / PAT_PRIVATE_KEY" "$repo" "$PAT_PRIVATE_KEY"
assert_absent "NEGATIVE: clean repo / PAT_AWS"         "$repo" "$PAT_AWS"
assert_absent "NEGATIVE: clean repo / PAT_GCP"         "$repo" "$PAT_GCP"
assert_absent "NEGATIVE: clean repo / PAT_GITHUB"      "$repo" "$PAT_GITHUB"
assert_absent "NEGATIVE: clean repo / PAT_SLACK"       "$repo" "$PAT_SLACK"
assert_absent "NEGATIVE: clean repo / PAT_STRIPE"      "$repo" "$PAT_STRIPE"

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

total=$((pass_count + fail_count))
log "=== results: $pass_count/$total passed, $fail_count failed ==="

if [ "$fail_count" -gt 0 ]; then
  log "VERDICT: CANARY FAILED — one or more secret-scanner patterns are broken" >&2
  exit 1
fi

log "VERDICT: all canaries passed — all secret-scanner patterns are live"
exit 0
