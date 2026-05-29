# lib.sh — shared helpers for api-gateway integration tests.
#
# Sourced by test-gateway-behavior.sh. POSIX sh. No bashisms.
#
# Contract:
#   - setup_session sid access_token expires_in_seconds xsrf
#     Writes a sess:{sid} JSON record into Valkey with TTL 1800s.
#   - setup_session_with_extra sid access_token expires_in_seconds xsrf extra_json
#     Same as setup_session but inserts a raw extra JSON fragment (e.g.
#     '"future_field":"value"') into the payload before the closing brace.
#   - clear_session sid
#     Deletes sess:{sid} from Valkey. Idempotent; never fails the script.
#   - get_session_field sid field
#     Echoes the (jq/python-extracted) value of a top-level field of sess:{sid}.
#     Empty string if the key is missing.
#   - hex_to_b64url hex_string
#     Converts hex to base64url (no padding). Used for HMAC-SHA256 outputs.
#   - sign_csrf_token signing_key_b64 value_b64
#     Echoes <value_b64>.<hmac_b64url> using the same scheme the Auth
#     Service's SignedCsrfSupport implements: HMAC-SHA256 over the value
#     part with the Base64-decoded signing key bytes.
#   - iso8601_in seconds
#     Echoes ISO-8601 UTC timestamp now+seconds. Handles both BSD and GNU
#     date.
#   - assert_status name expected actual [detail]
#     Prints [PASS] or [FAIL] and bumps PASSED/FAILED counters.

PASSED=0
FAILED=0

# Track sids set up so the trap can clean them up.
TRACKED_SIDS=""

track_sid() {
  TRACKED_SIDS="$TRACKED_SIDS $1"
}

valkey_exec() {
  # First positional: command; remaining: args (passed as separate argv).
  docker compose exec -T valkey valkey-cli "$@"
}

iso8601_in() {
  secs="$1"
  date -u -v "+${secs}S" +'%Y-%m-%dT%H:%M:%SZ' 2>/dev/null \
    || date -u -d "+${secs} seconds" +'%Y-%m-%dT%H:%M:%SZ'
}

setup_session() {
  sid="$1"
  access_token="$2"
  expires_in_seconds="${3:-300}"
  xsrf="$4"
  expires_at="$(iso8601_in "$expires_in_seconds")"
  payload="$(printf '{"access_token":"%s","access_token_expires_at":"%s","xsrf_token":"%s"}' \
    "$access_token" "$expires_at" "$xsrf")"
  valkey_exec SET "sess:$sid" "$payload" EX 1800 >/dev/null
  track_sid "$sid"
}

setup_session_with_extra() {
  sid="$1"
  access_token="$2"
  expires_in_seconds="${3:-300}"
  xsrf="$4"
  extra="$5"   # raw JSON fragment: '"future_field":"some_value"'
  expires_at="$(iso8601_in "$expires_in_seconds")"
  payload="$(printf '{"access_token":"%s","access_token_expires_at":"%s","xsrf_token":"%s",%s}' \
    "$access_token" "$expires_at" "$xsrf" "$extra")"
  valkey_exec SET "sess:$sid" "$payload" EX 1800 >/dev/null
  track_sid "$sid"
}

clear_session() {
  sid="$1"
  valkey_exec DEL "sess:$sid" >/dev/null 2>&1 || true
}

# Seed Valkey with the canonical session payload from
# schema/sess-payload.example.json (B8). The fixture's access_token_expires_at
# is a fixed historical date, so this helper rewrites it to be ~5 minutes in
# the future before SET — otherwise the gateway treats the session as expired
# and delegates a refresh. Returns nothing; tracks sid for cleanup.
setup_session_from_fixture() {
  sid="$1"
  fixture_path="$2"

  if ! command -v python3 >/dev/null 2>&1; then
    printf 'setup_session_from_fixture: python3 required to rewrite the fixture\n' >&2
    return 1
  fi
  payload="$(SID="$sid" FIXTURE="$fixture_path" python3 - <<'PY'
import json, os, sys
from datetime import datetime, timedelta, timezone

with open(os.environ['FIXTURE'], 'r') as f:
    doc = json.load(f)
p = doc['payload']
fresh = datetime.now(timezone.utc) + timedelta(minutes=5)
p['access_token_expires_at'] = fresh.strftime('%Y-%m-%dT%H:%M:%SZ')
sys.stdout.write(json.dumps(p, separators=(',', ':')))
PY
  )"
  if [ -z "$payload" ]; then
    printf 'setup_session_from_fixture: empty payload from python rewrite\n' >&2
    return 1
  fi
  valkey_exec SET "sess:$sid" "$payload" EX 1800 >/dev/null
  track_sid "$sid"
}

clear_all_tracked_sessions() {
  for sid in $TRACKED_SIDS; do
    clear_session "$sid"
  done
}

get_session_field() {
  sid="$1"
  field="$2"
  raw="$(valkey_exec GET "sess:$sid" 2>/dev/null || true)"
  if command -v python3 >/dev/null 2>&1; then
    FIELD="$field" printf '%s' "$raw" | python3 -c "
import json, os, sys
try:
  d = json.loads(sys.stdin.read())
  print(d.get(os.environ['FIELD'], ''))
except Exception:
  print('')
"
  else
    # crude fallback for flat string-valued JSON
    printf '%s' "$raw" \
      | sed -n "s/.*\"$field\"[[:space:]]*:[[:space:]]*\"\([^\"]*\)\".*/\1/p"
  fi
}

# Convert a hex string to base64url (no padding).
hex_to_b64url() {
  hex="$1"
  printf '%s' "$hex" \
    | xxd -r -p \
    | openssl base64 -A \
    | tr '+/' '-_' \
    | tr -d '='
}

# Sign a CSRF token-value with the shared HMAC key.
#
# This helper MUST stay in lockstep with the Auth Service's
# SignedCsrfSupport and the bff-session plugin's CSRF validator. Contract:
#   - signing_key_b64 is the standard (not base64url) base64 of the raw
#     256-bit key bytes (Java's Base64.getDecoder() accepts it).
#   - value_b64 is the random 128-bit token value, base64url-encoded.
#   - HMAC-SHA256 is computed over the ASCII bytes of value_b64 (not the
#     decoded random bytes) using the decoded key bytes.
#   - Output is value_b64 + "." + base64url(hmac_bytes), no padding.
#
# If either side ever changes the algorithm (e.g. to SHA-512), the
# value-encoding (raw bytes vs ASCII), or the key encoding (URL-safe
# base64 vs standard base64), this helper must be updated in lockstep.
sign_csrf_token() {
  signing_key_b64="$1"
  value_b64="$2"

  key_hex="$(printf '%s' "$signing_key_b64" \
    | openssl base64 -d -A \
    | xxd -p \
    | tr -d '\n')"
  if [ -z "$key_hex" ]; then
    printf 'sign_csrf_token: empty signing key (CSRF_SIGNING_KEY unset?)\n' >&2
    return 1
  fi

  hmac_hex="$(printf '%s' "$value_b64" \
    | openssl dgst -sha256 -mac HMAC -macopt "hexkey:$key_hex" \
    | awk '{print $NF}')"

  hmac_b64url="$(hex_to_b64url "$hmac_hex")"
  printf '%s.%s' "$value_b64" "$hmac_b64url"
}

# Generate a random base64url value (no padding) for the CSRF token-value.
random_b64url() {
  openssl rand 16 \
    | openssl base64 -A \
    | tr '+/' '-_' \
    | tr -d '='
}

# Compose a valid signed CSRF token (value + hmac) using $CSRF_SIGNING_KEY.
make_valid_csrf() {
  : "${CSRF_SIGNING_KEY:?CSRF_SIGNING_KEY must be set to a base64-encoded 256-bit key}"
  value="$(random_b64url)"
  sign_csrf_token "$CSRF_SIGNING_KEY" "$value"
}

assert_status() {
  name="$1"
  expected="$2"
  actual="$3"
  detail="${4:-}"
  if [ "$actual" = "$expected" ]; then
    printf '[PASS] %s\n' "$name"
    PASSED=$((PASSED + 1))
  else
    printf '[FAIL] %s expected=%s actual=%s %s\n' \
      "$name" "$expected" "$actual" "$detail"
    FAILED=$((FAILED + 1))
  fi
}

assert_contains() {
  name="$1"
  haystack="$2"
  needle="$3"
  if printf '%s' "$haystack" | grep -q -- "$needle"; then
    printf '[PASS] %s\n' "$name"
    PASSED=$((PASSED + 1))
  else
    printf '[FAIL] %s expected to contain %s\n' "$name" "$needle"
    FAILED=$((FAILED + 1))
  fi
}

assert_not_contains() {
  name="$1"
  haystack="$2"
  needle="$3"
  if printf '%s' "$haystack" | grep -q -- "$needle"; then
    printf '[FAIL] %s expected NOT to contain %s\n' "$name" "$needle"
    FAILED=$((FAILED + 1))
  else
    printf '[PASS] %s\n' "$name"
    PASSED=$((PASSED + 1))
  fi
}

skip_test() {
  name="$1"
  reason="$2"
  printf '[SKIP] %s -- %s\n' "$name" "$reason"
}
