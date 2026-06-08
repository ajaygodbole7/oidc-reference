# lib.sh — shared helpers for api-gateway integration tests.
#
# Sourced by test-gateway-behavior.sh. POSIX sh. No bashisms.
#
# Contract:
#   - setup_session sid access_token expires_in_seconds
#     Writes a sess:{sid} JSON record into Valkey with TTL 1800s.
#   - setup_session_with_extra sid access_token expires_in_seconds extra_json
#     Same as setup_session but inserts a raw extra JSON fragment (e.g.
#     '"future_field":"value"') into the payload before the closing brace.
#   - clear_session sid
#     Deletes sess:{sid} from Valkey. Idempotent; never fails the script.
#   - get_session_field sid field
#     Echoes the (jq/python-extracted) value of a top-level field of sess:{sid}.
#     Empty string if the key is missing.
#   - set_session_access_expiry sid expires_in_seconds
#     Rewrites only access_token_expires_at for a real sess:{sid}; used to move
#     a login-derived session into the gateway refresh window without forging
#     token state.
#   - mint_service_access_token
#     Echoes a real Keycloak client-credentials access token for
#     oidc-reference-service.
#   - json_get file dotted.path
#     Echoes a JSON field from a response file. Empty string if absent.
#   - hex_to_b64url hex_string
#     Converts hex to base64url (no padding). Used for HMAC-SHA256 outputs.
#   - sign_csrf_token signing_key_b64 value_b64 sid
#     Echoes <value_b64>.<hmac_b64url> using the same scheme the Auth
#     Service's SignedCsrfSupport implements: HMAC-SHA256 over the value
#     part plus ":" plus sid with the Base64-decoded signing key bytes.
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
  # Build a signed offset so a negative arg (a timestamp in the PAST, used to
  # model a session already past its absolute ceiling) is valid for both BSD
  # `date -v` and GNU `date -d`. Positive offsets keep their explicit '+'.
  case "$secs" in
    -*) op="$secs" ;;
    *)  op="+$secs" ;;
  esac
  date -u -v "${op}S" +'%Y-%m-%dT%H:%M:%SZ' 2>/dev/null \
    || date -u -d "${op} seconds" +'%Y-%m-%dT%H:%M:%SZ'
}

setup_session() {
  sid="$1"
  access_token="$2"
  expires_in_seconds="${3:-300}"
  expires_at="$(iso8601_in "$expires_in_seconds")"
  absolute_expires_at="$(iso8601_in 3600)"
  payload="$(printf '{"access_token":"%s","access_token_expires_at":"%s","absolute_expires_at":"%s"}' \
    "$access_token" "$expires_at" "$absolute_expires_at")"
  valkey_exec SET "sess:$sid" "$payload" EX 1800 >/dev/null
  track_sid "$sid"
}

setup_session_with_extra() {
  sid="$1"
  access_token="$2"
  expires_in_seconds="${3:-300}"
  extra="$4"   # raw JSON fragment: '"future_field":"some_value"'
  expires_at="$(iso8601_in "$expires_in_seconds")"
  absolute_expires_at="$(iso8601_in 3600)"
  payload="$(printf '{"access_token":"%s","access_token_expires_at":"%s","absolute_expires_at":"%s",%s}' \
    "$access_token" "$expires_at" "$absolute_expires_at" "$extra")"
  valkey_exec SET "sess:$sid" "$payload" EX 1800 >/dev/null
  track_sid "$sid"
}

setup_session_absolute() {
  # Like setup_session but with explicit control over the absolute ceiling and
  # the Valkey key TTL, so callers can prove the gateway's idle-slide is capped
  # by `absolute_expires_at`:
  #   $1 sid  $2 access_token  $3 access_expires_in  $4 absolute_in  $5 ttl
  # $4 may be NEGATIVE to model a session already past its hard ceiling.
  sid="$1"
  access_token="$2"
  expires_in_seconds="${3:-300}"
  absolute_in_seconds="${4:-3600}"
  ttl_seconds="${5:-1800}"
  expires_at="$(iso8601_in "$expires_in_seconds")"
  absolute_expires_at="$(iso8601_in "$absolute_in_seconds")"
  payload="$(printf '{"access_token":"%s","access_token_expires_at":"%s","absolute_expires_at":"%s"}' \
    "$access_token" "$expires_at" "$absolute_expires_at")"
  valkey_exec SET "sess:$sid" "$payload" EX "$ttl_seconds" >/dev/null
  track_sid "$sid"
}

clear_session() {
  sid="$1"
  valkey_exec DEL "sess:$sid" >/dev/null 2>&1 || true
}

# Seed Valkey with the canonical session payload from
# schema/sess-payload.example.json (B8). The fixture's access_token_expires_at
# and absolute_expires_at are fixed dates, so this helper rewrites them before
# SET — otherwise the gateway correctly treats the fixture as expired instead of
# exercising the parser contract. Returns nothing; tracks sid for cleanup.
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
p['absolute_expires_at'] = (datetime.now(timezone.utc) + timedelta(hours=1)).strftime('%Y-%m-%dT%H:%M:%SZ')
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
    printf '%s' "$raw" | FIELD="$field" python3 -c "
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

set_session_access_expiry() {
  sid="$1"
  expires_in_seconds="$2"
  expires_at="$(iso8601_in "$expires_in_seconds")"
  raw="$(valkey_exec GET "sess:$sid" 2>/dev/null || true)"
  if [ -z "$raw" ] || [ "$raw" = "(nil)" ]; then
    printf 'set_session_access_expiry: missing sess:%s\n' "$sid" >&2
    return 1
  fi
  if ! command -v python3 >/dev/null 2>&1; then
    printf 'set_session_access_expiry: python3 required to rewrite session JSON\n' >&2
    return 1
  fi
  payload="$(printf '%s' "$raw" | EXPIRES_AT="$expires_at" python3 -c '
import json, os, sys

doc = json.loads(sys.stdin.read())
doc["access_token_expires_at"] = os.environ["EXPIRES_AT"]
sys.stdout.write(json.dumps(doc, separators=(",", ":")))
')"
  if [ -z "$payload" ]; then
    printf 'set_session_access_expiry: empty rewritten payload for sess:%s\n' "$sid" >&2
    return 1
  fi
  valkey_exec SET "sess:$sid" "$payload" EX 1800 >/dev/null
}

mint_service_access_token() {
  token_endpoint="${OIDC_TOKEN_ENDPOINT:-http://localhost:8080/realms/oidc-reference/protocol/openid-connect/token}"
  service_secret="${SERVICE_CLIENT_SECRET:-LOCAL_DEV_SERVICE_CLIENT_SECRET__CHANGE_BEFORE_DEPLOY}"
  if ! command -v python3 >/dev/null 2>&1; then
    printf 'mint_service_access_token: python3 required to parse token JSON\n' >&2
    return 1
  fi
  tmp="$(mktemp)"
  if ! curl -fsS \
      -d "grant_type=client_credentials" \
      -d "client_id=oidc-reference-service" \
      --data-urlencode "client_secret=${service_secret}" \
      "$token_endpoint" >"$tmp"; then
    rm -f "$tmp"
    return 1
  fi
  python3 - "$tmp" <<'PY'
import json, sys
with open(sys.argv[1], "r") as f:
    doc = json.load(f)
print(doc.get("access_token", ""))
PY
  rm -f "$tmp"
}

json_get() {
  file="$1"
  path="$2"
  if ! command -v python3 >/dev/null 2>&1; then
    printf 'json_get: python3 required to parse response JSON\n' >&2
    return 1
  fi
  python3 - "$file" "$path" <<'PY'
import json, sys
with open(sys.argv[1], "r") as f:
    doc = json.load(f)
cur = doc
for part in sys.argv[2].split("."):
    if isinstance(cur, dict) and part in cur:
        cur = cur[part]
    else:
        print("")
        sys.exit(0)
if cur is None:
    print("")
elif isinstance(cur, (dict, list)):
    print(json.dumps(cur, separators=(",", ":")))
else:
    print(cur)
PY
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
#   - sid is the opaque session id from the session cookie.
#   - HMAC-SHA256 is computed over the ASCII bytes of value_b64 + ":" + sid
#     (not the decoded random bytes) using the decoded key bytes.
#   - Output is value_b64 + "." + base64url(hmac_bytes), no padding.
#
# If either side ever changes the algorithm (e.g. to SHA-512), the
# value-encoding (raw bytes vs ASCII), or the key encoding (URL-safe
# base64 vs standard base64), this helper must be updated in lockstep.
sign_csrf_token() {
  signing_key_b64="$1"
  value_b64="$2"
  sid="$3"

  key_hex="$(printf '%s' "$signing_key_b64" \
    | openssl base64 -d -A \
    | xxd -p \
    | tr -d '\n')"
  if [ -z "$key_hex" ]; then
    printf 'sign_csrf_token: empty signing key (CSRF_SIGNING_KEY unset?)\n' >&2
    return 1
  fi

  hmac_hex="$(printf '%s:%s' "$value_b64" "$sid" \
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
  sid="$1"
  value="$(random_b64url)"
  sign_csrf_token "$CSRF_SIGNING_KEY" "$value" "$sid"
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
