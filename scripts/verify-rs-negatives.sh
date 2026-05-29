#!/usr/bin/env sh
# verify-rs-negatives.sh — assert RS rejects invalid JWTs, including access
# tokens that do NOT carry the oidc-reference-api audience.
#
# Strategy:
#   1. Run the RS decoder negative suite. This is the isolated audience check:
#      the test signs with the trusted in-memory key and varies only aud/missing
#      aud, so a failure proves the audience validator is broken.
#   2. Optional live smoke: send a locally minted foreign-token to a running RS
#      and assert it returns 401 with application/problem+json.
#
# The live smoke is intentionally not treated as isolated audience evidence:
# a JWT signed with an unrecognised private key fails before audience validation
# is reached. The unit suite is the audience proof.
#
# Dependencies: openssl (RSA key + sign), node (base64url + JSON manipulation).
# Both are present in the standard dev environment.
#
# Env vars (same conventions as verify-cross-service.sh):
#   RS_JOBS_URL          — full URL of the protected POST endpoint
#                          default: http://localhost:8082/api/jobs
#   EXPECTED_AUDIENCE    — the audience the RS actually requires (informational)
#                          default: oidc-reference-api
#
# Gated by env var so static-only CI does not need a live RS:
#   RUN_LIVE_RS_NEGATIVES=1

set -eu

cd "$(dirname "$0")/.."

fail() {
  printf 'rs-negatives verification failed: %s\n' "$1" >&2
  exit 1
}

# ---------------------------------------------------------------------------
# Static phase: assert the RS application.yml declares the expected audience
# ---------------------------------------------------------------------------

audience_line="$(grep -r 'oidc-reference-api' \
  backend-resource-server/src/main/resources/ \
  2>/dev/null || true)"
[ -n "$audience_line" ] || \
  fail "could not find 'oidc-reference-api' audience in RS application config"

echo "static audience config check passed"

echo "running isolated RS JWT negative tests"
(cd backend-resource-server && ./mvnw -Dtest=JwtDecoderNegativeTest test)
echo "isolated RS JWT negative tests passed"

# ---------------------------------------------------------------------------
# Live phase (opt-in)
# ---------------------------------------------------------------------------

if [ "${RUN_LIVE_RS_NEGATIVES:-0}" != "1" ]; then
  echo "rs-negatives live check skipped (set RUN_LIVE_RS_NEGATIVES=1 to enable)"
  exit 0
fi

: "${RS_JOBS_URL:=http://localhost:8082/api/jobs}"
expected_audience="${EXPECTED_AUDIENCE:-oidc-reference-api}"

# Require tooling
command -v openssl >/dev/null 2>&1 || fail "openssl not found in PATH"
command -v node    >/dev/null 2>&1 || fail "node not found in PATH"

# ---------------------------------------------------------------------------
# Mint a self-signed JWT with a foreign (unrecognised) RSA-256 key.
# Audience is explicitly set to a value that does NOT include the required
# audience, so even if the RS were to skip signature verification it would
# still reject on audience grounds.
# ---------------------------------------------------------------------------

tmp_dir="$(mktemp -d)"
trap 'rm -rf -- "$tmp_dir"' EXIT INT TERM

# Generate a one-shot RSA key pair (2048-bit, throwaway).
openssl genrsa -out "$tmp_dir/private.pem" 2048 2>/dev/null
openssl rsa -in "$tmp_dir/private.pem" -pubout -out "$tmp_dir/public.pem" 2>/dev/null

# Build and sign the JWT in Node so we stay POSIX-portable (no Bash 4 arrays
# needed, no base64url dependency beyond what Node ships).
wrong_aud_token="$(node - "$tmp_dir/private.pem" "$expected_audience" <<'NODESCRIPT'
const fs   = require('fs');
const crypto = require('crypto');

const keyFile = process.argv[2];
const correctAud = process.argv[3];

const pem = fs.readFileSync(keyFile, 'utf8');

// Build header + payload
const header  = { alg: 'RS256', typ: 'JWT', kid: 'foreign-key-smoke-test' };
const now     = Math.floor(Date.now() / 1000);
const payload = {
  iss: 'https://smoke-test.local/realms/foreign',
  sub: 'smoke-test-subject',
  // Deliberately wrong audience — does NOT include the required value
  aud: 'not-' + correctAud,
  iat: now,
  exp: now + 300,
};

function b64url(str) {
  return Buffer.from(str).toString('base64')
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

const headerB64  = b64url(JSON.stringify(header));
const payloadB64 = b64url(JSON.stringify(payload));
const signingInput = headerB64 + '.' + payloadB64;

const sign = crypto.createSign('RSA-SHA256');
sign.update(signingInput);
sign.end();
const sig = sign.sign(pem, 'base64')
  .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

process.stdout.write(signingInput + '.' + sig);
NODESCRIPT
)"

[ -n "$wrong_aud_token" ] || fail "failed to mint wrong-audience JWT"

# ---------------------------------------------------------------------------
# Call the RS protected endpoint with the wrong-audience token
# ---------------------------------------------------------------------------

http_status="$(curl -o /dev/null -s -w '%{http_code}' \
  -X POST \
  -H "Authorization: Bearer $wrong_aud_token" \
  "$RS_JOBS_URL")"

if [ "$http_status" != "401" ]; then
  fail "expected 401 from RS for foreign invalid JWT but got HTTP $http_status (RS_JOBS_URL=$RS_JOBS_URL)"
fi

# ---------------------------------------------------------------------------
# Assert Content-Type is application/problem+json on the 401 response
# ---------------------------------------------------------------------------

content_type="$(curl -o /dev/null -s \
  -X POST \
  -H "Authorization: Bearer $wrong_aud_token" \
  -w '%{content_type}' \
  "$RS_JOBS_URL")"

# Extract the MIME type part before any ';' separator
mime_type="${content_type%%;*}"

if [ "$mime_type" = "application/problem+json" ]; then
  echo "foreign-token rejection Content-Type check passed (application/problem+json)"
else
  fail "expected application/problem+json on 401 but got ${content_type:-<empty>}"
fi

echo "foreign-token live rejection smoke passed"
