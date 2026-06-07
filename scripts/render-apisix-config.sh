#!/usr/bin/env sh
# render-apisix-config.sh — render api-gateway/apisix.yaml.local from the
# tracked template, substituting required env vars and refusing to emit
# any line that still contains a REPLACE_ME_ placeholder.
#
# Why:
#   The tracked apisix.yaml.template is the source of truth, but the
#   runtime route file MUST embed real secrets (gateway client secret +
#   CSRF signing key). Compose mounts the rendered .local file, which is
#   gitignored. The startup guard at the end exits non-zero if any
#   REPLACE_ME_ sneaks past — so a developer who forgets to export the
#   env vars gets an immediate, loud failure instead of a silently-broken
#   gateway that accepts placeholder secrets at runtime.
#
# Usage:
#   GATEWAY_CLIENT_SECRET=... CSRF_SIGNING_KEY=... ./scripts/render-apisix-config.sh
#
# Then bring the stack up; compose.yaml mounts apisix.yaml.local.

set -eu

cd "$(dirname "$0")/.."

TEMPLATE="api-gateway/apisix.yaml.template"
RENDERED="api-gateway/apisix.yaml.local"

if [ ! -f "$TEMPLATE" ]; then
  printf 'fatal: template not found at %s\n' "$TEMPLATE" >&2
  exit 2
fi

# Required env vars. We check both before substitution so the error is
# crisp; envsubst would otherwise silently render an empty placeholder.
APISIX_IDP_TOKEN_URL="${APISIX_IDP_TOKEN_URL:-http://keycloak:8080/realms/oidc-reference/protocol/openid-connect/token}"
export APISIX_IDP_TOKEN_URL

# The gateway's confidential client id. Default is the local Keycloak client
# name; override (alongside the Auth Service's GATEWAY_CLIENT_ID) when the IdP
# assigns a different id. The gateway authenticates AS this client for the
# /internal/refresh client-credentials call.
GATEWAY_CLIENT_ID="${GATEWAY_CLIENT_ID:-oidc-reference-api-gateway}"
export GATEWAY_CLIENT_ID

missing=
for var in GATEWAY_CLIENT_SECRET CSRF_SIGNING_KEY APISIX_IDP_TOKEN_URL GATEWAY_CLIENT_ID; do
  eval "value=\${$var:-}"
  if [ -z "$value" ]; then
    missing="$missing $var"
  fi
done
if [ -n "$missing" ]; then
  printf 'fatal: required env vars are unset or empty:%s\n' "$missing" >&2
  printf 'hint: source a .env or export them inline, e.g.\n' >&2
  printf '  GATEWAY_CLIENT_SECRET=LOCAL_DEV_GATEWAY_CLIENT_SECRET__CHANGE_BEFORE_DEPLOY \\\n' >&2
  printf '  CSRF_SIGNING_KEY=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA= \\\n' >&2
  printf '    ./scripts/render-apisix-config.sh\n' >&2
  exit 2
fi

# envsubst is the cleanest tool: substitutes ${VAR} and $VAR only,
# leaves Lua/YAML alone. Restrict it to the names we expect so a stray
# $foo in a comment doesn't get clobbered by the host env.
if ! command -v envsubst >/dev/null 2>&1; then
  printf 'fatal: envsubst not found (install gettext / apt install gettext-base)\n' >&2
  exit 2
fi

# shellcheck disable=SC2016
envsubst '${GATEWAY_CLIENT_SECRET} ${CSRF_SIGNING_KEY} ${APISIX_IDP_TOKEN_URL} ${GATEWAY_CLIENT_ID}' \
  < "$TEMPLATE" > "$RENDERED"

# Startup guard: a REPLACE_ME_ in the rendered file means an unsubstituted
# placeholder. Refuse to leave a foot-gun for the next compose up. Skip
# YAML comment lines (first non-whitespace char is #) — the template's own
# documentation block mentions the word REPLACE_ME_ explaining what the
# guard does, and we don't want to false-positive on that.
leftovers="$(grep -nE '^[[:space:]]*[^#[:space:]].*REPLACE_ME_' "$RENDERED" 2>/dev/null || true)"
if [ -n "$leftovers" ]; then
  printf 'fatal: rendered file still contains REPLACE_ME_ placeholders:\n%s\n' \
    "$leftovers" >&2
  rm -f "$RENDERED"
  exit 3
fi

# Also refuse empty values that envsubst may have collapsed into nothing
# for keys we know must be non-empty.
for key in gateway_client_secret cookie_signing_key idp_token_url gateway_client_id; do
  # YAML key followed by zero-or-more spaces and then end-of-line is
  # the empty-string footgun. Real values are non-empty.
  if grep -E "^[[:space:]]+${key}:[[:space:]]*$" "$RENDERED" >/dev/null 2>&1; then
    printf 'fatal: rendered file has empty value for %s\n' "$key" >&2
    rm -f "$RENDERED"
    exit 3
  fi
done

printf 'rendered %s -> %s\n' "$TEMPLATE" "$RENDERED"
