#!/usr/bin/env bash
# Proof harness for the DISTRIBUTED RefreshLock (DistributedRefreshKeyLock).
#
# Assumes the two-replica stack is already up (compose.distributed-lock.yml):
#   replica 1 -> 127.0.0.1:8091   replica 2 -> 127.0.0.1:8092   shared Valkey.
#
# Seeds a real session (ROPC-issued access+refresh+id tokens, access token put
# INTO the refresh window), then fires TWO concurrent POST /internal/resolve —
# one at each replica — for the SAME sid. With the distributed lock, the two
# collapse to ONE upstream refresh: both return 200 (the loser re-reads the
# rotated session), no invalid_grant. With the in-process lock the two replicas
# do not coordinate, so a real overlap makes Keycloak's reuse detection reject
# the second refresh -> 409 -> the cross-instance logout the lock exists to fix.
#
# Usage:  bash scripts/e2e-distributed-lock.sh [TRIALS]   (default 1)
# Container exec auto-detects docker vs podman (override: CONTAINER_RUNTIME).
set -u

KC=http://localhost:8080
REALM=oidc-reference
TOKEN_URL="$KC/realms/$REALM/protocol/openid-connect/token"
ADMIN_BASE="$KC/admin/realms/$REALM"
AUTH_SECRET="${AUTH_CLIENT_SECRET:-LOCAL_DEV_AUTH_CLIENT_SECRET__CHANGE_BEFORE_DEPLOY}"
GW_SECRET="${GATEWAY_CLIENT_SECRET:-LOCAL_DEV_GATEWAY_CLIENT_SECRET__CHANGE_BEFORE_DEPLOY}"
R1="${R1:-http://127.0.0.1:8091}"
R2="${R2:-http://127.0.0.1:8092}"
VALKEY="${VALKEY_CONTAINER:-oidc-reference-valkey-1}"
TRIALS="${1:-1}"

# Container runtime: the two-replica stack may be brought up under Docker or
# Podman, so detect which one is actually running this harness's Valkey and
# drive `exec` through it. Override with CONTAINER_RUNTIME=docker|podman.
detect_runtime() {
  if [ -n "${CONTAINER_RUNTIME:-}" ]; then printf '%s\n' "$CONTAINER_RUNTIME"; return; fi
  # Prefer the runtime that actually holds the target container.
  for rt in docker podman; do
    command -v "$rt" >/dev/null 2>&1 || continue
    if "$rt" ps --format '{{.Names}}' 2>/dev/null | grep -qx "$VALKEY"; then
      printf '%s\n' "$rt"; return
    fi
  done
  # Otherwise the first runtime with a reachable engine.
  for rt in docker podman; do
    command -v "$rt" >/dev/null 2>&1 || continue
    if "$rt" info >/dev/null 2>&1; then printf '%s\n' "$rt"; return; fi
  done
  echo "FATAL: no usable container runtime (docker or podman) found" >&2
  exit 1
}
RUNTIME="$(detect_runtime)"
echo "== container runtime: $RUNTIME (override with CONTAINER_RUNTIME) =="

jget() { python3 -c 'import json,sys; print(json.load(sys.stdin).get(sys.argv[1],""))' "$1"; }
decode_claim() {  # $1 jwt  $2 claim
  python3 - "$1" "$2" <<'PY'
import sys,json,base64
p=sys.argv[1].split('.')[1]; p+='='*(-len(p)%4)
print(json.loads(base64.urlsafe_b64decode(p)).get(sys.argv[2],""))
PY
}

echo "== waiting for both replicas (=, 401 from /auth/me means the app is up) =="
for url in "$R1" "$R2"; do
  for _ in $(seq 1 60); do
    code=$(curl -s -o /dev/null -w '%{http_code}' -H 'Accept: application/json' "$url/auth/me")
    [ "$code" = "401" ] && break
    sleep 2
  done
  echo "  $url/auth/me -> $code"
done

echo "== enabling direct grant on $REALM/oidc-reference-auth (runtime only, to seed real tokens) =="
ADMIN=$(curl -s "$KC/realms/master/protocol/openid-connect/token" \
  -d grant_type=password -d client_id=admin-cli -d username=admin -d password=admin | jget access_token)
[ -n "$ADMIN" ] || { echo "FATAL: no admin token"; exit 1; }
CID=$(curl -s -H "Authorization: Bearer $ADMIN" "$ADMIN_BASE/clients?clientId=oidc-reference-auth" \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)[0]["id"])')
curl -s -X PUT -H "Authorization: Bearer $ADMIN" -H 'Content-Type: application/json' \
  "$ADMIN_BASE/clients/$CID" -d '{"directAccessGrantsEnabled":true}' -o /dev/null -w "  patch client: %{http_code}\n"

echo "== minting the gateway client-credentials token (CC bearer for /internal/resolve) =="
GWTOK=$(curl -s -d grant_type=client_credentials -d client_id=oidc-reference-api-gateway \
  --data-urlencode "client_secret=$GW_SECRET" "$TOKEN_URL" | jget access_token)
[ -n "$GWTOK" ] || { echo "FATAL: no gateway CC token"; exit 1; }
echo "  gateway CC aud: $(decode_claim "$GWTOK" aud)"

pass=0; fail=0; conflict=0
for trial in $(seq 1 "$TRIALS"); do
  # --- seed a fresh real session ---------------------------------------------
  ROPC=$(curl -s "$TOKEN_URL" -d grant_type=password -d client_id=oidc-reference-auth \
    --data-urlencode "client_secret=$AUTH_SECRET" -d username=alice -d password=alice -d scope=openid)
  AT=$(echo "$ROPC" | jget access_token); RT=$(echo "$ROPC" | jget refresh_token); IT=$(echo "$ROPC" | jget id_token)
  [ -n "$RT" ] || { echo "FATAL: ROPC produced no refresh token: $ROPC"; exit 1; }
  SUB=$(decode_claim "$IT" sub)
  SID="dlock-$trial-$RANDOM$RANDOM"

  AT="$AT" RT="$RT" IT="$IT" SUB="$SUB" python3 - > /tmp/dlock-sess.json <<'PY'
import os, json, datetime
now = datetime.datetime.now(datetime.timezone.utc)
iso = lambda d: d.strftime('%Y-%m-%dT%H:%M:%SZ')
print(json.dumps({
  "access_token": os.environ["AT"],
  "refresh_token": os.environ["RT"],
  "id_token": os.environ["IT"],
  # access token already INSIDE the 60s refresh window -> resolve will refresh.
  "access_token_expires_at": iso(now + datetime.timedelta(seconds=10)),
  "refresh_token_expires_at": iso(now + datetime.timedelta(seconds=1800)),
  "created_at": iso(now),
  "absolute_expires_at": iso(now + datetime.timedelta(hours=8)),
  "claims": {"sub": os.environ["SUB"], "preferred_username": "alice", "roles": ["user"]}
}))
PY
  "$RUNTIME" exec -i "$VALKEY" valkey-cli -x SET "sess:$SID" < /tmp/dlock-sess.json >/dev/null
  "$RUNTIME" exec "$VALKEY" valkey-cli EXPIRE "sess:$SID" 1800 >/dev/null
  # The real /auth/callback writes the idp_sid index; the rotation's repoint
  # swap-if-present gates on it, so seed it too or rotate() fails closed — which
  # is NOT a lock outcome. idp_sid:{idpSid} is a SET of local sids (one OP
  # session can back several local sessions); SADD it as a set so the rotation's
  # SISMEMBER-gated swap does not hit WRONGTYPE on a string.
  IDP_SID=$(decode_claim "$IT" sid); [ -n "$IDP_SID" ] || IDP_SID=$(decode_claim "$AT" sid)
  if [ -n "$IDP_SID" ]; then
    "$RUNTIME" exec "$VALKEY" valkey-cli SADD "idp_sid:$IDP_SID" "$SID" >/dev/null
    "$RUNTIME" exec "$VALKEY" valkey-cli EXPIRE "idp_sid:$IDP_SID" 1800 >/dev/null
  fi

  # --- fire two concurrent resolves, one per replica -------------------------
  body="{\"sid\":\"$SID\"}"
  curl -s -o /tmp/dlock-r1.body -w '%{http_code}' -X POST "$R1/internal/resolve" \
    -H "Authorization: Bearer $GWTOK" -H 'Content-Type: application/json' -d "$body" > /tmp/dlock-r1.code &
  curl -s -o /tmp/dlock-r2.body -w '%{http_code}' -X POST "$R2/internal/resolve" \
    -H "Authorization: Bearer $GWTOK" -H 'Content-Type: application/json' -d "$body" > /tmp/dlock-r2.code &
  wait
  c1=$(cat /tmp/dlock-r1.code); c2=$(cat /tmp/dlock-r2.code)

  status="?"
  if [ "$c1" = "200" ] && [ "$c2" = "200" ]; then status="BOTH-200 (collapsed to one refresh)"; pass=$((pass+1));
  elif [ "$c1" = "409" ] || [ "$c2" = "409" ]; then status="409 invalid_grant (cross-instance reuse — NO shared lock)"; conflict=$((conflict+1));
  else status="unexpected"; fail=$((fail+1)); fi
  printf 'trial %s: replica1=%s replica2=%s -> %s\n' "$trial" "$c1" "$c2" "$status"
done

echo "== summary: both-200=$pass  409-conflict=$conflict  other=$fail (trials=$TRIALS) =="
