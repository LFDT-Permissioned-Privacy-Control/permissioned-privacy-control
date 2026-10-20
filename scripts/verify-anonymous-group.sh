#!/usr/bin/env bash
# verify-anonymous-group.sh — RD-870 manual test §3.3 automation.
#
# Asserts that the anonymous first-class group invariants hold:
#   1. The anonymous org appears in /api/v1/admin/orgs?include_system=true
#      (and is hidden by default).
#   2. Super-admin can update the anonymous group's group_access.
#   3. JWT-admin (anything other than super-admin) is forbidden from doing
#      the same — system rows are super-admin-only.
#   4. An unauthenticated request through the proxy succeeds for methods
#      listed in the anonymous group's allowed_methods, and is denied
#      (404 — opaque RBAC denial) for methods that are not.
#
# Requires the privacy stack running at $PROXY_URL (defaults to localhost:8080)
# and the super-admin token in $ADMIN_API_TOKEN.
#
# Usage:
#   ADMIN_API_TOKEN=$(docker exec privacy-proxy-proxy-backend-1 \
#     sh -c 'echo $ADMIN_API_TOKEN') ./scripts/verify-anonymous-group.sh
set -euo pipefail

PROXY_URL="${PROXY_URL:-http://localhost:8080}"
ADMIN_TOKEN="${ADMIN_API_TOKEN:?ADMIN_API_TOKEN must be set}"

LOG=/tmp/verify-anonymous-group.log
: >"$LOG"

red() { printf '\033[0;31m%s\033[0m\n' "$*"; }
green() { printf '\033[0;32m%s\033[0m\n' "$*"; }
fail() { red "FAIL: $1"; echo "      see $LOG"; exit 1; }
ok() { green "OK:   $1"; }

# ----------------------------------------------------------------------------
# 1. Anonymous org is listed only when include_system=true
# ----------------------------------------------------------------------------
echo "==> Step 1: anonymous org is_system filtering" | tee -a "$LOG"

DEFAULT_ORGS=$(curl -s -H "X-Admin-Token: $ADMIN_TOKEN" \
  "$PROXY_URL/api/v1/admin/orgs?limit=1000")
echo "$DEFAULT_ORGS" >>"$LOG"
if echo "$DEFAULT_ORGS" | python3 -c \
  'import json,sys; orgs=json.load(sys.stdin)["data"]; sys.exit(0 if not any(o["slug"]=="anonymous" for o in orgs) else 1)'
then
  ok "default listing hides anonymous org"
else
  fail "default listing leaked anonymous org (RD-870 regression)"
fi

WITH_SYSTEM=$(curl -s -H "X-Admin-Token: $ADMIN_TOKEN" \
  "$PROXY_URL/api/v1/admin/orgs?limit=1000&include_system=true")
echo "$WITH_SYSTEM" >>"$LOG"
if echo "$WITH_SYSTEM" | python3 -c \
  'import json,sys; orgs=json.load(sys.stdin)["data"]; sys.exit(0 if any(o["slug"]=="anonymous" for o in orgs) else 1)'
then
  ok "include_system=true exposes anonymous org"
else
  fail "include_system=true did not include anonymous org"
fi

ANON_ORG_ID=$(echo "$WITH_SYSTEM" | python3 -c \
  'import json,sys; orgs=json.load(sys.stdin)["data"]; print([o["id"] for o in orgs if o["slug"]=="anonymous"][0])')
ANON_GROUPS=$(curl -s -H "X-Admin-Token: $ADMIN_TOKEN" \
  "$PROXY_URL/api/v1/admin/orgs/$ANON_ORG_ID/groups")
echo "$ANON_GROUPS" >>"$LOG"
ANON_GROUP_ID=$(echo "$ANON_GROUPS" | python3 -c \
  'import json,sys; data=json.load(sys.stdin)["data"]; print([e["group"]["id"] for e in data if e["group"]["slug"]=="anonymous"][0])')

# ----------------------------------------------------------------------------
# 2. Super-admin can PUT group_access on the anonymous group
# ----------------------------------------------------------------------------
echo "==> Step 2: super-admin can update anonymous group_access" | tee -a "$LOG"
SUPER_RESP=$(curl -s -o /dev/null -w '%{http_code}' \
  -X PUT \
  -H "X-Admin-Token: $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"allowed_methods":["eth_blockNumber","eth_chainId","net_version"],"claims":[]}' \
  "$PROXY_URL/api/v1/admin/orgs/$ANON_ORG_ID/groups/$ANON_GROUP_ID/access")
echo "super-admin PUT /access -> $SUPER_RESP" >>"$LOG"
[ "$SUPER_RESP" = "200" ] || fail "super-admin PUT returned $SUPER_RESP, expected 200"
ok "super-admin can update anonymous group_access"

# ----------------------------------------------------------------------------
# 3. JWT-admin (no X-Admin-Token) is forbidden
# ----------------------------------------------------------------------------
echo "==> Step 3: JWT admin is rejected on anonymous-group writes" | tee -a "$LOG"
# Issue a JWT for a mock user. The proxy's mock-login flow accepts any DID.
SESSION_ID=$(curl -s -X POST "$PROXY_URL/auth/request" \
  -H "Content-Type: application/json" | python3 -c 'import json,sys;print(json.load(sys.stdin)["session_id"])')
JWT_RESP=$(curl -s -X POST "$PROXY_URL/auth/verify" \
  -H "Content-Type: application/json" \
  -d "{\"session_id\":\"$SESSION_ID\",\"jwz_token\":\"mock.did:privado:verify_anon_$$\"}")
echo "$JWT_RESP" >>"$LOG"
JWT=$(echo "$JWT_RESP" | python3 -c 'import json,sys;print(json.load(sys.stdin)["access_token"])')

# Attempt PUT with only the JWT. The localhost-only middleware lets the
# request reach adminAuth, which rejects non-super-admin writes on system
# rows (admin_rbac_group.go updateGroupAccess + the orgScopingMiddleware
# block on system orgs).
JWT_RESP_CODE=$(curl -s -o /dev/null -w '%{http_code}' \
  -X PUT \
  -H "Authorization: Bearer $JWT" \
  -H "Content-Type: application/json" \
  -d '{"allowed_methods":["eth_blockNumber"],"claims":[]}' \
  "$PROXY_URL/api/v1/admin/orgs/$ANON_ORG_ID/groups/$ANON_GROUP_ID/access")
echo "jwt PUT /access -> $JWT_RESP_CODE" >>"$LOG"
case "$JWT_RESP_CODE" in
  401|403)
    ok "JWT-only write on anonymous group is rejected ($JWT_RESP_CODE)"
    ;;
  *)
    fail "JWT-only write returned $JWT_RESP_CODE — expected 401 or 403"
    ;;
esac

# ----------------------------------------------------------------------------
# 4. Anonymous RPC traffic respects the allowlist
# ----------------------------------------------------------------------------
echo "==> Step 4: anonymous RPC honors allowlist" | tee -a "$LOG"

# Allowed (eth_blockNumber set above)
ALLOWED_RESP=$(curl -s -o /dev/null -w '%{http_code}' \
  -X POST "$PROXY_URL/" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}')
echo "anon eth_blockNumber -> $ALLOWED_RESP" >>"$LOG"
[ "$ALLOWED_RESP" = "200" ] || fail "anon eth_blockNumber returned $ALLOWED_RESP, expected 200"
ok "anonymous request: eth_blockNumber allowed (200)"

# Denied (eth_sendTransaction not in the list)
DENIED_RESP=$(curl -s -o /dev/null -w '%{http_code}' \
  -X POST "$PROXY_URL/" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"eth_sendTransaction","params":[{}],"id":1}')
echo "anon eth_sendTransaction -> $DENIED_RESP" >>"$LOG"
case "$DENIED_RESP" in
  401|404)
    # Opaque-404 is the standard denial; 401 is also acceptable (auth-required
    # signal). 403 would be a regression of the opaque-denial fix in a73efec.
    ok "anonymous request: eth_sendTransaction denied ($DENIED_RESP)"
    ;;
  *)
    fail "anon eth_sendTransaction returned $DENIED_RESP — expected 401 or 404"
    ;;
esac

green "All RD-870 anonymous-group invariants hold."
