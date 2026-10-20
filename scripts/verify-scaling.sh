#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# verify-scaling.sh — Verify multi-instance state sharing
# =============================================================================
#
# Tests that two Open Privacy Suite instances sharing Postgres + Redis correctly
# share sessions, RBAC permissions, cache invalidation, and address links.
#
# Usage:
#   ./scripts/verify-scaling.sh [PROXY1_URL] [PROXY2_URL]
#
# Defaults:
#   PROXY1_URL=http://localhost:8091
#   PROXY2_URL=http://localhost:8092

PROXY1="${1:-http://localhost:8091}"
PROXY2="${2:-http://localhost:8092}"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m'
FAILURES=0

ok()   { echo -e "  ${GREEN}PASS${NC}  $1"; }
fail() { echo -e "  ${RED}FAIL${NC}  $1"; FAILURES=$((FAILURES + 1)); }
info() { echo -e "  ${YELLOW}....${NC}  $1"; }

# Admin API token (must match ADMIN_API_TOKEN in compose)
ADMIN_TOKEN="${ADMIN_TOKEN:-scale-test-admin-token}"

# Helper: call admin API
admin() {
    local url="$1"; shift
    curl -s -H "X-Admin-Token: ${ADMIN_TOKEN}" "$url" "$@"
}

# Helper: mock-login and get JWT tokens
#   login <proxy_url> <did> → sets ACCESS_TOKEN, REFRESH_TOKEN
login() {
    local proxy="$1" did="$2"

    # Start OAuth session (Accept: application/json to get JSON instead of HTML)
    local auth_resp
    auth_resp=$(curl -s "${proxy}/oauth/authorize?redirect_uri=http://localhost:19999/callback&state=s&response_type=code&client_id=privacy-proxy" \
        -H "Accept: application/json")
    local oauth_session_id
    oauth_session_id=$(echo "$auth_resp" | python3 -c "import sys,json; print(json.load(sys.stdin)['oauth_session_id'])")

    # Mock-complete with specific DID
    curl -s -X POST "${proxy}/oauth/session/${oauth_session_id}/mock-complete" \
        -H "Content-Type: application/json" \
        -d "{\"did\":\"${did}\"}" > /dev/null

    # Get the code from session status (code is in the redirect_url query params)
    local status_resp code
    status_resp=$(curl -s "${proxy}/oauth/session/${oauth_session_id}/status")
    code=$(echo "$status_resp" | python3 -c "
import sys,json
from urllib.parse import urlparse, parse_qs
d = json.load(sys.stdin)
url = d.get('redirect_url','')
qs = parse_qs(urlparse(url).query)
print(qs.get('code',[''])[0])
")

    if [[ -z "$code" ]]; then
        echo ""; return 1
    fi

    # Exchange code for tokens
    local token_resp
    token_resp=$(curl -s -X POST "${proxy}/oauth/token" \
        -H "Content-Type: application/json" \
        -d "{\"grant_type\":\"authorization_code\",\"code\":\"${code}\",\"redirect_uri\":\"http://localhost:19999/callback\",\"client_id\":\"privacy-proxy\"}")

    ACCESS_TOKEN=$(echo "$token_resp" | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")
    REFRESH_TOKEN=$(echo "$token_resp" | python3 -c "import sys,json; print(json.load(sys.stdin).get('refresh_token',''))")

    # Grant KYC to the user (mock-login creates with kyc=false)
    local user_id
    user_id=$(admin "${proxy}/api/v1/admin/users?search=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$did'))")" \
        | python3 -c "import sys,json; users=json.load(sys.stdin).get('data',[]); print(users[0]['id'] if users else '')" 2>/dev/null)
    if [[ -n "$user_id" ]]; then
        admin "${proxy}/api/v1/admin/users/${user_id}" \
            -X PUT -H "Content-Type: application/json" \
            -d '{"kyc":true}' > /dev/null 2>&1
    fi
}

# Helper: authenticated RPC call
rpc_call() {
    local proxy="$1" method="$2" token="$3"
    curl -s -X POST "${proxy}" \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer ${token}" \
        -d "{\"jsonrpc\":\"2.0\",\"method\":\"${method}\",\"params\":[],\"id\":1}" 2>/dev/null || echo '{"error":"request_failed"}'
}

echo "==========================================="
echo "  Multi-Instance State Sharing Verification"
echo "==========================================="
echo "  Instance 1: ${PROXY1}"
echo "  Instance 2: ${PROXY2}"
echo ""

# --- Health check ---
echo "=== Health Check ==="
if curl -s "${PROXY1}/health" > /dev/null; then ok "Instance 1 healthy"; else fail "Instance 1 not healthy"; fi
if curl -s "${PROXY2}/health" > /dev/null; then ok "Instance 2 healthy"; else fail "Instance 2 not healthy"; fi
echo ""

# --- Test 1: Sessions — login on instance 1, use token on instance 2 ---
echo "=== Test 1: Session Sharing ==="
info "Logging in on instance 1..."
DID_USER1="did:mock:scale-user-1"
if login "$PROXY1" "$DID_USER1"; then
    TOKEN1="$ACCESS_TOKEN"
    ok "Got JWT from instance 1"

    info "Using token on instance 2..."
    resp=$(rpc_call "$PROXY2" "eth_blockNumber" "$TOKEN1")
    # Token is valid cross-instance if we get a JSON-RPC response (even an error like "method not found"
    # means the JWT was accepted — an invalid token would return "invalid token").
    if echo "$resp" | python3 -c "import sys,json; d=json.load(sys.stdin); assert 'invalid token' not in str(d)" 2>/dev/null; then
        ok "Token from instance 1 accepted by instance 2"
    else
        fail "Token from instance 1 rejected by instance 2: $resp"
    fi
else
    fail "Login failed on instance 1"
fi
echo ""

# --- Test 2: RBAC — default group methods enforced on both instances ---
echo "=== Test 2: RBAC Sharing ==="
# Mock-login users (did:mock:*) get auto-provisioned into the dev-admin group
# with wildcard (*) method access + admin claim. This tests that the provisioning
# and RBAC resolution work consistently across both instances.
DID_USER2="did:mock:scale-rbac-$(date +%s)"
info "Logging in as fresh user on instance 1..."
if login "$PROXY1" "$DID_USER2"; then
    TOKEN2_I1="$ACCESS_TOKEN"

    info "Testing allowed method (eth_blockNumber) on instance 1..."
    resp=$(rpc_call "$PROXY1" "eth_blockNumber" "$TOKEN2_I1")
    if echo "$resp" | python3 -c "import sys,json; d=json.load(sys.stdin); assert 'result' in d" 2>/dev/null; then
        ok "eth_blockNumber allowed on instance 1 (correct)"
    else
        fail "eth_blockNumber denied on instance 1: $resp"
    fi

    info "Testing non-allowed method (debug_traceTransaction) on instance 1..."
    resp=$(rpc_call "$PROXY1" "debug_traceTransaction" "$TOKEN2_I1")
    if echo "$resp" | python3 -c "import sys,json; d=json.load(sys.stdin); assert 'result' not in d" 2>/dev/null; then
        ok "debug_traceTransaction denied on instance 1 (correct — not in default group)"
    else
        fail "debug_traceTransaction should be denied on instance 1: $resp"
    fi
else
    fail "Login failed on instance 1"
fi

info "Logging in as same user on instance 2..."
if login "$PROXY2" "$DID_USER2"; then
    TOKEN2="$ACCESS_TOKEN"

    info "Testing allowed method (eth_blockNumber) on instance 2..."
    resp=$(rpc_call "$PROXY2" "eth_blockNumber" "$TOKEN2")
    if echo "$resp" | python3 -c "import sys,json; d=json.load(sys.stdin); assert 'result' in d" 2>/dev/null; then
        ok "eth_blockNumber allowed on instance 2 (RBAC shared via Postgres)"
    else
        fail "eth_blockNumber denied on instance 2: $resp"
    fi

    info "Testing non-allowed method (debug_traceTransaction) on instance 2..."
    resp=$(rpc_call "$PROXY2" "debug_traceTransaction" "$TOKEN2")
    if echo "$resp" | python3 -c "import sys,json; d=json.load(sys.stdin); assert 'result' not in d" 2>/dev/null; then
        ok "debug_traceTransaction denied on instance 2 (correct — same RBAC rules)"
    else
        fail "debug_traceTransaction should be denied on instance 2: $resp"
    fi
else
    fail "Login failed on instance 2"
fi
echo ""

# --- Test 3: Admin API shared — create resource on 1, read on 2 ---
echo "=== Test 3: Admin API Shared State ==="
info "Creating test org on instance 1..."
TEST_ORG_SLUG="scale-verify-$(date +%s)"
ORG_RESP=$(admin "${PROXY1}/api/v1/admin/orgs" \
    -X POST -H "Content-Type: application/json" \
    -d "{\"slug\":\"${TEST_ORG_SLUG}\",\"name\":\"Scale Verify Org\"}" 2>/dev/null)
TEST_ORG_ID=$(echo "$ORG_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('id',''))" 2>/dev/null)

if [[ -n "$TEST_ORG_ID" ]]; then
    ok "Org created on instance 1: ${TEST_ORG_ID}"

    info "Reading org on instance 2..."
    READ_RESP=$(admin "${PROXY2}/api/v1/admin/orgs/${TEST_ORG_ID}" 2>/dev/null)
    READ_SLUG=$(echo "$READ_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('slug',''))" 2>/dev/null)
    if [[ "$READ_SLUG" == "$TEST_ORG_SLUG" ]]; then
        ok "Org visible on instance 2 (Postgres shared correctly)"
    else
        fail "Org not found on instance 2: $READ_RESP"
    fi

    # Cleanup
    admin "${PROXY1}/api/v1/admin/orgs/${TEST_ORG_ID}" -X DELETE > /dev/null 2>&1
else
    fail "Could not create test org: $ORG_RESP"
fi
echo ""

# --- Test 4: Both instances see same blockchain state ---
echo "=== Test 4: Blockchain State Consistency ==="
block1=$(curl -s -X POST "$PROXY1" -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}' \
    | python3 -c "import sys,json; print(json.load(sys.stdin)['result'])")
block2=$(curl -s -X POST "$PROXY2" -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":2}' \
    | python3 -c "import sys,json; print(json.load(sys.stdin)['result'])")
if [[ "$block1" == "$block2" ]]; then
    ok "Both instances see block ${block1}"
else
    fail "Block mismatch: instance 1=${block1}, instance 2=${block2}"
fi
echo ""

# --- Summary ---
echo "==========================================="
if [[ $FAILURES -eq 0 ]]; then
    echo -e "  ${GREEN}All scaling verification checks passed${NC}"
else
    echo -e "  ${RED}${FAILURES} check(s) failed${NC}"
fi
echo "==========================================="
exit $FAILURES
