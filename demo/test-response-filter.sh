#!/bin/bash
# =============================================================================
# RESPONSE FILTER TEST: eth_getTransactionByHash non-participant returns null
# =============================================================================
#
# Tests PR #46 checkbox #3:
#   "Link an ETH address and verify eth_getTransactionByHash returns null for
#    non-participant txs"
#
# SCENARIO:
#   1. Alice sends ETH directly to Bob on Anvil
#   2. Charlie authenticates and links his address
#      - Charlie is NOT involved in the transaction
#      - Charlie queries the tx hash through the proxy → expects null
#   3. Alice authenticates and links her address
#      - Alice IS the sender ('from') in the transaction
#      - Alice queries the same tx hash → expects full transaction object
#   4. Bob authenticates and links his address
#      - Bob IS the recipient ('to') in the transaction
#      - Bob queries the same tx hash → expects full transaction object
#
# WHAT IS BEING TESTED:
#   The response-level privacy filter in the proxy. Even though all users
#   have access to call eth_getTransactionByHash (method allowed by their
#   group), only participants (from OR to) see the actual data.
#
# =============================================================================

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

PROXY_URL="${PROXY_URL:-http://localhost:8080}"
ANVIL_URL="${ANVIL_URL:-http://localhost:8545}"
API_URL="${PROXY_URL}/api/v1/admin"

# Anvil Account #0 — funder only (not linked to any test user)
FUNDER_KEY="0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
FUNDER_ADDR="0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"

# A 65-byte mock signature (accepted when MOCK_SIGNATURES=true)
MOCK_SIG="0xabababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababab"

TIMESTAMP=$(date +%s)

# Generate fresh random keys/addresses each run to avoid "already linked" conflicts.
# Alice: sender of the test transaction.
ALICE_KEY="0x$(openssl rand -hex 32)"
ALICE_ADDR=$(cast wallet address --private-key "$ALICE_KEY" 2>/dev/null)
# Bob: recipient of the test transaction (random address, never sent a tx).
BOB_ADDR="0x$(openssl rand -hex 20)"
# Charlie: observer — random address not involved in any transaction.
CHARLIE_ADDR="0x$(openssl rand -hex 20)"

echo -e "${BLUE}=============================================${NC}"
echo -e "${BLUE}  RESPONSE FILTER TEST                       ${NC}"
echo -e "${BLUE}  eth_getTransactionByHash                   ${NC}"
echo -e "${BLUE}=============================================${NC}"
echo ""

# =============================================================================
# Helper: get JWT token via mock auth
# =============================================================================
get_jwt_token() {
    local user_did="$1"

    local auth_req_resp
    auth_req_resp=$(curl -s -X POST "${PROXY_URL}/auth/request" \
        -H "Content-Type: application/json")

    local session_id
    session_id=$(echo "$auth_req_resp" | jq -r '.session_id // empty')
    if [ -z "$session_id" ]; then
        echo ""
        return 1
    fi

    local verify_resp
    verify_resp=$(curl -s -X POST "${PROXY_URL}/auth/verify" \
        -H "Content-Type: application/json" \
        -d "{\"session_id\": \"${session_id}\", \"jwz_token\": \"mock.${user_did}\"}")

    echo "$verify_resp" | jq -r '.access_token // empty'
}

# =============================================================================
# Helper: setup user (auth + KYC + org/group + link address)
# Returns the JWT token; exports ORG_ID, GROUP_ID into environment.
# =============================================================================
setup_user() {
    local user_did="$1"
    local eth_addr="$2"
    local org_slug="$3"

    # Auth
    local token
    token=$(get_jwt_token "$user_did")
    if [ -z "$token" ]; then
        echo -e "${RED}ERROR: auth failed for $user_did${NC}" >&2
        return 1
    fi

    # Find user record and set KYC
    local users_resp
    users_resp=$(curl -s "${API_URL}/users?search=${user_did}")
    local user_db_id
    user_db_id=$(echo "$users_resp" | jq -r "(.data // [])[] | select(.external_id == \"${user_did}\") | .id")
    if [ -z "$user_db_id" ]; then
        echo -e "${RED}ERROR: user not found after auth: $user_did${NC}" >&2
        echo "  users response: $users_resp" >&2
        return 1
    fi

    curl -s -X PUT "${API_URL}/users/${user_db_id}" \
        -H "Content-Type: application/json" \
        -d '{"kyc": true}' > /dev/null

    # Create org
    local org_resp
    org_resp=$(curl -s -X POST "${API_URL}/orgs" \
        -H "Content-Type: application/json" \
        -d "{\"slug\": \"${org_slug}\", \"name\": \"Test Org ${org_slug}\"}")
    local org_id
    org_id=$(echo "$org_resp" | jq -r '.id // empty')
    if [ -z "$org_id" ]; then
        echo -e "${RED}ERROR: failed to create org: $org_resp${NC}" >&2
        return 1
    fi

    # Create group with eth_getTransactionByHash allowed
    local group_resp
    group_resp=$(curl -s -X POST "${API_URL}/orgs/${org_id}/groups" \
        -H "Content-Type: application/json" \
        -d '{"slug": "readers", "name": "Readers"}')
    local group_id
    group_id=$(echo "$group_resp" | jq -r '.id // empty')
    if [ -z "$group_id" ]; then
        echo -e "${RED}ERROR: failed to create group: $group_resp${NC}" >&2
        return 1
    fi

    curl -s -X PUT "${API_URL}/orgs/${org_id}/groups/${group_id}/access" \
        -H "Content-Type: application/json" \
        -d '{"claims": ["read"], "allowed_methods": ["eth_getTransactionByHash", "eth_blockNumber"]}' > /dev/null

    # Add user to test group
    curl -s -X POST "${API_URL}/users/${user_db_id}/memberships" \
        -H "Content-Type: application/json" \
        -d "{\"group_id\": \"${group_id}\"}" > /dev/null

    # Remove from ALL OTHER orgs AFTER adding to test group.
    # Mock auth auto-adds users to dev-admin-org on every auth call; removing
    # it last (with no subsequent re-auth) keeps the test org as the only membership.
    local memberships
    memberships=$(curl -s "${API_URL}/users/${user_db_id}/memberships")
    while IFS= read -r mid; do
        [ -n "$mid" ] && curl -s -X DELETE "${API_URL}/users/${user_db_id}/memberships/${mid}" > /dev/null
    done < <(echo "$memberships" | jq -r ".[] | select(.group.org_id != \"${org_id}\") | .membership.id // empty")

    # Link ETH address
    local challenge_resp
    challenge_resp=$(curl -s -X POST "${PROXY_URL}/api/v1/eth/link/challenge" \
        -H "Authorization: Bearer ${token}" \
        -H "Content-Type: application/json")
    local nonce
    nonce=$(echo "$challenge_resp" | jq -r '.nonce // empty')
    if [ -z "$nonce" ]; then
        echo -e "${RED}ERROR: challenge failed: $challenge_resp${NC}" >&2
        return 1
    fi

    local link_resp
    link_resp=$(curl -s -X POST "${PROXY_URL}/api/v1/eth/link/verify" \
        -H "Authorization: Bearer ${token}" \
        -H "Content-Type: application/json" \
        -d "{\"nonce\": \"${nonce}\", \"address\": \"${eth_addr}\", \"signature\": \"${MOCK_SIG}\"}")

    if echo "$link_resp" | jq -e '.error' > /dev/null 2>&1; then
        echo -e "${RED}ERROR: link failed: $link_resp${NC}" >&2
        return 1
    fi

    echo "$token"
}

# =============================================================================
# Step 1: Check services
# =============================================================================
echo -e "${YELLOW}Step 1: Checking services...${NC}"

if ! curl -s "${PROXY_URL}/health" > /dev/null 2>&1; then
    echo -e "${RED}ERROR: Open Privacy Suite not running at ${PROXY_URL}${NC}"
    echo "Start it with: docker-compose up -d"
    exit 1
fi

if ! curl -s "${ANVIL_URL}" -X POST -H "Content-Type: application/json" \
    --data '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}' > /dev/null 2>&1; then
    echo -e "${RED}ERROR: Anvil not running at ${ANVIL_URL}${NC}"
    exit 1
fi

if ! command -v cast &> /dev/null; then
    echo -e "${RED}ERROR: cast not found. Install Foundry first.${NC}"
    exit 1
fi

echo -e "${GREEN}✓ Services running${NC}"
echo ""

# =============================================================================
# Step 2: Fund Alice and send Alice→Bob transaction on Anvil
# =============================================================================
echo -e "${YELLOW}Step 2: Sending Alice→Bob transaction on Anvil...${NC}"
echo "  Alice address: $ALICE_ADDR (fresh random key)"
echo "  Charlie address: $CHARLIE_ADDR (fresh random address)"
echo ""

# Fund Alice from the funder account so she can send a tx
cast send \
    --private-key "$FUNDER_KEY" \
    --rpc-url "$ANVIL_URL" \
    --value 0.01ether \
    "$ALICE_ADDR" > /dev/null 2>&1

TX_HASH=$(cast send \
    --private-key "$ALICE_KEY" \
    --rpc-url "$ANVIL_URL" \
    --value 0.001ether \
    "$BOB_ADDR" \
    --json 2>/dev/null | jq -r '.transactionHash')

if [ -z "$TX_HASH" ] || [ "$TX_HASH" == "null" ]; then
    echo -e "${RED}ERROR: Failed to send transaction${NC}"
    exit 1
fi

echo -e "${GREEN}✓ Transaction sent: $TX_HASH${NC}"
echo "  From: $ALICE_ADDR"
echo "  To:   $BOB_ADDR"
echo "  Value: 0.001 ETH"
echo ""

# Verify tx exists on Anvil
TX_ON_ANVIL=$(cast tx "$TX_HASH" --rpc-url "$ANVIL_URL" --json 2>/dev/null | jq -r '.hash // empty')
if [ -z "$TX_ON_ANVIL" ]; then
    echo -e "${RED}ERROR: Transaction not found on Anvil${NC}"
    exit 1
fi
echo -e "${GREEN}✓ Transaction confirmed on Anvil${NC}"
echo ""

# =============================================================================
# Step 3: Setup Charlie (non-participant) and test
# =============================================================================
echo -e "${YELLOW}Step 3: Setting up Charlie (non-participant)...${NC}"
echo "  Charlie's address ($CHARLIE_ADDR) is NOT involved in the Alice→Bob tx."
echo ""

CHARLIE_DID="did:privado:test-response-filter-charlie-${TIMESTAMP}"
CHARLIE_TOKEN=$(setup_user "$CHARLIE_DID" "$CHARLIE_ADDR" "rf-charlie-${TIMESTAMP}")

if [ -z "$CHARLIE_TOKEN" ]; then
    echo -e "${RED}ERROR: Failed to setup Charlie${NC}"
    exit 1
fi

echo -e "${GREEN}✓ Charlie authenticated and linked to $CHARLIE_ADDR${NC}"
echo ""

echo -e "${YELLOW}  Charlie queries the Alice→Bob tx hash through the proxy...${NC}"
echo "  Expected: null (Charlie is not a participant)"
echo ""

CHARLIE_RESP=$(curl -s -X POST "${PROXY_URL}/" \
    -H "Authorization: Bearer ${CHARLIE_TOKEN}" \
    -H "Content-Type: application/json" \
    -d "{
        \"jsonrpc\": \"2.0\",
        \"method\": \"eth_getTransactionByHash\",
        \"params\": [\"${TX_HASH}\"],
        \"id\": 1
    }")

echo "Response:"
echo "$CHARLIE_RESP" | jq .
echo ""

CHARLIE_RESULT=$(echo "$CHARLIE_RESP" | jq -r '.result')
if [ "$CHARLIE_RESULT" == "null" ]; then
    echo -e "${GREEN}✓ Non-participant correctly receives null${NC}"
    CHARLIE_TEST_PASSED=true
else
    echo -e "${RED}SECURITY ISSUE: Non-participant received transaction data!${NC}"
    CHARLIE_TEST_PASSED=false
fi
echo ""

# =============================================================================
# Step 4: Setup Alice (participant) and test
# =============================================================================
echo -e "${YELLOW}Step 4: Setting up Alice (participant, sender)...${NC}"
echo "  Alice's address ($ALICE_ADDR) is the 'from' address in the tx."
echo ""

ALICE_DID="did:privado:test-response-filter-alice-${TIMESTAMP}"
ALICE_TOKEN=$(setup_user "$ALICE_DID" "$ALICE_ADDR" "rf-alice-${TIMESTAMP}")

if [ -z "$ALICE_TOKEN" ]; then
    echo -e "${RED}ERROR: Failed to setup Alice${NC}"
    exit 1
fi

echo -e "${GREEN}✓ Alice authenticated and linked to $ALICE_ADDR${NC}"
echo ""

echo -e "${YELLOW}  Alice queries the same tx hash through the proxy...${NC}"
echo "  Expected: full transaction object (Alice is the sender)"
echo ""

ALICE_RESP=$(curl -s -X POST "${PROXY_URL}/" \
    -H "Authorization: Bearer ${ALICE_TOKEN}" \
    -H "Content-Type: application/json" \
    -d "{
        \"jsonrpc\": \"2.0\",
        \"method\": \"eth_getTransactionByHash\",
        \"params\": [\"${TX_HASH}\"],
        \"id\": 1
    }")

echo "Response:"
echo "$ALICE_RESP" | jq .
echo ""

ALICE_TX_HASH=$(echo "$ALICE_RESP" | jq -r '.result.hash // empty')
ALICE_FROM=$(echo "$ALICE_RESP" | jq -r '.result.from // empty')
if [ -n "$ALICE_TX_HASH" ] && [ "$ALICE_TX_HASH" != "null" ]; then
    echo -e "${GREEN}✓ Participant (sender) receives full transaction${NC}"
    echo "  tx hash: $ALICE_TX_HASH"
    echo "  from:    $ALICE_FROM"
    ALICE_TEST_PASSED=true
else
    echo -e "${RED}UNEXPECTED: Participant (sender) did not receive transaction data${NC}"
    ALICE_TEST_PASSED=false
fi
echo ""

# =============================================================================
# Step 5: Setup Bob (participant, recipient) and test
# =============================================================================
echo -e "${YELLOW}Step 5: Setting up Bob (participant, recipient)...${NC}"
echo "  Bob's address ($BOB_ADDR) is the 'to' address in the tx."
echo ""

BOB_DID="did:privado:test-response-filter-bob-${TIMESTAMP}"
BOB_TOKEN=$(setup_user "$BOB_DID" "$BOB_ADDR" "rf-bob-${TIMESTAMP}")

if [ -z "$BOB_TOKEN" ]; then
    echo -e "${RED}ERROR: Failed to setup Bob${NC}"
    exit 1
fi

echo -e "${GREEN}✓ Bob authenticated and linked to $BOB_ADDR${NC}"
echo ""

echo -e "${YELLOW}  Bob queries the same tx hash through the proxy...${NC}"
echo "  Expected: full transaction object (Bob is the recipient)"
echo ""

BOB_RESP=$(curl -s -X POST "${PROXY_URL}/" \
    -H "Authorization: Bearer ${BOB_TOKEN}" \
    -H "Content-Type: application/json" \
    -d "{
        \"jsonrpc\": \"2.0\",
        \"method\": \"eth_getTransactionByHash\",
        \"params\": [\"${TX_HASH}\"],
        \"id\": 1
    }")

echo "Response:"
echo "$BOB_RESP" | jq .
echo ""

BOB_TX_HASH=$(echo "$BOB_RESP" | jq -r '.result.hash // empty')
BOB_TO=$(echo "$BOB_RESP" | jq -r '.result.to // empty')
if [ -n "$BOB_TX_HASH" ] && [ "$BOB_TX_HASH" != "null" ]; then
    echo -e "${GREEN}✓ Participant (recipient) receives full transaction${NC}"
    echo "  tx hash: $BOB_TX_HASH"
    echo "  to:      $BOB_TO"
    BOB_TEST_PASSED=true
else
    echo -e "${RED}UNEXPECTED: Participant (recipient) did not receive transaction data${NC}"
    BOB_TEST_PASSED=false
fi
echo ""

# =============================================================================
# Summary
# =============================================================================
echo -e "${BLUE}=============================================${NC}"
echo -e "${BLUE}  SUMMARY                                    ${NC}"
echo -e "${BLUE}=============================================${NC}"
echo ""
echo "Transaction: $TX_HASH"
echo "  from: $ALICE_ADDR (Alice — sender)"
echo "  to:   $BOB_ADDR   (Bob   — recipient)"
echo ""

if [ "$CHARLIE_TEST_PASSED" == "true" ]; then
    echo -e "  Charlie (non-participant): ${GREEN}null${NC} ✓"
else
    echo -e "  Charlie (non-participant): ${RED}SECURITY ISSUE -- got data${NC}"
fi

if [ "$ALICE_TEST_PASSED" == "true" ]; then
    echo -e "  Alice   (sender):          ${GREEN}full transaction${NC} ✓"
else
    echo -e "  Alice   (sender):          ${RED}UNEXPECTED -- no data${NC}"
fi

if [ "$BOB_TEST_PASSED" == "true" ]; then
    echo -e "  Bob     (recipient):       ${GREEN}full transaction${NC} ✓"
else
    echo -e "  Bob     (recipient):       ${RED}UNEXPECTED -- no data${NC}"
fi

echo ""

if [ "$CHARLIE_TEST_PASSED" == "true" ] && [ "$ALICE_TEST_PASSED" == "true" ] && [ "$BOB_TEST_PASSED" == "true" ]; then
    echo -e "${GREEN}=============================================${NC}"
    echo -e "${GREEN}  ALL TESTS PASSED                           ${NC}"
    echo -e "${GREEN}=============================================${NC}"
    echo ""
    echo "The response filter correctly restricts transaction visibility:"
    echo "  - Sender (from) sees the full transaction"
    echo "  - Recipient (to) sees the full transaction"
    echo "  - Uninvolved third party sees null"
    exit 0
else
    echo -e "${RED}=============================================${NC}"
    echo -e "${RED}  TESTS FAILED                               ${NC}"
    echo -e "${RED}=============================================${NC}"
    exit 1
fi
