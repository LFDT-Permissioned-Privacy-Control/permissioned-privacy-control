#!/bin/bash
# =============================================================================
# CROSS-ORG ATTACK DEMO
# =============================================================================
#
# This script demonstrates that the runtime tracer correctly blocks cross-org
# calls even when made through an intermediary contract owned by the user's org.
#
# ATTACK SCENARIO:
# 1. User is member of Org A
# 2. User deploys "Forwarder" contract to Org A
# 3. Org B has a "Target" contract
# 4. User calls Forwarder.forward(Target_Address, calldata)
# 5. Forwarder makes CALL to Target (cross-org!)
# 6. EXPECTED: Runtime tracer detects and BLOCKS the transaction
#
# This is the critical security test for cross-org isolation.
# Without proper tracing, the attack would succeed because:
# - Direct target is Forwarder (org-owned, passes RBAC check)
# - Internal call to Target is hidden from RBAC
# - Only runtime tracing can detect this attack
#
# =============================================================================

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
PROXY_URL="${PROXY_URL:-http://localhost:8080}"
ANVIL_URL="${ANVIL_URL:-http://localhost:8545}"
API_URL="${PROXY_URL}/api/v1/admin"

# Anvil pre-funded accounts
# NOTE: These are well-known Anvil/Hardhat default keys — NOT real secrets.
# See https://book.getfoundry.sh/reference/anvil/
DEPLOYER_KEY="${DEPLOYER_KEY:-0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80}"
DEPLOYER_ADDR="${DEPLOYER_ADDR:-0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266}"

USER_A_KEY="${USER_A_KEY:-0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d}"
USER_A_ADDR="${USER_A_ADDR:-0x70997970C51812dc3A010C7d01b50e0d17dc79C8}"

echo -e "${BLUE}=============================================${NC}"
echo -e "${BLUE}  CROSS-ORG ATTACK DEMO                      ${NC}"
echo -e "${BLUE}=============================================${NC}"
echo ""

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

echo -e "${GREEN}✓ Services are running${NC}"
echo ""

# =============================================================================
# Step 2: Create Organizations
# =============================================================================
echo -e "${YELLOW}Step 2: Creating organizations...${NC}"

TIMESTAMP=$(date +%s)

# Create Org A (attacker's org)
ORG_A_RESP=$(curl -s -X POST "${API_URL}/orgs" \
    -H "Content-Type: application/json" \
    -d "{\"slug\": \"attack-org-a-${TIMESTAMP}\", \"name\": \"Attack Test Org A\"}")

ORG_A_ID=$(echo "$ORG_A_RESP" | jq -r '.id // empty')
if [ -z "$ORG_A_ID" ]; then
    echo -e "${RED}ERROR: Failed to create Org A: $ORG_A_RESP${NC}"
    exit 1
fi
echo -e "${GREEN}✓ Created Org A: $ORG_A_ID${NC}"

# Create Org B (victim's org)
ORG_B_RESP=$(curl -s -X POST "${API_URL}/orgs" \
    -H "Content-Type: application/json" \
    -d "{\"slug\": \"attack-org-b-${TIMESTAMP}\", \"name\": \"Attack Test Org B\"}")

ORG_B_ID=$(echo "$ORG_B_RESP" | jq -r '.id // empty')
if [ -z "$ORG_B_ID" ]; then
    echo -e "${RED}ERROR: Failed to create Org B: $ORG_B_RESP${NC}"
    exit 1
fi
echo -e "${GREEN}✓ Created Org B: $ORG_B_ID${NC}"
echo ""

# =============================================================================
# Step 3: Create Groups with permissions
# =============================================================================
echo -e "${YELLOW}Step 3: Creating groups with permissions...${NC}"

# Create group for Org A
GROUP_A_RESP=$(curl -s -X POST "${API_URL}/orgs/${ORG_A_ID}/groups" \
    -H "Content-Type: application/json" \
    -d '{"slug": "attackers", "name": "Attackers Group"}')

GROUP_A_ID=$(echo "$GROUP_A_RESP" | jq -r '.id // empty')
if [ -z "$GROUP_A_ID" ]; then
    echo -e "${RED}ERROR: Failed to create Group A: $GROUP_A_RESP${NC}"
    exit 1
fi

# Set permissions for Group A (full access including deploy)
curl -s -X PUT "${API_URL}/orgs/${ORG_A_ID}/groups/${GROUP_A_ID}/access" \
    -H "Content-Type: application/json" \
    -d '{
        "allowed_methods": ["eth_call", "eth_sendTransaction", "eth_estimateGas", "eth_getBalance", "eth_getCode", "eth_blockNumber", "eth_chainId", "eth_getTransactionReceipt", "eth_getTransactionByHash", "net_version"],
        "allowed_methods": ["*"], "claims": ["deploy"]
    }' > /dev/null

echo -e "${GREEN}✓ Created Group A with deploy permissions${NC}"

# Create group for Org B
GROUP_B_RESP=$(curl -s -X POST "${API_URL}/orgs/${ORG_B_ID}/groups" \
    -H "Content-Type: application/json" \
    -d '{"slug": "victims", "name": "Victims Group"}')

GROUP_B_ID=$(echo "$GROUP_B_RESP" | jq -r '.id // empty')

# Set permissions for Group B
curl -s -X PUT "${API_URL}/orgs/${ORG_B_ID}/groups/${GROUP_B_ID}/access" \
    -H "Content-Type: application/json" \
    -d '{
        "allowed_methods": ["eth_call", "eth_sendTransaction", "eth_estimateGas", "eth_getBalance", "eth_getCode", "eth_blockNumber", "eth_chainId", "eth_getTransactionReceipt", "eth_getTransactionByHash", "net_version"],
        "allowed_methods": ["*"], "claims": ["deploy"]
    }' > /dev/null

echo -e "${GREEN}✓ Created Group B with permissions${NC}"
echo ""

# =============================================================================
# Step 4: Create and setup User A (attacker)
# =============================================================================
echo -e "${YELLOW}Step 4: Creating attacker user...${NC}"

USER_A_DID="did:attack:user-a-${TIMESTAMP}"

# Helper function to get JWT token using auth flow
get_jwt_token() {
    local user_did="$1"

    # Step 1: Create auth request to get session ID
    local auth_req_resp=$(curl -s -X POST "${PROXY_URL}/auth/request" \
        -H "Content-Type: application/json")

    local session_id=$(echo "$auth_req_resp" | jq -r '.session_id // empty')
    if [ -z "$session_id" ]; then
        echo ""
        return 1
    fi

    # Step 2: Verify with mock JWZ token (dev mode)
    local verify_resp=$(curl -s -X POST "${PROXY_URL}/auth/verify" \
        -H "Content-Type: application/json" \
        -d "{\"session_id\": \"${session_id}\", \"jwz_token\": \"mock.${user_did}\"}")

    local token=$(echo "$verify_resp" | jq -r '.access_token // empty')
    echo "$token"
}

# Get JWT token (creates user if needed)
USER_A_TOKEN=$(get_jwt_token "$USER_A_DID")
if [ -z "$USER_A_TOKEN" ]; then
    echo -e "${RED}ERROR: Failed to get token for User A${NC}"
    exit 1
fi

# Find user and set KYC
USERS_RESP=$(curl -s "${API_URL}/users")
USER_A_DB_ID=$(echo "$USERS_RESP" | jq -r ".data[] | select(.external_id == \"${USER_A_DID}\") | .id")

if [ -z "$USER_A_DB_ID" ]; then
    echo -e "${RED}ERROR: User A not found${NC}"
    exit 1
fi

curl -s -X PUT "${API_URL}/users/${USER_A_DB_ID}" \
    -H "Content-Type: application/json" \
    -d '{"kyc": true}' > /dev/null

# Remove user from default org (so attack org is used for deployments)
DEFAULT_MEMBERSHIPS=$(curl -s "${API_URL}/users/${USER_A_DB_ID}/memberships")
DEFAULT_MEMBERSHIP_ID=$(echo "$DEFAULT_MEMBERSHIPS" | jq -r '.[] | select(.group.org_id == "00000000-0000-0000-0000-000000000001") | .membership.id // empty')
if [ -n "$DEFAULT_MEMBERSHIP_ID" ]; then
    curl -s -X DELETE "${API_URL}/users/${USER_A_DB_ID}/memberships/${DEFAULT_MEMBERSHIP_ID}" > /dev/null
    echo "Removed user from default org"
fi

# Add user to Org A (via group membership)
MEMBERSHIP_RESP=$(curl -s -X POST "${API_URL}/users/${USER_A_DB_ID}/memberships" \
    -H "Content-Type: application/json" \
    -d "{\"group_id\": \"${GROUP_A_ID}\"}")

if echo "$MEMBERSHIP_RESP" | jq -e '.error' > /dev/null 2>&1; then
    echo -e "${YELLOW}Note: Membership might already exist: $(echo "$MEMBERSHIP_RESP" | jq -r '.error')${NC}"
fi

# Refresh token with updated permissions
USER_A_TOKEN=$(get_jwt_token "$USER_A_DID")
if [ -z "$USER_A_TOKEN" ]; then
    echo -e "${RED}ERROR: Failed to refresh token${NC}"
    exit 1
fi

echo -e "${GREEN}✓ Created User A (attacker) in Org A${NC}"
echo ""

# =============================================================================
# Step 5: Deploy Forwarder contract to Org A
# =============================================================================
echo -e "${YELLOW}Step 5: Deploying Forwarder contract to Org A...${NC}"

# Compile the Forwarder contract
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}/contracts"

# Check if forge is available
if ! command -v forge &> /dev/null; then
    echo -e "${RED}ERROR: forge not found. Install Foundry first.${NC}"
    exit 1
fi

# Install dependencies if not present (lib/ is gitignored)
if [ ! -d "lib/forge-std" ]; then
    echo -e "${YELLOW}Installing Solidity dependencies...${NC}"
    rm -rf lib
    mkdir -p lib
    git clone --quiet --depth 1 https://github.com/foundry-rs/forge-std.git lib/forge-std || true
    git clone --quiet --depth 1 https://github.com/OpenZeppelin/openzeppelin-contracts.git lib/openzeppelin-contracts || true
    git clone --quiet --depth 1 https://github.com/OpenZeppelin/openzeppelin-contracts-upgradeable.git lib/openzeppelin-contracts-upgradeable || true
    git clone --quiet --depth 1 https://github.com/Vectorized/solady.git lib/solady || true
fi

# Compile contracts
forge build --quiet 2>/dev/null || true

# Get Forwarder bytecode
FORWARDER_BYTECODE=$(cat out/Forwarder.sol/Forwarder.json 2>/dev/null | jq -r '.bytecode.object // empty')
if [ -z "$FORWARDER_BYTECODE" ] || [ "$FORWARDER_BYTECODE" == "null" ]; then
    echo -e "${YELLOW}Compiling Forwarder contract...${NC}"
    forge build --contracts src/attack/Forwarder.sol 2>/dev/null
    FORWARDER_BYTECODE=$(cat out/Forwarder.sol/Forwarder.json | jq -r '.bytecode.object')
fi

# Get Target bytecode
TARGET_BYTECODE=$(cat out/Target.sol/Target.json 2>/dev/null | jq -r '.bytecode.object // empty')
if [ -z "$TARGET_BYTECODE" ] || [ "$TARGET_BYTECODE" == "null" ]; then
    echo -e "${YELLOW}Compiling Target contract...${NC}"
    forge build --contracts src/attack/Target.sol 2>/dev/null
    TARGET_BYTECODE=$(cat out/Target.sol/Target.json | jq -r '.bytecode.object')
fi

cd - > /dev/null

# Deploy Forwarder via Open Privacy Suite (Org A)
echo "Deploying Forwarder..."
DEPLOY_RESP=$(curl -s -X POST "${PROXY_URL}/" \
    -H "Authorization: Bearer ${USER_A_TOKEN}" \
    -H "Content-Type: application/json" \
    -d "{
        \"jsonrpc\": \"2.0\",
        \"method\": \"eth_sendTransaction\",
        \"params\": [{
            \"from\": \"${DEPLOYER_ADDR}\",
            \"data\": \"${FORWARDER_BYTECODE}\",
            \"gas\": \"0x200000\"
        }],
        \"id\": 1
    }")

# Check for errors
if echo "$DEPLOY_RESP" | jq -e '.error' > /dev/null 2>&1; then
    ERROR_MSG=$(echo "$DEPLOY_RESP" | jq -r '.error')
    echo -e "${RED}ERROR deploying Forwarder: $ERROR_MSG${NC}"
    exit 1
fi

FORWARDER_TX=$(echo "$DEPLOY_RESP" | jq -r '.result // empty')
if [ -z "$FORWARDER_TX" ]; then
    echo -e "${RED}ERROR: No transaction hash returned: $DEPLOY_RESP${NC}"
    exit 1
fi

echo "Waiting for transaction receipt..."
sleep 2

# Get transaction receipt
RECEIPT_RESP=$(curl -s -X POST "${PROXY_URL}/" \
    -H "Authorization: Bearer ${USER_A_TOKEN}" \
    -H "Content-Type: application/json" \
    -d "{
        \"jsonrpc\": \"2.0\",
        \"method\": \"eth_getTransactionReceipt\",
        \"params\": [\"${FORWARDER_TX}\"],
        \"id\": 1
    }")

FORWARDER_ADDR=$(echo "$RECEIPT_RESP" | jq -r '.result.contractAddress // empty')
if [ -z "$FORWARDER_ADDR" ]; then
    echo -e "${RED}ERROR: Failed to get Forwarder address: $RECEIPT_RESP${NC}"
    exit 1
fi

echo -e "${GREEN}✓ Forwarder deployed at: $FORWARDER_ADDR${NC}"

# Register Forwarder to Org A
curl -s -X POST "${API_URL}/orgs/${ORG_A_ID}/contracts" \
    -H "Content-Type: application/json" \
    -d "{\"address\": \"${FORWARDER_ADDR}\", \"name\": \"Forwarder\"}" > /dev/null

echo -e "${GREEN}✓ Forwarder registered to Org A${NC}"
echo ""

# =============================================================================
# Step 6: Deploy Target contract to Org B (directly to anvil, not via proxy)
# =============================================================================
echo -e "${YELLOW}Step 6: Deploying Target contract to Org B...${NC}"

# Deploy Target directly to Anvil (bypassing proxy - simulating Org B's deployment)
TARGET_DEPLOY_RESP=$(curl -s -X POST "${ANVIL_URL}" \
    -H "Content-Type: application/json" \
    -d "{
        \"jsonrpc\": \"2.0\",
        \"method\": \"eth_sendTransaction\",
        \"params\": [{
            \"from\": \"${DEPLOYER_ADDR}\",
            \"data\": \"${TARGET_BYTECODE}\",
            \"gas\": \"0x200000\"
        }],
        \"id\": 1
    }")

TARGET_TX=$(echo "$TARGET_DEPLOY_RESP" | jq -r '.result')
sleep 2

TARGET_RECEIPT=$(curl -s -X POST "${ANVIL_URL}" \
    -H "Content-Type: application/json" \
    -d "{
        \"jsonrpc\": \"2.0\",
        \"method\": \"eth_getTransactionReceipt\",
        \"params\": [\"${TARGET_TX}\"],
        \"id\": 1
    }")

TARGET_ADDR=$(echo "$TARGET_RECEIPT" | jq -r '.result.contractAddress')
echo -e "${GREEN}✓ Target deployed at: $TARGET_ADDR${NC}"

# Register Target to Org B
curl -s -X POST "${API_URL}/orgs/${ORG_B_ID}/contracts" \
    -H "Content-Type: application/json" \
    -d "{\"address\": \"${TARGET_ADDR}\", \"name\": \"Target\"}" > /dev/null

echo -e "${GREEN}✓ Target registered to Org B${NC}"
echo ""

# =============================================================================
# Step 7: Verify baseline - direct access
# =============================================================================
echo -e "${YELLOW}Step 7: Verifying baseline access controls...${NC}"

# User A should be able to call their own Forwarder
echo "Testing: User A calls own Forwarder (should succeed)..."
OWN_CALL_RESP=$(curl -s -X POST "${PROXY_URL}/" \
    -H "Authorization: Bearer ${USER_A_TOKEN}" \
    -H "Content-Type: application/json" \
    -d "{
        \"jsonrpc\": \"2.0\",
        \"method\": \"eth_call\",
        \"params\": [{
            \"to\": \"${FORWARDER_ADDR}\",
            \"data\": \"0x\"
        }, \"latest\"],
        \"id\": 1
    }")

if echo "$OWN_CALL_RESP" | jq -e '.error' > /dev/null 2>&1; then
    echo -e "${RED}UNEXPECTED: User A cannot call own Forwarder: $OWN_CALL_RESP${NC}"
else
    echo -e "${GREEN}✓ User A can call own Forwarder (expected)${NC}"
fi

# User A should NOT be able to directly call Org B's Target
echo "Testing: User A directly calls Org B's Target (should fail)..."
DIRECT_CALL_RESP=$(curl -s -X POST "${PROXY_URL}/" \
    -H "Authorization: Bearer ${USER_A_TOKEN}" \
    -H "Content-Type: application/json" \
    -d "{
        \"jsonrpc\": \"2.0\",
        \"method\": \"eth_call\",
        \"params\": [{
            \"to\": \"${TARGET_ADDR}\",
            \"data\": \"0x\"
        }, \"latest\"],
        \"id\": 1
    }")

HTTP_STATUS=$(echo "$DIRECT_CALL_RESP" | jq -r '.error // empty')
if [ -n "$HTTP_STATUS" ]; then
    echo -e "${GREEN}✓ Direct cross-org call blocked (expected)${NC}"
else
    echo -e "${RED}SECURITY ISSUE: Direct cross-org call was ALLOWED!${NC}"
    exit 1
fi
echo ""

# =============================================================================
# Step 8: THE ATTACK - Forwarder calls Target
# =============================================================================
echo -e "${YELLOW}Step 8: EXECUTING CROSS-ORG ATTACK...${NC}"
echo ""
echo "Attack scenario:"
echo "  1. User A is member of Org A"
echo "  2. Forwarder contract is owned by Org A"
echo "  3. Target contract is owned by Org B"
echo "  4. User A calls Forwarder.forward(Target, ping_calldata)"
echo "  5. Forwarder makes internal CALL to Target"
echo ""
echo -e "${BLUE}If this succeeds, cross-org isolation is BROKEN!${NC}"
echo -e "${BLUE}Expected result: Transaction DENIED by runtime tracer${NC}"
echo ""

# Encode the forward(address, bytes) call using cast for proper ABI encoding
# forward(address,bytes) selector: 0x6fadcf72 (keccak256 of "forward(address,bytes)")
# ping() selector: 0x5c36b186

FORWARD_CALLDATA=$(cast calldata "forward(address,bytes)" "$TARGET_ADDR" "0x5c36b186")

echo "Calling Forwarder.forward(Target, ping())..."
ATTACK_RESP=$(curl -s -X POST "${PROXY_URL}/" \
    -H "Authorization: Bearer ${USER_A_TOKEN}" \
    -H "Content-Type: application/json" \
    -d "{
        \"jsonrpc\": \"2.0\",
        \"method\": \"eth_sendTransaction\",
        \"params\": [{
            \"from\": \"${DEPLOYER_ADDR}\",
            \"to\": \"${FORWARDER_ADDR}\",
            \"data\": \"${FORWARD_CALLDATA}\",
            \"gas\": \"0x100000\"
        }],
        \"id\": 1
    }")

echo ""
echo "Response:"
echo "$ATTACK_RESP" | jq .
echo ""

# Check the result
if echo "$ATTACK_RESP" | jq -e '.error' > /dev/null 2>&1; then
    ERROR_MSG=$(echo "$ATTACK_RESP" | jq -r '.error')
    if echo "$ERROR_MSG" | grep -qi "cross-org\|denied\|forbidden\|isolation"; then
        echo -e "${GREEN}=============================================${NC}"
        echo -e "${GREEN}  ATTACK BLOCKED - SECURITY TEST PASSED!     ${NC}"
        echo -e "${GREEN}=============================================${NC}"
        echo ""
        echo "The runtime tracer correctly detected that the Forwarder"
        echo "contract (Org A) was trying to call the Target contract (Org B)"
        echo "and blocked the transaction."
        echo ""
        echo -e "${GREEN}Cross-org isolation is working correctly!${NC}"
        exit 0
    else
        echo -e "${YELLOW}Transaction failed with error: $ERROR_MSG${NC}"
        echo "This might be a different error, not cross-org isolation."
    fi
else
    TX_HASH=$(echo "$ATTACK_RESP" | jq -r '.result // empty')
    if [ -n "$TX_HASH" ]; then
        echo -e "${RED}=============================================${NC}"
        echo -e "${RED}  ATTACK SUCCEEDED - SECURITY VULNERABILITY! ${NC}"
        echo -e "${RED}=============================================${NC}"
        echo ""
        echo "Transaction hash: $TX_HASH"
        echo ""
        echo "The cross-org attack was NOT blocked!"
        echo "User A was able to use their Forwarder contract to call"
        echo "Org B's Target contract through an internal CALL."
        echo ""
        echo "This indicates a security vulnerability in the runtime tracer."
        exit 1
    fi
fi

echo ""
echo -e "${YELLOW}Test completed - check results above${NC}"
