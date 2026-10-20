#!/bin/bash
# =============================================================================
# BALANCEOF "SELF" RESTRICTION DEMO
# =============================================================================
#
# Demonstrates that a user can only call balanceOf() for their own address.
# The proxy enforces parameter-level constraints on smart contract calls.
#
# SCENARIO:
# 1. Deploy an ERC20 contract (auto-mints 1M tokens to deployer)
# 2. Create a user and link the deployer address to them
# 3. Register the ERC20 with a grant that restricts balanceOf to "self"
# 4. User calls balanceOf(own_address) -> ALLOWED
# 5. User calls balanceOf(other_address) -> DENIED
#
# This demonstrates per-parameter access control: even though the user
# has read access to the contract, they can only query their own balance.
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
API_URL="${PROXY_URL}/api/v1"

# Anvil pre-funded accounts
# Account #0 - used as deployer (deploys the ERC20, holds the minted tokens)
# NOTE: This is the well-known Anvil/Hardhat Account #0 default key — NOT a real secret.
# It is publicly documented at https://book.getfoundry.sh/reference/anvil/
# Override via environment variable for non-default setups.
DEPLOYER_KEY="${DEPLOYER_KEY:-0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80}"
DEPLOYER_ADDR="${DEPLOYER_ADDR:-0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266}"

# User's linked address - generated fresh each run to avoid "already linked" errors
USER_ETH_ADDR="0x$(openssl rand -hex 20)"
# An unrelated address (for the denied test)
OTHER_ADDR="0x$(openssl rand -hex 20)"

echo -e "${BLUE}=============================================${NC}"
echo -e "${BLUE}  BALANCEOF \"SELF\" RESTRICTION DEMO          ${NC}"
echo -e "${BLUE}=============================================${NC}"
echo ""
echo "Demonstrates that a user can only call balanceOf() for their own address."
echo "The proxy enforces parameter-level constraints on smart contract calls."
echo ""

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
# Step 2: Deploy ERC20 contract directly to Anvil
# =============================================================================
echo -e "${YELLOW}Step 2: Deploying ERC20 contract to Anvil...${NC}"

# Check if forge is available
if ! command -v forge &> /dev/null; then
    echo -e "${RED}ERROR: forge not found. Install Foundry first.${NC}"
    exit 1
fi

# Deploy DemoERC20 from contracts/ dir (auto-mints 1M tokens to deployer)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONTRACTS_DIR="${SCRIPT_DIR}/../contracts"

# Install forge-std if not present (needed for compilation)
if [ ! -d "${CONTRACTS_DIR}/lib/forge-std" ] || [ ! -f "${CONTRACTS_DIR}/lib/forge-std/src/Test.sol" ]; then
    echo "Installing forge-std..."
    # Remove any stale submodule/empty dir first
    rm -rf "${CONTRACTS_DIR}/lib/forge-std" 2>/dev/null || true
    cd "${CONTRACTS_DIR}" && forge install foundry-rs/forge-std --no-commit 2>/dev/null || true
    cd - > /dev/null
fi

# Bump deployer nonce to avoid address collision with contracts from other demo runs
cast send --private-key "$DEPLOYER_KEY" --rpc-url "$ANVIL_URL" --value 0 "$DEPLOYER_ADDR" > /dev/null 2>&1

# Pre-compile so forge create --json outputs clean JSON (first compile prints progress to stdout)
(cd "${CONTRACTS_DIR}" && forge build --quiet 2>/dev/null)

# Deploy from contracts dir (forge resolves src/ relative to CWD)
DEPLOY_OUTPUT=$(cd "${CONTRACTS_DIR}" && forge create "src/DemoERC20.sol:DemoERC20" \
    --private-key "$DEPLOYER_KEY" \
    --rpc-url "$ANVIL_URL" \
    --broadcast \
    --json 2>/dev/null)

ERC20_ADDR=$(echo "$DEPLOY_OUTPUT" | jq -r '.deployedTo')

if [ -z "$ERC20_ADDR" ] || [ "$ERC20_ADDR" == "null" ]; then
    echo -e "${RED}ERROR: Failed to deploy ERC20: $DEPLOY_OUTPUT${NC}"
    exit 1
fi

echo -e "${GREEN}✓ ERC20 deployed at: $ERC20_ADDR${NC}"

# Verify the contract works by checking deployer balance directly on Anvil
DEPLOYER_BALANCE=$(cast call "$ERC20_ADDR" "balanceOf(address)(uint256)" "$DEPLOYER_ADDR" --rpc-url "$ANVIL_URL")
echo -e "${GREEN}✓ Deployer balance on Anvil: $DEPLOYER_BALANCE${NC}"

# Transfer 500 tokens to the user's address so balanceOf returns a non-zero value
cast send --private-key "$DEPLOYER_KEY" --rpc-url "$ANVIL_URL" \
    "$ERC20_ADDR" "transfer(address,uint256)" "$USER_ETH_ADDR" 500000000000000000000 > /dev/null 2>&1
USER_BALANCE=$(cast call "$ERC20_ADDR" "balanceOf(address)(uint256)" "$USER_ETH_ADDR" --rpc-url "$ANVIL_URL")
echo -e "${GREEN}✓ Transferred 500 tokens to user address${NC}"
echo -e "${GREEN}✓ User balance on Anvil: $USER_BALANCE${NC}"
echo ""

# =============================================================================
# Step 3: Authenticate user (mock auth)
# =============================================================================
echo -e "${YELLOW}Step 3: Authenticating user...${NC}"

TIMESTAMP=$(date +%s)
USER_DID="did:privado:demo-balance-${TIMESTAMP}"

USER_TOKEN=$(get_jwt_token "$USER_DID")
if [ -z "$USER_TOKEN" ]; then
    echo -e "${RED}ERROR: Failed to get token for user${NC}"
    exit 1
fi

# Find user and set KYC
USERS_RESP=$(curl -s "${API_URL}/users?search=${USER_DID}")
USER_DB_ID=$(echo "$USERS_RESP" | jq -r ".data[] | select(.external_id == \"${USER_DID}\") | .id")

if [ -z "$USER_DB_ID" ]; then
    echo -e "${RED}ERROR: User not found${NC}"
    exit 1
fi

curl -s -X PUT "${API_URL}/users/${USER_DB_ID}" \
    -H "Content-Type: application/json" \
    -d '{"kyc": true}' > /dev/null

echo -e "${GREEN}✓ User authenticated: $USER_DID${NC}"
echo -e "${GREEN}✓ KYC set to true${NC}"
echo ""

# =============================================================================
# Step 4: Link ETH address to user
# =============================================================================
echo -e "${YELLOW}Step 4: Linking ETH address to user...${NC}"

# Get challenge
CHALLENGE_RESP=$(curl -s -X POST "${PROXY_URL}/api/v1/eth/link/challenge" \
    -H "Authorization: Bearer ${USER_TOKEN}" \
    -H "Content-Type: application/json")
NONCE=$(echo "$CHALLENGE_RESP" | jq -r '.nonce')

if [ -z "$NONCE" ] || [ "$NONCE" == "null" ]; then
    echo -e "${RED}ERROR: Failed to get challenge nonce: $CHALLENGE_RESP${NC}"
    exit 1
fi

# Verify with mock signature (any hex string works when MOCK_SIGNATURES=true)
LINK_RESP=$(curl -s -X POST "${PROXY_URL}/api/v1/eth/link/verify" \
    -H "Authorization: Bearer ${USER_TOKEN}" \
    -H "Content-Type: application/json" \
    -d "{\"nonce\": \"${NONCE}\", \"address\": \"${USER_ETH_ADDR}\", \"signature\": \"0xabababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababab\"}")

if echo "$LINK_RESP" | jq -e '.error' > /dev/null 2>&1; then
    echo -e "${RED}ERROR: Failed to link address: $LINK_RESP${NC}"
    exit 1
fi

echo -e "${GREEN}✓ Linked ${USER_ETH_ADDR} to user${NC}"
echo ""

# =============================================================================
# Step 5: Create org, group with READ claim, add user to group
# =============================================================================
echo -e "${YELLOW}Step 5: Setting up organization and group...${NC}"

# Create org
ORG_RESP=$(curl -s -X POST "${API_URL}/orgs" \
    -H "Content-Type: application/json" \
    -d "{\"slug\": \"balance-demo-${TIMESTAMP}\", \"name\": \"Balance Demo Org\"}")

ORG_ID=$(echo "$ORG_RESP" | jq -r '.id // empty')
if [ -z "$ORG_ID" ]; then
    echo -e "${RED}ERROR: Failed to create org: $ORG_RESP${NC}"
    exit 1
fi
echo -e "${GREEN}✓ Created org: $ORG_ID${NC}"

# Create group
GROUP_RESP=$(curl -s -X POST "${API_URL}/orgs/${ORG_ID}/groups" \
    -H "Content-Type: application/json" \
    -d '{"slug": "readers", "name": "Readers Group"}')

GROUP_ID=$(echo "$GROUP_RESP" | jq -r '.id // empty')
if [ -z "$GROUP_ID" ]; then
    echo -e "${RED}ERROR: Failed to create group: $GROUP_RESP${NC}"
    exit 1
fi

# Set group access: read claim, limited methods
curl -s -X PUT "${API_URL}/orgs/${ORG_ID}/groups/${GROUP_ID}/access" \
    -H "Content-Type: application/json" \
    -d '{
        "claims": ["read"],
        "allowed_methods": ["eth_call", "eth_getBalance", "eth_blockNumber", "eth_chainId", "eth_getTransactionCount", "net_version"]
    }' > /dev/null

echo -e "${GREEN}✓ Created group with read permissions${NC}"

# Remove user from default org membership
DEFAULT_MEMBERSHIPS=$(curl -s "${API_URL}/users/${USER_DB_ID}/memberships")
DEFAULT_MEMBERSHIP_ID=$(echo "$DEFAULT_MEMBERSHIPS" | jq -r '.[] | select(.group.org_id == "00000000-0000-0000-0000-000000000001") | .membership.id // empty')
if [ -n "$DEFAULT_MEMBERSHIP_ID" ]; then
    curl -s -X DELETE "${API_URL}/users/${USER_DB_ID}/memberships/${DEFAULT_MEMBERSHIP_ID}" > /dev/null
    echo "Removed user from default org"
fi

# Add user to the new group
MEMBERSHIP_RESP=$(curl -s -X POST "${API_URL}/users/${USER_DB_ID}/memberships" \
    -H "Content-Type: application/json" \
    -d "{\"group_id\": \"${GROUP_ID}\"}")

if echo "$MEMBERSHIP_RESP" | jq -e '.error' > /dev/null 2>&1; then
    echo -e "${YELLOW}Note: Membership might already exist: $(echo "$MEMBERSHIP_RESP" | jq -r '.error')${NC}"
fi

# Refresh JWT token after membership change
USER_TOKEN=$(get_jwt_token "$USER_DID")
if [ -z "$USER_TOKEN" ]; then
    echo -e "${RED}ERROR: Failed to refresh token${NC}"
    exit 1
fi

echo -e "${GREEN}✓ User added to group and token refreshed${NC}"
echo ""

# =============================================================================
# Step 6: Register the ERC20 contract in the org
# =============================================================================
echo -e "${YELLOW}Step 6: Registering ERC20 contract in org...${NC}"

# Check if this address is already registered in another org (from previous runs)
ERC20_ADDR_LOWER=$(echo "$ERC20_ADDR" | tr '[:upper:]' '[:lower:]')
ALL_ORGS=$(curl -s "${API_URL}/orgs" | jq -r '.data[]?.id // empty')
for CHECK_ORG in $ALL_ORGS; do
    if [ "$CHECK_ORG" != "$ORG_ID" ]; then
        EXISTING=$(curl -s "${API_URL}/orgs/${CHECK_ORG}/contracts" | jq -r ".data[]? | select(.address == \"${ERC20_ADDR_LOWER}\") | .address // empty")
        if [ -n "$EXISTING" ]; then
            echo "Removing stale registration of ${ERC20_ADDR_LOWER} from org ${CHECK_ORG}..."
            curl -s -X DELETE "${API_URL}/orgs/${CHECK_ORG}/contracts/${ERC20_ADDR_LOWER}" > /dev/null
        fi
    fi
done

# Register the contract
curl -s -X POST "${API_URL}/orgs/${ORG_ID}/contracts" \
    -H "Content-Type: application/json" \
    -d "{\"address\": \"${ERC20_ADDR}\", \"name\": \"Demo ERC20\"}" > /dev/null

echo -e "${GREEN}✓ ERC20 registered to org${NC}"

# Set the ABI (balanceOf, totalSupply, transfer) - must be wrapped in {"abi": "..."}
ABI_JSON='[{"inputs":[{"name":"account","type":"address"}],"name":"balanceOf","outputs":[{"name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"totalSupply","outputs":[{"name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[{"name":"to","type":"address"},{"name":"amount","type":"uint256"}],"name":"transfer","outputs":[{"name":"","type":"bool"}],"stateMutability":"nonpayable","type":"function"}]'

# The endpoint expects {"abi": "<string>"} where the ABI is a JSON string
curl -s -X PUT "${API_URL}/orgs/${ORG_ID}/contracts/${ERC20_ADDR}/abi" \
    -H "Content-Type: application/json" \
    -d "{\"abi\": $(echo "$ABI_JSON" | jq -Rs .)}" > /dev/null

echo -e "${GREEN}✓ ABI set for ERC20 contract${NC}"
echo ""

# =============================================================================
# Step 7: Create contract grant with balanceOf "self" restriction
# =============================================================================
echo -e "${YELLOW}Step 7: Creating contract grant with balanceOf \"self\" restriction...${NC}"

GRANT_RESP=$(curl -s -X POST "${API_URL}/orgs/${ORG_ID}/contracts/${ERC20_ADDR}/grants" \
    -H "Content-Type: application/json" \
    -d "{
        \"group_id\": \"${GROUP_ID}\",
        \"functions\": [
            {
                \"selector\": \"0x70a08231\",
                \"param_rules\": [{\"index\": 0, \"must_be\": \"self\"}]
            }
        ]
    }")

if echo "$GRANT_RESP" | jq -e '.error' > /dev/null 2>&1; then
    echo -e "${RED}ERROR: Failed to create grant: $GRANT_RESP${NC}"
    exit 1
fi

echo -e "${GREEN}✓ Grant created: balanceOf(address) restricted to \"self\"${NC}"
echo "  Only the user's own linked address can be queried"
echo ""

# =============================================================================
# Step 8: Test - balanceOf with OWN address (should SUCCEED)
# =============================================================================
echo -e "${YELLOW}Step 8: Testing balanceOf with OWN address (should succeed)...${NC}"
echo ""
echo "Calling balanceOf(${USER_ETH_ADDR}) through proxy..."
echo "This is the user's linked address, so it should be ALLOWED."
echo ""

# balanceOf calldata: selector 0x70a08231 + address left-padded to 32 bytes
# Dynamically encode the calldata from USER_ETH_ADDR
OWN_ADDR_HEX=$(echo "$USER_ETH_ADDR" | sed 's/0x//' | tr '[:upper:]' '[:lower:]')
OWN_CALLDATA="0x70a08231000000000000000000000000${OWN_ADDR_HEX}"

OWN_RESP=$(curl -s -w "\n%{http_code}" -X POST "${PROXY_URL}/" \
    -H "Authorization: Bearer ${USER_TOKEN}" \
    -H "Content-Type: application/json" \
    -d "{
        \"jsonrpc\": \"2.0\",
        \"method\": \"eth_call\",
        \"params\": [{\"to\": \"${ERC20_ADDR}\", \"data\": \"${OWN_CALLDATA}\"}, \"latest\"],
        \"id\": 1
    }")

OWN_HTTP_CODE=$(echo "$OWN_RESP" | tail -1)
OWN_BODY=$(echo "$OWN_RESP" | sed '$d')

echo "HTTP Status: $OWN_HTTP_CODE"
echo "Response:"
echo "$OWN_BODY" | jq .
echo ""

OWN_RESULT=$(echo "$OWN_BODY" | jq -r '.result // empty')
if [ -n "$OWN_RESULT" ] && [ "$OWN_RESULT" != "null" ]; then
    # Decode the hex balance using cast (handles large numbers correctly)
    OWN_BALANCE_WEI=$(cast --to-dec "$OWN_RESULT" 2>/dev/null || echo "could not decode")
    OWN_BALANCE_TOKENS=$(cast --from-wei "$OWN_BALANCE_WEI" 2>/dev/null || echo "$OWN_BALANCE_WEI")
    echo -e "${GREEN}✓ balanceOf(own address) ALLOWED${NC}"
    echo -e "${GREEN}  Balance: ${OWN_BALANCE_TOKENS} tokens${NC}"
    OWN_TEST_PASSED=true
else
    echo -e "${RED}UNEXPECTED: balanceOf(own address) was rejected!${NC}"
    echo "$OWN_BODY" | jq .
    OWN_TEST_PASSED=false
fi
echo ""

# =============================================================================
# Step 9: Test - balanceOf with DIFFERENT address (should be REJECTED)
# =============================================================================
echo -e "${YELLOW}Step 9: Testing balanceOf with DIFFERENT address (should be rejected)...${NC}"
echo ""
echo "Calling balanceOf(${OTHER_ADDR}) through proxy..."
echo "This is NOT the user's address, so it should be DENIED."
echo ""

OTHER_ADDR_HEX=$(echo "$OTHER_ADDR" | sed 's/0x//' | tr '[:upper:]' '[:lower:]')
OTHER_CALLDATA="0x70a08231000000000000000000000000${OTHER_ADDR_HEX}"

OTHER_RESP=$(curl -s -w "\n%{http_code}" -X POST "${PROXY_URL}/" \
    -H "Authorization: Bearer ${USER_TOKEN}" \
    -H "Content-Type: application/json" \
    -d "{
        \"jsonrpc\": \"2.0\",
        \"method\": \"eth_call\",
        \"params\": [{\"to\": \"${ERC20_ADDR}\", \"data\": \"${OTHER_CALLDATA}\"}, \"latest\"],
        \"id\": 1
    }")

OTHER_HTTP_CODE=$(echo "$OTHER_RESP" | tail -1)
OTHER_BODY=$(echo "$OTHER_RESP" | sed '$d')

echo "HTTP Status: $OTHER_HTTP_CODE"
echo "Response:"
echo "$OTHER_BODY" | jq .
echo ""

OTHER_ERROR=$(echo "$OTHER_BODY" | jq -r '.error // empty')
if [ "$OTHER_HTTP_CODE" == "403" ] || echo "$OTHER_BODY" | grep -qi "parameter constraint violation\|param.*constraint\|denied\|forbidden"; then
    echo -e "${GREEN}✓ balanceOf(other address) correctly DENIED${NC}"
    OTHER_TEST_PASSED=true
else
    echo -e "${RED}SECURITY ISSUE: balanceOf(other address) was ALLOWED!${NC}"
    OTHER_TEST_PASSED=false
fi
echo ""

# =============================================================================
# Step 10: Summary
# =============================================================================
echo -e "${BLUE}=============================================${NC}"
echo -e "${BLUE}  SUMMARY                                    ${NC}"
echo -e "${BLUE}=============================================${NC}"
echo ""

if [ "$OWN_TEST_PASSED" == "true" ]; then
    echo -e "  balanceOf(own address):   ${GREEN}ALLOWED${NC} (balance: ${OWN_BALANCE_TOKENS} tokens)"
else
    echo -e "  balanceOf(own address):   ${RED}UNEXPECTED FAILURE${NC}"
fi

if [ "$OTHER_TEST_PASSED" == "true" ]; then
    echo -e "  balanceOf(other address): ${RED}DENIED${NC} (parameter constraint violation)"
else
    echo -e "  balanceOf(other address): ${RED}UNEXPECTED ALLOW - SECURITY ISSUE${NC}"
fi

echo ""

if [ "$OWN_TEST_PASSED" == "true" ] && [ "$OTHER_TEST_PASSED" == "true" ]; then
    echo -e "${GREEN}=============================================${NC}"
    echo -e "${GREEN}  ALL TESTS PASSED                           ${NC}"
    echo -e "${GREEN}=============================================${NC}"
    echo ""
    echo "The proxy correctly enforces per-parameter access control:"
    echo "  - Users CAN call balanceOf() with their own linked address"
    echo "  - Users CANNOT call balanceOf() with any other address"
    echo "  - The \"self\" constraint maps to the caller's linked ETH address"
    echo ""
    echo "This demonstrates fine-grained smart contract access control"
    echo "at the parameter level, not just the function level."
    echo ""
    echo -e "${YELLOW}Verify manually:${NC}"
    echo ""
    echo -e "  ${BLUE}export ETH_RPC_HEADERS=\"Authorization: Bearer ${USER_TOKEN}\"${NC}"
    echo ""
    echo -e "  ${GREEN}# Own address (allowed):${NC}"
    echo -e "  ${BLUE}cast call $ERC20_ADDR \"balanceOf(address)(uint256)\" $USER_ETH_ADDR --rpc-url $PROXY_URL${NC}"
    echo ""
    echo -e "  ${RED}# Other address (rejected):${NC}"
    echo -e "  ${BLUE}cast call $ERC20_ADDR \"balanceOf(address)(uint256)\" $OTHER_ADDR --rpc-url $PROXY_URL${NC}"
    exit 0
else
    echo -e "${RED}=============================================${NC}"
    echo -e "${RED}  SOME TESTS FAILED                          ${NC}"
    echo -e "${RED}=============================================${NC}"
    exit 1
fi
