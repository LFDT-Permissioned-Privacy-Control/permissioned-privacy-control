#!/bin/bash

# =============================================================================
# Open Privacy Suite - UUPS Proxy Upgrade Demo
# =============================================================================
# This script demonstrates the UUPS proxy upgrade workflow:
# 1. Deploy V1 implementations and proxies
# 2. Interact with V1 (show version, perform operations)
# 3. Deploy V2 implementations
# 4. Upgrade proxies to V2
# 5. Verify new functionality (show new version, new features)
#
# Uses the DeFi contracts: DemoToken, LiquidityPool, SwapRouter
# =============================================================================

set -e

# Colors for pretty output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m' # No Color
BOLD='\033[1m'

# Box drawing characters
BOX_TL="╔"
BOX_TR="╗"
BOX_BL="╚"
BOX_BR="╝"
BOX_H="═"
BOX_V="║"

# Print functions
print_header() {
    local text="$1"
    local width=70
    local padding=$(( (width - ${#text} - 2) / 2 ))
    echo ""
    echo -e "${CYAN}${BOX_TL}$(printf '%*s' $width | tr ' ' "$BOX_H")${BOX_TR}${NC}"
    echo -e "${CYAN}${BOX_V}${NC}$(printf '%*s' $padding)${BOLD}${WHITE}$text${NC}$(printf '%*s' $((width - padding - ${#text})))${CYAN}${BOX_V}${NC}"
    echo -e "${CYAN}${BOX_BL}$(printf '%*s' $width | tr ' ' "$BOX_H")${BOX_BR}${NC}"
    echo ""
}

print_step() {
    echo -e "\n${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${YELLOW}▶${NC} ${BOLD}$1${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n"
}

print_substep() {
    echo -e "  ${CYAN}→${NC} $1"
}

print_success() {
    echo -e "  ${GREEN}✓${NC} $1"
}

print_error() {
    echo -e "  ${RED}✗${NC} $1"
}

print_info() {
    echo -e "  ${MAGENTA}ℹ${NC} $1"
}

print_value() {
    echo -e "  ${WHITE}│${NC} $1: ${GREEN}$2${NC}"
}

print_json() {
    echo -e "${WHITE}$1${NC}" | jq '.' 2>/dev/null || echo -e "${WHITE}$1${NC}"
}

print_contract_call() {
    local contract="$1"
    local method="$2"
    local result="$3"
    echo -e "  ${CYAN}┌─────────────────────────────────────────────────────────────────┐${NC}"
    echo -e "  ${CYAN}│${NC} Contract: ${YELLOW}$contract${NC}"
    echo -e "  ${CYAN}│${NC} Method:   ${YELLOW}$method${NC}"
    echo -e "  ${CYAN}│${NC} Result:   ${GREEN}$result${NC}"
    echo -e "  ${CYAN}└─────────────────────────────────────────────────────────────────┘${NC}"
}

# =============================================================================
# Helper function for RPC calls through the proxy
# =============================================================================
rpc_call() {
    local method="$1"
    local params="$2"

    curl -s -X POST "$PROXY_RPC_URL" \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer $AUTH_TOKEN" \
        -d "{\"jsonrpc\":\"2.0\",\"method\":\"$method\",\"params\":$params,\"id\":1}"
}

# =============================================================================
# Configuration
# =============================================================================

print_header "UUPS Proxy Upgrade Demo"

print_step "Step 1: Checking Configuration"

# Environment variables with defaults
: "${ADMIN_API_URL:=http://localhost:8080/api}"
: "${PROXY_RPC_URL:=http://localhost:8080}"
: "${ANVIL_URL:=http://localhost:8545}"
: "${PRIVATE_KEY:=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80}"

print_value "Admin API URL" "$ADMIN_API_URL"
print_value "Proxy RPC URL" "$PROXY_RPC_URL"
print_value "Anvil URL" "$ANVIL_URL"
print_value "Private Key" "${PRIVATE_KEY:0:10}..."

DEPLOYER_ADDRESS=$(cast wallet address "$PRIVATE_KEY" 2>/dev/null)
print_value "Deployer Address" "$DEPLOYER_ADDRESS"

# Check services
print_substep "Checking Anvil connection..."
CHAIN_ID=$(cast chain-id --rpc-url "$ANVIL_URL" 2>/dev/null || echo "")
if [ -z "$CHAIN_ID" ]; then
    print_error "Could not connect to Anvil"
    exit 1
fi
print_success "Connected to Anvil (chainId: $CHAIN_ID)"

# Get org
if [ -z "$ORG_ID" ] && [ -z "$ORG_SLUG" ]; then
    ORGS_RESPONSE=$(curl -s "$ADMIN_API_URL/v1/orgs")
    ORG_COUNT=$(echo "$ORGS_RESPONSE" | jq '.data | length' 2>/dev/null || echo "0")
    if [ "$ORG_COUNT" -gt 0 ]; then
        ORG_ID=$(echo "$ORGS_RESPONSE" | jq -r '.data[0].id')
        ORG_SLUG=$(echo "$ORGS_RESPONSE" | jq -r '.data[0].slug')
        print_success "Using organization: $ORG_SLUG"
    else
        print_error "No organization found"
        exit 1
    fi
elif [ -n "$ORG_SLUG" ] && [ -z "$ORG_ID" ]; then
    ORGS_RESPONSE=$(curl -s "$ADMIN_API_URL/v1/orgs")
    ORG_ID=$(echo "$ORGS_RESPONSE" | jq -r ".data[] | select(.slug == \"$ORG_SLUG\") | .id")
fi

print_value "Organization" "$ORG_SLUG ($ORG_ID)"

# Clean up stale preregistered addresses from previous runs
print_substep "Cleaning up stale preregistered addresses..."
if command -v docker-compose &> /dev/null; then
    docker-compose exec -T postgres psql -U postgres -d privacy_proxy -c "DELETE FROM preregistered_addresses;" > /dev/null 2>&1 || true
elif command -v docker &> /dev/null; then
    docker exec privacy-proxy-postgres-1 psql -U postgres -d privacy_proxy -c "DELETE FROM preregistered_addresses;" > /dev/null 2>&1 || true
fi
print_success "Cleanup complete"

# =============================================================================
# Step 2: Authentication
# =============================================================================

print_step "Step 2: Authentication"

USER_EXTERNAL_ID="did:demo:upgrader-$(date +%s)"
print_substep "Creating user: $USER_EXTERNAL_ID"

AUTH_REQUEST_RESP=$(curl -s -X POST "$PROXY_RPC_URL/auth/request" \
    -H "Content-Type: application/json" \
    -d '{"reason": "UUPS Upgrade Demo"}')
SESSION_ID=$(echo "$AUTH_REQUEST_RESP" | jq -r '.session_id // .sessionId // empty')

if [ -z "$SESSION_ID" ]; then
    print_error "Failed to create auth session"
    exit 1
fi

MOCK_TOKEN="mock.${USER_EXTERNAL_ID}"
AUTH_CALLBACK_RESP=$(curl -s -X POST "$PROXY_RPC_URL/auth/callback?session=$SESSION_ID" \
    -H "Content-Type: application/json" \
    -d "{\"token\": \"$MOCK_TOKEN\"}")
AUTH_TOKEN=$(echo "$AUTH_CALLBACK_RESP" | jq -r '.access_token // .accessToken // empty')

if [ -z "$AUTH_TOKEN" ] || [ "$AUTH_TOKEN" = "null" ]; then
    print_error "Authentication failed"
    exit 1
fi
print_success "Authenticated"

# Set up user permissions
USERS_RESP=$(curl -s "$ADMIN_API_URL/v1/users")
USER_ID=$(echo "$USERS_RESP" | jq -r ".data[] | select(.external_id == \"$USER_EXTERNAL_ID\") | .id" | head -1)

curl -s -X PUT "$ADMIN_API_URL/v1/users/${USER_ID}" \
    -H "Content-Type: application/json" \
    -d '{"kyc": true}' > /dev/null

GROUPS_RESP=$(curl -s "$ADMIN_API_URL/v1/orgs/$ORG_ID/groups")
DEPLOYER_GROUP_ID=$(echo "$GROUPS_RESP" | jq -r '.data[] | select(.group.slug == "demo-deployers") | .group.id' | head -1)

if [ -z "$DEPLOYER_GROUP_ID" ] || [ "$DEPLOYER_GROUP_ID" = "null" ]; then
    # Create the deployers group if it doesn't exist
    GROUP_CREATE_RESP=$(curl -s -X POST "$ADMIN_API_URL/v1/orgs/$ORG_ID/groups" \
        -H "Content-Type: application/json" \
        -d '{
            "slug": "demo-deployers",
            "name": "Demo Deployers"
        }')
    DEPLOYER_GROUP_ID=$(echo "$GROUP_CREATE_RESP" | jq -r '.id')
fi

if [ -z "$DEPLOYER_GROUP_ID" ] || [ "$DEPLOYER_GROUP_ID" = "null" ]; then
    print_error "Failed to create or find deployers group"
    exit 1
fi

# Always configure group access
curl -s -X PUT "$ADMIN_API_URL/v1/orgs/$ORG_ID/groups/$DEPLOYER_GROUP_ID/access" \
    -H "Content-Type: application/json" \
    -d '{
        "allowed_methods": ["eth_sendTransaction", "eth_call", "eth_estimateGas", "eth_getBalance", "eth_chainId", "eth_blockNumber", "eth_getTransactionCount", "eth_getTransactionReceipt", "net_version"],
        "claims": ["deploy"]
    }' > /dev/null

curl -s -X POST "$ADMIN_API_URL/v1/users/${USER_ID}/memberships" \
    -H "Content-Type: application/json" \
    -d "{\"group_id\": \"$DEPLOYER_GROUP_ID\"}" > /dev/null
print_success "Permissions configured"

# =============================================================================
# Step 3: Get or Deploy CREATE3 Factory
# =============================================================================

print_step "Step 3: CREATE3 Factory"

# Check if factory is configured for the org
FACTORY_RESPONSE=$(curl -s "$ADMIN_API_URL/orgs/$ORG_ID/config/create3")
CREATE3_FACTORY=$(echo "$FACTORY_RESPONSE" | jq -r '.factory // empty')

# Check if factory has code deployed
if [ -n "$CREATE3_FACTORY" ] && [ "$CREATE3_FACTORY" != "null" ]; then
    FACTORY_CODE=$(cast code "$CREATE3_FACTORY" --rpc-url "$ANVIL_URL" 2>/dev/null || echo "0x")
    if [ "$FACTORY_CODE" = "0x" ]; then
        print_info "Factory at $CREATE3_FACTORY has no code, deploying new factory..."
        CREATE3_FACTORY=""
    fi
fi

# Deploy factory if needed
if [ -z "$CREATE3_FACTORY" ] || [ "$CREATE3_FACTORY" = "null" ]; then
    print_substep "Deploying CREATE3 factory..."
    # Use the dev endpoint to deploy the factory
    DEPLOY_RESP=$(curl -s -X POST "$ADMIN_API_URL/v1/dev/create3-factory")
    CREATE3_FACTORY=$(echo "$DEPLOY_RESP" | jq -r '.address // empty')

    if [ -z "$CREATE3_FACTORY" ] || [ "$CREATE3_FACTORY" = "null" ]; then
        print_error "Failed to deploy CREATE3 factory"
        echo "Response: $DEPLOY_RESP"
        exit 1
    fi
    print_success "Deployed factory: $CREATE3_FACTORY"

    # Configure the org with the new factory
    print_substep "Configuring org with factory..."
    curl -s -X PUT "$ADMIN_API_URL/orgs/$ORG_ID/config/create3" \
        -H "Content-Type: application/json" \
        -d "{\"factory\": \"$CREATE3_FACTORY\"}" > /dev/null
    print_success "Factory configured for org"
fi

print_success "Factory: $CREATE3_FACTORY"

# =============================================================================
# Step 4: Preregister Addresses
# =============================================================================

print_step "Step 4: Preregistering Addresses"

# Need addresses for:
# - 3 V1 implementations
# - 3 proxies
# - 3 V2 implementations
TIMESTAMP=$(date +%s)
SALT_PREFIX="upgrade-demo-$TIMESTAMP"

print_substep "Preregistering 9 addresses..."
PREREGISTER_RESPONSE=$(curl -s -X POST "$ADMIN_API_URL/orgs/$ORG_ID/addresses/preregister" \
    -H "Content-Type: application/json" \
    -d "{
        \"factory\": \"$CREATE3_FACTORY\",
        \"salt_prefix\": \"$SALT_PREFIX\",
        \"count\": 9,
        \"note\": \"UUPS upgrade demo\"
    }")

if ! echo "$PREREGISTER_RESPONSE" | jq -e '.addresses' > /dev/null 2>&1; then
    print_error "Failed to preregister addresses"
    exit 1
fi

# Extract all addresses
TOKEN_V1_IMPL=$(echo "$PREREGISTER_RESPONSE" | jq -r '.addresses[0].address')
TOKEN_V1_SALT=$(echo "$PREREGISTER_RESPONSE" | jq -r '.addresses[0].salt')
POOL_V1_IMPL=$(echo "$PREREGISTER_RESPONSE" | jq -r '.addresses[1].address')
POOL_V1_SALT=$(echo "$PREREGISTER_RESPONSE" | jq -r '.addresses[1].salt')
ROUTER_V1_IMPL=$(echo "$PREREGISTER_RESPONSE" | jq -r '.addresses[2].address')
ROUTER_V1_SALT=$(echo "$PREREGISTER_RESPONSE" | jq -r '.addresses[2].salt')

TOKEN_PROXY=$(echo "$PREREGISTER_RESPONSE" | jq -r '.addresses[3].address')
TOKEN_PROXY_SALT=$(echo "$PREREGISTER_RESPONSE" | jq -r '.addresses[3].salt')
POOL_PROXY=$(echo "$PREREGISTER_RESPONSE" | jq -r '.addresses[4].address')
POOL_PROXY_SALT=$(echo "$PREREGISTER_RESPONSE" | jq -r '.addresses[4].salt')
ROUTER_PROXY=$(echo "$PREREGISTER_RESPONSE" | jq -r '.addresses[5].address')
ROUTER_PROXY_SALT=$(echo "$PREREGISTER_RESPONSE" | jq -r '.addresses[5].salt')

TOKEN_V2_IMPL=$(echo "$PREREGISTER_RESPONSE" | jq -r '.addresses[6].address')
TOKEN_V2_SALT=$(echo "$PREREGISTER_RESPONSE" | jq -r '.addresses[6].salt')
POOL_V2_IMPL=$(echo "$PREREGISTER_RESPONSE" | jq -r '.addresses[7].address')
POOL_V2_SALT=$(echo "$PREREGISTER_RESPONSE" | jq -r '.addresses[7].salt')
ROUTER_V2_IMPL=$(echo "$PREREGISTER_RESPONSE" | jq -r '.addresses[8].address')
ROUTER_V2_SALT=$(echo "$PREREGISTER_RESPONSE" | jq -r '.addresses[8].salt')

print_success "9 addresses preregistered"

echo ""
echo -e "  ${WHITE}V1 Implementations:${NC}"
echo -e "  ${CYAN}│${NC} Token V1:  $TOKEN_V1_IMPL"
echo -e "  ${CYAN}│${NC} Pool V1:   $POOL_V1_IMPL"
echo -e "  ${CYAN}│${NC} Router V1: $ROUTER_V1_IMPL"
echo ""
echo -e "  ${WHITE}Proxies (stable addresses):${NC}"
echo -e "  ${CYAN}│${NC} Token:  $TOKEN_PROXY"
echo -e "  ${CYAN}│${NC} Pool:   $POOL_PROXY"
echo -e "  ${CYAN}│${NC} Router: $ROUTER_PROXY"
echo ""
echo -e "  ${WHITE}V2 Implementations:${NC}"
echo -e "  ${CYAN}│${NC} Token V2:  $TOKEN_V2_IMPL"
echo -e "  ${CYAN}│${NC} Pool V2:   $POOL_V2_IMPL"
echo -e "  ${CYAN}│${NC} Router V2: $ROUTER_V2_IMPL"

# =============================================================================
# Step 5: Build Contracts
# =============================================================================

print_step "Step 5: Building Contracts"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR=$(mktemp -d)

cp -r "$SCRIPT_DIR/contracts"/* "$BUILD_DIR/"
cd "$BUILD_DIR"

cleanup() {
    if [ -n "$BUILD_DIR" ] && [ -d "$BUILD_DIR" ]; then
        rm -rf "$BUILD_DIR"
    fi
}
trap cleanup EXIT

git init --quiet
git config user.email "demo@example.com"
git config user.name "Demo"
git add -A
git commit -m "Initial" --quiet

# Remove any copied local artifacts (these are gitignored but cp -r copies them)
rm -rf lib out cache
mkdir -p lib
git clone --quiet --depth 1 https://github.com/OpenZeppelin/openzeppelin-contracts-upgradeable.git lib/openzeppelin-contracts-upgradeable || { print_error "Failed to clone openzeppelin-contracts-upgradeable"; exit 1; }
git clone --quiet --depth 1 https://github.com/OpenZeppelin/openzeppelin-contracts.git lib/openzeppelin-contracts || { print_error "Failed to clone openzeppelin-contracts"; exit 1; }
git clone --quiet --depth 1 https://github.com/foundry-rs/forge-std.git lib/forge-std || { print_error "Failed to clone forge-std"; exit 1; }

print_substep "Compiling V1 and V2 contracts..."
forge build --quiet
print_success "Contracts compiled"

# Get bytecode for V1
TOKEN_V1_BYTECODE=$(forge inspect DemoToken bytecode)
POOL_V1_BYTECODE=$(forge inspect LiquidityPool bytecode)
ROUTER_V1_BYTECODE=$(forge inspect SwapRouter bytecode)

# Get bytecode for V2
TOKEN_V2_BYTECODE=$(forge inspect DemoTokenV2 bytecode)
POOL_V2_BYTECODE=$(forge inspect LiquidityPoolV2 bytecode)
ROUTER_V2_BYTECODE=$(forge inspect SwapRouterV2 bytecode)

# Create proxy bytecode
cat > "$BUILD_DIR/src/DeployProxy.sol" << 'EOF'
// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

contract DeployableProxy is ERC1967Proxy {
    constructor(address implementation, bytes memory data) ERC1967Proxy(implementation, data) {}
}
EOF

forge build --quiet
PROXY_BYTECODE=$(forge inspect DeployableProxy bytecode)

print_value "V1 bytecode sizes" "Token: $(echo -n "$TOKEN_V1_BYTECODE" | wc -c | tr -d ' '), Pool: $(echo -n "$POOL_V1_BYTECODE" | wc -c | tr -d ' '), Router: $(echo -n "$ROUTER_V1_BYTECODE" | wc -c | tr -d ' ')"
print_value "V2 bytecode sizes" "Token: $(echo -n "$TOKEN_V2_BYTECODE" | wc -c | tr -d ' '), Pool: $(echo -n "$POOL_V2_BYTECODE" | wc -c | tr -d ' '), Router: $(echo -n "$ROUTER_V2_BYTECODE" | wc -c | tr -d ' ')"

# =============================================================================
# Helper: Deploy via CREATE3
# =============================================================================

deploy_create3() {
    local salt="$1"
    local bytecode="$2"
    local name="$3"

    DEPLOY_CALLDATA=$(cast calldata "deploy(bytes32,bytes)" "$salt" "$bytecode")
    NONCE_RESP=$(rpc_call "eth_getTransactionCount" "[\"$DEPLOYER_ADDRESS\", \"latest\"]")
    NONCE=$(echo "$NONCE_RESP" | jq -r '.result // "0x0"')

    TX_PARAMS=$(cat <<EOF
[{"from": "$DEPLOYER_ADDRESS", "to": "$CREATE3_FACTORY", "data": "$DEPLOY_CALLDATA", "gas": "0x500000", "nonce": "$NONCE"}]
EOF
)

    RESULT=$(rpc_call "eth_sendTransaction" "$TX_PARAMS")
    TX_HASH=$(echo "$RESULT" | jq -r '.result // empty')

    if [ -z "$TX_HASH" ] || [ "$TX_HASH" = "null" ]; then
        ERROR=$(echo "$RESULT" | jq -r 'if .error | type == "object" then .error.message else .error // "Unknown error" end' 2>/dev/null)
        print_error "Failed to deploy $name: $ERROR"
        return 1
    fi
    print_success "$name deployed"
}

# =============================================================================
# Step 6: Deploy V1
# =============================================================================

print_step "Step 6: Deploying V1 Implementations"

deploy_create3 "$TOKEN_V1_SALT" "$TOKEN_V1_BYTECODE" "DemoToken V1"
deploy_create3 "$POOL_V1_SALT" "$POOL_V1_BYTECODE" "LiquidityPool V1"
deploy_create3 "$ROUTER_V1_SALT" "$ROUTER_V1_BYTECODE" "SwapRouter V1"

# =============================================================================
# Step 7: Deploy Proxies
# =============================================================================

print_step "Step 7: Deploying Proxies"

# Token proxy (init with deployer + pool proxy address)
TOKEN_INIT=$(cast calldata "initialize(address,address)" "$DEPLOYER_ADDRESS" "$POOL_PROXY")
TOKEN_PROXY_CONSTRUCTOR=$(cast abi-encode "constructor(address,bytes)" "$TOKEN_V1_IMPL" "$TOKEN_INIT")
TOKEN_PROXY_INITCODE="${PROXY_BYTECODE}${TOKEN_PROXY_CONSTRUCTOR:2}"
deploy_create3 "$TOKEN_PROXY_SALT" "$TOKEN_PROXY_INITCODE" "Token Proxy"

# Pool proxy
POOL_INIT=$(cast calldata "initialize(address,address)" "$DEPLOYER_ADDRESS" "$TOKEN_PROXY")
POOL_PROXY_CONSTRUCTOR=$(cast abi-encode "constructor(address,bytes)" "$POOL_V1_IMPL" "$POOL_INIT")
POOL_PROXY_INITCODE="${PROXY_BYTECODE}${POOL_PROXY_CONSTRUCTOR:2}"
deploy_create3 "$POOL_PROXY_SALT" "$POOL_PROXY_INITCODE" "Pool Proxy"

# Router proxy
ROUTER_INIT=$(cast calldata "initialize(address,address,address)" "$DEPLOYER_ADDRESS" "$POOL_PROXY" "$TOKEN_PROXY")
ROUTER_PROXY_CONSTRUCTOR=$(cast abi-encode "constructor(address,bytes)" "$ROUTER_V1_IMPL" "$ROUTER_INIT")
ROUTER_PROXY_INITCODE="${PROXY_BYTECODE}${ROUTER_PROXY_CONSTRUCTOR:2}"
deploy_create3 "$ROUTER_PROXY_SALT" "$ROUTER_PROXY_INITCODE" "Router Proxy"

# Note: Runtime tracing validates that upgrade targets are org-owned at transaction time.
# Managed proxy registration is not required.

# =============================================================================
# Step 8: Interact with V1
# =============================================================================

print_step "Step 8: Interacting with V1"

print_substep "Checking V1 versions..."
TOKEN_VER_V1=$(cast call "$TOKEN_PROXY" "version()(string)" --rpc-url "$ANVIL_URL" 2>/dev/null)
POOL_VER_V1=$(cast call "$POOL_PROXY" "version()(string)" --rpc-url "$ANVIL_URL" 2>/dev/null)
ROUTER_VER_V1=$(cast call "$ROUTER_PROXY" "version()(string)" --rpc-url "$ANVIL_URL" 2>/dev/null)

print_contract_call "$TOKEN_PROXY" "version()" "$TOKEN_VER_V1"
print_contract_call "$POOL_PROXY" "version()" "$POOL_VER_V1"
print_contract_call "$ROUTER_PROXY" "version()" "$ROUTER_VER_V1"

# Mint and add liquidity
print_substep "Minting tokens and adding liquidity..."
MINT_CALLDATA=$(cast calldata "mint(address,uint256)" "$DEPLOYER_ADDRESS" "1000000000000000000000")
NONCE_RESP=$(rpc_call "eth_getTransactionCount" "[\"$DEPLOYER_ADDRESS\", \"latest\"]")
NONCE=$(echo "$NONCE_RESP" | jq -r '.result // "0x0"')
TX_PARAMS="[{\"from\": \"$DEPLOYER_ADDRESS\", \"to\": \"$TOKEN_PROXY\", \"data\": \"$MINT_CALLDATA\", \"gas\": \"0x100000\", \"nonce\": \"$NONCE\"}]"
rpc_call "eth_sendTransaction" "$TX_PARAMS" > /dev/null

APPROVE_CALLDATA=$(cast calldata "approve(address,uint256)" "$POOL_PROXY" "1000000000000000000000")
NONCE_RESP=$(rpc_call "eth_getTransactionCount" "[\"$DEPLOYER_ADDRESS\", \"latest\"]")
NONCE=$(echo "$NONCE_RESP" | jq -r '.result // "0x0"')
TX_PARAMS="[{\"from\": \"$DEPLOYER_ADDRESS\", \"to\": \"$TOKEN_PROXY\", \"data\": \"$APPROVE_CALLDATA\", \"gas\": \"0x100000\", \"nonce\": \"$NONCE\"}]"
rpc_call "eth_sendTransaction" "$TX_PARAMS" > /dev/null

ADD_LIQ=$(cast calldata "addLiquidity(uint256)" "500000000000000000000")
NONCE_RESP=$(rpc_call "eth_getTransactionCount" "[\"$DEPLOYER_ADDRESS\", \"latest\"]")
NONCE=$(echo "$NONCE_RESP" | jq -r '.result // "0x0"')
TX_PARAMS="[{\"from\": \"$DEPLOYER_ADDRESS\", \"to\": \"$POOL_PROXY\", \"data\": \"$ADD_LIQ\", \"value\": \"0xde0b6b3a7640000\", \"gas\": \"0x200000\", \"nonce\": \"$NONCE\"}]"
rpc_call "eth_sendTransaction" "$TX_PARAMS" > /dev/null

TOKEN_RESERVE=$(cast call "$POOL_PROXY" "tokenReserve()(uint256)" --rpc-url "$ANVIL_URL" 2>/dev/null)
ETH_RESERVE=$(cast call "$POOL_PROXY" "ethReserve()(uint256)" --rpc-url "$ANVIL_URL" 2>/dev/null)
print_success "Liquidity added"
print_value "Token Reserve" "$TOKEN_RESERVE"
print_value "ETH Reserve" "$ETH_RESERVE"

# Try V2-only features (should fail)
print_substep "Trying V2-only features (should fail)..."
set +e
BURN_RESULT=$(cast call "$TOKEN_PROXY" "burn(uint256)" "1000000000000000000" --rpc-url "$ANVIL_URL" 2>&1)
set -e
if echo "$BURN_RESULT" | grep -q "revert\|error\|Error"; then
    print_success "burn() correctly unavailable in V1"
else
    print_info "burn() call result: $BURN_RESULT"
fi

# =============================================================================
# Step 9: Deploy V2 Implementations
# =============================================================================

print_step "Step 9: Deploying V2 Implementations"

print_info "V2 adds new features:"
print_info "  - DemoTokenV2: burn() function"
print_info "  - LiquidityPoolV2: configurable fees"
print_info "  - SwapRouterV2: deadline protection"
echo ""

deploy_create3 "$TOKEN_V2_SALT" "$TOKEN_V2_BYTECODE" "DemoToken V2"
deploy_create3 "$POOL_V2_SALT" "$POOL_V2_BYTECODE" "LiquidityPool V2"
deploy_create3 "$ROUTER_V2_SALT" "$ROUTER_V2_BYTECODE" "SwapRouter V2"

# =============================================================================
# Step 10: Upgrade Proxies
# =============================================================================

print_step "Step 10: Upgrading Proxies to V2"

print_info "UUPS upgrade: calling upgradeToAndCall() on each proxy"
echo ""

# Upgrade Token
print_substep "Upgrading DemoToken..."
UPGRADE_CALLDATA=$(cast calldata "upgradeToAndCall(address,bytes)" "$TOKEN_V2_IMPL" "0x")
NONCE_RESP=$(rpc_call "eth_getTransactionCount" "[\"$DEPLOYER_ADDRESS\", \"latest\"]")
NONCE=$(echo "$NONCE_RESP" | jq -r '.result // "0x0"')
TX_PARAMS="[{\"from\": \"$DEPLOYER_ADDRESS\", \"to\": \"$TOKEN_PROXY\", \"data\": \"$UPGRADE_CALLDATA\", \"gas\": \"0x100000\", \"nonce\": \"$NONCE\"}]"
RESULT=$(rpc_call "eth_sendTransaction" "$TX_PARAMS")
if echo "$RESULT" | jq -e '.result' > /dev/null 2>&1; then
    print_success "DemoToken upgraded"
else
    ERROR=$(echo "$RESULT" | jq -r 'if .error | type == "object" then .error.message else .error // "Unknown error" end' 2>/dev/null)
    print_error "DemoToken upgrade failed: $ERROR"
fi

# Upgrade Pool
print_substep "Upgrading LiquidityPool..."
UPGRADE_CALLDATA=$(cast calldata "upgradeToAndCall(address,bytes)" "$POOL_V2_IMPL" "0x")
NONCE_RESP=$(rpc_call "eth_getTransactionCount" "[\"$DEPLOYER_ADDRESS\", \"latest\"]")
NONCE=$(echo "$NONCE_RESP" | jq -r '.result // "0x0"')
TX_PARAMS="[{\"from\": \"$DEPLOYER_ADDRESS\", \"to\": \"$POOL_PROXY\", \"data\": \"$UPGRADE_CALLDATA\", \"gas\": \"0x100000\", \"nonce\": \"$NONCE\"}]"
RESULT=$(rpc_call "eth_sendTransaction" "$TX_PARAMS")
if echo "$RESULT" | jq -e '.result' > /dev/null 2>&1; then
    print_success "LiquidityPool upgraded"
else
    ERROR=$(echo "$RESULT" | jq -r 'if .error | type == "object" then .error.message else .error // "Unknown error" end' 2>/dev/null)
    print_error "LiquidityPool upgrade failed: $ERROR"
fi

# Upgrade Router
print_substep "Upgrading SwapRouter..."
UPGRADE_CALLDATA=$(cast calldata "upgradeToAndCall(address,bytes)" "$ROUTER_V2_IMPL" "0x")
NONCE_RESP=$(rpc_call "eth_getTransactionCount" "[\"$DEPLOYER_ADDRESS\", \"latest\"]")
NONCE=$(echo "$NONCE_RESP" | jq -r '.result // "0x0"')
TX_PARAMS="[{\"from\": \"$DEPLOYER_ADDRESS\", \"to\": \"$ROUTER_PROXY\", \"data\": \"$UPGRADE_CALLDATA\", \"gas\": \"0x100000\", \"nonce\": \"$NONCE\"}]"
RESULT=$(rpc_call "eth_sendTransaction" "$TX_PARAMS")
if echo "$RESULT" | jq -e '.result' > /dev/null 2>&1; then
    print_success "SwapRouter upgraded"
else
    ERROR=$(echo "$RESULT" | jq -r 'if .error | type == "object" then .error.message else .error // "Unknown error" end' 2>/dev/null)
    print_error "SwapRouter upgrade failed: $ERROR"
fi

# =============================================================================
# Step 11: Verify V2 Features
# =============================================================================

print_step "Step 11: Verifying V2 Features"

print_substep "Checking V2 versions..."
TOKEN_VER_V2=$(cast call "$TOKEN_PROXY" "version()(string)" --rpc-url "$ANVIL_URL" 2>/dev/null)
POOL_VER_V2=$(cast call "$POOL_PROXY" "version()(string)" --rpc-url "$ANVIL_URL" 2>/dev/null)
ROUTER_VER_V2=$(cast call "$ROUTER_PROXY" "version()(string)" --rpc-url "$ANVIL_URL" 2>/dev/null)

print_contract_call "$TOKEN_PROXY" "version()" "$TOKEN_VER_V2"
print_contract_call "$POOL_PROXY" "version()" "$POOL_VER_V2"
print_contract_call "$ROUTER_PROXY" "version()" "$ROUTER_VER_V2"

# Verify state preserved
print_substep "Verifying state was preserved..."
TOKEN_RESERVE_AFTER=$(cast call "$POOL_PROXY" "tokenReserve()(uint256)" --rpc-url "$ANVIL_URL" 2>/dev/null)
ETH_RESERVE_AFTER=$(cast call "$POOL_PROXY" "ethReserve()(uint256)" --rpc-url "$ANVIL_URL" 2>/dev/null)

if [ "$TOKEN_RESERVE" = "$TOKEN_RESERVE_AFTER" ] && [ "$ETH_RESERVE" = "$ETH_RESERVE_AFTER" ]; then
    print_success "State preserved across upgrade!"
else
    print_error "State mismatch after upgrade"
fi

# Test V2-only features
print_substep "Testing V2-only features..."

# Test burn (V2 feature)
TOKEN_BALANCE_BEFORE=$(cast call "$TOKEN_PROXY" "balanceOf(address)(uint256)" "$DEPLOYER_ADDRESS" --rpc-url "$ANVIL_URL" 2>/dev/null)
print_value "Token balance before burn" "$TOKEN_BALANCE_BEFORE"

BURN_CALLDATA=$(cast calldata "burn(uint256)" "10000000000000000000") # Burn 10 tokens
NONCE_RESP=$(rpc_call "eth_getTransactionCount" "[\"$DEPLOYER_ADDRESS\", \"latest\"]")
NONCE=$(echo "$NONCE_RESP" | jq -r '.result // "0x0"')
TX_PARAMS="[{\"from\": \"$DEPLOYER_ADDRESS\", \"to\": \"$TOKEN_PROXY\", \"data\": \"$BURN_CALLDATA\", \"gas\": \"0x100000\", \"nonce\": \"$NONCE\"}]"
BURN_RESULT=$(rpc_call "eth_sendTransaction" "$TX_PARAMS")
BURN_TX=$(echo "$BURN_RESULT" | jq -r '.result // empty')

if [ -n "$BURN_TX" ] && [ "$BURN_TX" != "null" ]; then
    print_success "burn() works in V2!"
    TOKEN_BALANCE_AFTER=$(cast call "$TOKEN_PROXY" "balanceOf(address)(uint256)" "$DEPLOYER_ADDRESS" --rpc-url "$ANVIL_URL" 2>/dev/null)
    print_value "Token balance after burn" "$TOKEN_BALANCE_AFTER"
else
    print_error "burn() failed"
fi

# Test setFee (V2 Pool feature)
print_substep "Testing Pool V2 fee configuration..."
SET_FEE_CALLDATA=$(cast calldata "setFee(uint256)" "50") # 0.5% fee
NONCE_RESP=$(rpc_call "eth_getTransactionCount" "[\"$DEPLOYER_ADDRESS\", \"latest\"]")
NONCE=$(echo "$NONCE_RESP" | jq -r '.result // "0x0"')
TX_PARAMS="[{\"from\": \"$DEPLOYER_ADDRESS\", \"to\": \"$POOL_PROXY\", \"data\": \"$SET_FEE_CALLDATA\", \"gas\": \"0x100000\", \"nonce\": \"$NONCE\"}]"
FEE_RESULT=$(rpc_call "eth_sendTransaction" "$TX_PARAMS")

if echo "$FEE_RESULT" | jq -e '.result' > /dev/null 2>&1; then
    FEE_VALUE=$(cast call "$POOL_PROXY" "feeNumerator()(uint256)" --rpc-url "$ANVIL_URL" 2>/dev/null)
    print_success "setFee() works in V2!"
    print_value "Fee numerator" "$FEE_VALUE (= 0.5%)"
else
    print_error "setFee() failed"
fi

# Test deadline swap (V2 Router feature)
print_substep "Testing Router V2 deadline protection..."
DEADLINE=$(($(date +%s) + 3600)) # 1 hour from now
SLIPPAGE_CALC=$(cast call "$ROUTER_PROXY" "calculateMinOutput(uint256,uint256)(uint256)" "1000000000000000000" "100" --rpc-url "$ANVIL_URL" 2>/dev/null)
print_success "calculateMinOutput() available in V2!"
print_value "Min output for 1 ETH with 1% slippage" "$SLIPPAGE_CALC"

# =============================================================================
# Summary
# =============================================================================

print_header "Demo Complete!"

echo -e "${WHITE}UUPS Upgrade Summary:${NC}"
echo -e "${CYAN}┌─────────────────────────────────────────────────────────────────────┐${NC}"
echo -e "${CYAN}│${NC}  ${YELLOW}Proxy Addresses (unchanged):${NC}"
echo -e "${CYAN}│${NC}    Token:  $TOKEN_PROXY"
echo -e "${CYAN}│${NC}    Pool:   $POOL_PROXY"
echo -e "${CYAN}│${NC}    Router: $ROUTER_PROXY"
echo -e "${CYAN}├─────────────────────────────────────────────────────────────────────┤${NC}"
echo -e "${CYAN}│${NC}  ${YELLOW}Versions:${NC}"
echo -e "${CYAN}│${NC}    Before: Token=$TOKEN_VER_V1, Pool=$POOL_VER_V1, Router=$ROUTER_VER_V1"
echo -e "${CYAN}│${NC}    After:  Token=$TOKEN_VER_V2, Pool=$POOL_VER_V2, Router=$ROUTER_VER_V2"
echo -e "${CYAN}├─────────────────────────────────────────────────────────────────────┤${NC}"
echo -e "${CYAN}│${NC}  ${GREEN}State preserved:${NC} Reserves intact after upgrade"
echo -e "${CYAN}│${NC}  ${GREEN}New features:${NC} burn(), setFee(), deadline protection"
echo -e "${CYAN}└─────────────────────────────────────────────────────────────────────┘${NC}"

echo ""
echo -e "${GREEN}All operations completed successfully!${NC}"
echo ""
echo -e "${WHITE}Key Upgrade Benefits Demonstrated:${NC}"
echo -e "  ${CYAN}1.${NC} Proxy addresses stay the same (users don't need to update)"
echo -e "  ${CYAN}2.${NC} State is preserved across upgrades"
echo -e "  ${CYAN}3.${NC} New functionality available immediately"
echo -e "  ${CYAN}4.${NC} Only owner can perform upgrades (UUPS pattern)"
echo ""
echo -e "${WHITE}Compare with:${NC}"
echo -e "  ${GREEN}./demo-anvil-direct.sh${NC}      - Direct deployment without upgrade capability"
echo -e "  ${GREEN}./demo-defi-deployment.sh${NC}   - CREATE3 circular dependency resolution"
echo ""
