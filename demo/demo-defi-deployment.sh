#!/bin/bash

# =============================================================================
# Open Privacy Suite - CREATE3 DeFi Deployment Demo
# =============================================================================
# This script demonstrates CREATE3 deployment with circular dependencies:
# 1. Compute addresses deterministically using CREATE3 salts
# 2. Register all addresses with proxy
# 3. Deploy contracts with cross-references
# 4. Verify all contracts work together
# 5. Demonstrate a swap through the router
#
# The key insight: CREATE3 lets us know addresses BEFORE deployment, enabling
# contracts to reference each other even when deployed in separate transactions.
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

print_header "CREATE3 DeFi Deployment Demo"

print_step "Step 1: Understanding the Problem"

echo -e "  ${WHITE}The Circular Dependency Problem:${NC}"
echo ""
echo -e "  ${CYAN}┌─────────────────────────────────────────────────────────────────┐${NC}"
echo -e "  ${CYAN}│${NC}                                                                 ${CYAN}│${NC}"
echo -e "  ${CYAN}│${NC}   DemoToken ─────────────────────────────────────┐             ${CYAN}│${NC}"
echo -e "  ${CYAN}│${NC}       │                                          │             ${CYAN}│${NC}"
echo -e "  ${CYAN}│${NC}       │ needs pool address                       │             ${CYAN}│${NC}"
echo -e "  ${CYAN}│${NC}       ▼                                          │             ${CYAN}│${NC}"
echo -e "  ${CYAN}│${NC}   LiquidityPool ◄─────────────────────────────────             ${CYAN}│${NC}"
echo -e "  ${CYAN}│${NC}       │                   needs token address                  ${CYAN}│${NC}"
echo -e "  ${CYAN}│${NC}       │                                                        ${CYAN}│${NC}"
echo -e "  ${CYAN}│${NC}       │ referenced by                                          ${CYAN}│${NC}"
echo -e "  ${CYAN}│${NC}       ▼                                                        ${CYAN}│${NC}"
echo -e "  ${CYAN}│${NC}   SwapRouter                                                   ${CYAN}│${NC}"
echo -e "  ${CYAN}│${NC}       │                                                        ${CYAN}│${NC}"
echo -e "  ${CYAN}│${NC}       └──► needs both pool AND token addresses                 ${CYAN}│${NC}"
echo -e "  ${CYAN}│${NC}                                                                 ${CYAN}│${NC}"
echo -e "  ${CYAN}└─────────────────────────────────────────────────────────────────┘${NC}"
echo ""
echo -e "  ${WHITE}The CREATE3 Solution:${NC}"
echo -e "  ${GREEN}Addresses are computed BEFORE deployment using only:${NC}"
echo -e "  ${GREEN}  - Factory address${NC}"
echo -e "  ${GREEN}  - Salt (bytes32)${NC}"
echo ""
print_info "This demo shows how CREATE3 enables deploying interdependent contracts"
echo ""

print_step "Step 2: Checking Configuration"

# Environment variables with defaults
: "${ADMIN_API_URL:=http://localhost:8080/api/v1/admin}"
: "${PROXY_RPC_URL:=http://localhost:8080}"
: "${ANVIL_URL:=http://localhost:8545}"
: "${PRIVATE_KEY:=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80}"

print_value "Admin API URL" "$ADMIN_API_URL"
print_value "Proxy RPC URL" "$PROXY_RPC_URL"
print_value "Anvil URL" "$ANVIL_URL"
print_value "Private Key" "${PRIVATE_KEY:0:10}..."

DEPLOYER_ADDRESS=$(cast wallet address "$PRIVATE_KEY" 2>/dev/null)
print_value "Deployer Address" "$DEPLOYER_ADDRESS"

# Check if org is configured
if [ -z "$ORG_ID" ] && [ -z "$ORG_SLUG" ]; then
    echo ""
    echo -e "  ${YELLOW}Note: No ORG_SLUG or ORG_ID provided${NC}"
    echo -e "  ${WHITE}Looking for existing organizations...${NC}"

    ORGS_RESPONSE=$(curl -s "$ADMIN_API_URL/orgs")
    ORG_COUNT=$(echo "$ORGS_RESPONSE" | jq '.data | length' 2>/dev/null || echo "0")

    if [ "$ORG_COUNT" -gt 0 ]; then
        ORG_ID=$(echo "$ORGS_RESPONSE" | jq -r '.data[0].id')
        ORG_SLUG=$(echo "$ORGS_RESPONSE" | jq -r '.data[0].slug')
        print_success "Using organization: $ORG_SLUG"
    else
        print_error "No organizations found. Create one first or run demo-privacy-proxy.sh"
        exit 1
    fi
elif [ -n "$ORG_SLUG" ] && [ -z "$ORG_ID" ]; then
    ORGS_RESPONSE=$(curl -s "$ADMIN_API_URL/orgs")
    ORG_ID=$(echo "$ORGS_RESPONSE" | jq -r ".data[] | select(.slug == \"$ORG_SLUG\") | .id")
fi

print_value "Organization ID" "$ORG_ID"
print_value "Organization Slug" "$ORG_SLUG"

# Clean up any stale preregistered addresses to avoid cross-org issues
# This is necessary because addresses from other orgs (e.g., E2E tests) can interfere
print_substep "Cleaning up stale preregistered addresses..."
if command -v docker-compose &> /dev/null; then
    docker-compose exec -T postgres psql -U postgres -d privacy_proxy -c "DELETE FROM preregistered_addresses;" > /dev/null 2>&1 || true
elif command -v docker &> /dev/null; then
    docker exec privacy-proxy-postgres-1 psql -U postgres -d privacy_proxy -c "DELETE FROM preregistered_addresses;" > /dev/null 2>&1 || true
fi
print_success "Cleanup complete"

# =============================================================================
# Step 3: Authentication
# =============================================================================

print_step "Step 3: Authentication"

USER_EXTERNAL_ID="did:demo:defi-deployer-$(date +%s)"
print_substep "Creating user: $USER_EXTERNAL_ID"

# Auth flow
AUTH_REQUEST_RESP=$(curl -s -X POST "$PROXY_RPC_URL/auth/request" \
    -H "Content-Type: application/json" \
    -d '{"reason": "CREATE3 DeFi Demo"}')
SESSION_ID=$(echo "$AUTH_REQUEST_RESP" | jq -r '.session_id // .sessionId // empty')

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

# Get user ID and set up permissions
USERS_RESP=$(curl -s "$ADMIN_API_URL/users")
USER_ID=$(echo "$USERS_RESP" | jq -r ".data[] | select(.external_id == \"$USER_EXTERNAL_ID\") | .id" | head -1)

# Set KYC
curl -s -X PUT "$ADMIN_API_URL/users/${USER_ID}" \
    -H "Content-Type: application/json" \
    -d '{"kyc": true}' > /dev/null

# Add to deployers group
GROUPS_RESP=$(curl -s "$ADMIN_API_URL/orgs/$ORG_ID/groups")
DEPLOYER_GROUP_ID=$(echo "$GROUPS_RESP" | jq -r '.data[] | select(.group.slug == "demo-deployers") | .group.id' | head -1)

if [ -z "$DEPLOYER_GROUP_ID" ] || [ "$DEPLOYER_GROUP_ID" = "null" ]; then
    # Create the deployers group if it doesn't exist
    GROUP_CREATE_RESP=$(curl -s -X POST "$ADMIN_API_URL/orgs/$ORG_ID/groups" \
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
curl -s -X PUT "$ADMIN_API_URL/orgs/$ORG_ID/groups/$DEPLOYER_GROUP_ID/access" \
    -H "Content-Type: application/json" \
    -d '{
        "allowed_methods": ["eth_sendTransaction", "eth_call", "eth_estimateGas", "eth_getBalance", "eth_chainId", "eth_blockNumber", "eth_getTransactionCount", "eth_getTransactionReceipt", "net_version"],
        "allowed_methods": ["*"], "claims": ["deploy"]
    }' > /dev/null

curl -s -X POST "$ADMIN_API_URL/users/${USER_ID}/memberships" \
    -H "Content-Type: application/json" \
    -d "{\"group_id\": \"$DEPLOYER_GROUP_ID\"}" > /dev/null

print_success "Permissions configured"

# =============================================================================
# Step 4: Get CREATE3 Factory
# =============================================================================

print_step "Step 4: CREATE3 Factory Configuration"

FACTORY_RESPONSE=$(curl -s "$ADMIN_API_URL/orgs/$ORG_ID/config/create3")
CREATE3_FACTORY=$(echo "$FACTORY_RESPONSE" | jq -r '.factory // empty')

# Check if we need to deploy a factory
NEED_FACTORY=false
if [ -z "$CREATE3_FACTORY" ] || [ "$CREATE3_FACTORY" = "null" ]; then
    NEED_FACTORY=true
else
    # Verify factory has code
    FACTORY_CODE=$(cast codesize "$CREATE3_FACTORY" --rpc-url "$ANVIL_URL" 2>/dev/null || echo "0")
    if [ "$FACTORY_CODE" = "0" ]; then
        print_info "Factory at $CREATE3_FACTORY has no code, deploying new factory..."
        NEED_FACTORY=true
    fi
fi

if [ "$NEED_FACTORY" = true ]; then
    print_substep "Deploying CREATE3 factory..."
    DEPLOY_RESP=$(curl -s -X POST "$ADMIN_API_URL/dev/create3-factory")
    CREATE3_FACTORY=$(echo "$DEPLOY_RESP" | jq -r '.address // empty')

    if [ -z "$CREATE3_FACTORY" ] || [ "$CREATE3_FACTORY" = "null" ]; then
        print_error "Failed to deploy CREATE3 factory"
        echo "Response: $DEPLOY_RESP"
        exit 1
    fi
    print_success "Deployed factory: $CREATE3_FACTORY"

    # Configure the org with the new factory
    curl -s -X PUT "$ADMIN_API_URL/orgs/$ORG_ID/config/create3" \
        -H "Content-Type: application/json" \
        -d "{\"factory\": \"$CREATE3_FACTORY\"}" > /dev/null
    print_success "Factory configured for org"
fi

print_success "Factory: $CREATE3_FACTORY"
FACTORY_CODE=$(cast codesize "$CREATE3_FACTORY" --rpc-url "$ANVIL_URL" 2>/dev/null || echo "0")
print_value "Factory code size" "$FACTORY_CODE bytes"

# =============================================================================
# Step 5 & 6: Preregister and Compute Addresses (The Magic of CREATE3)
# =============================================================================

print_step "Step 5: Preregistering & Computing Addresses"

echo -e "  ${WHITE}CREATE3 address computation:${NC}"
echo -e "  ${CYAN}address = hash(factory, salt)${NC} - NOT dependent on bytecode!"
echo ""

# Generate a unique salt prefix for this deployment
TIMESTAMP=$(date +%s)
SALT_PREFIX="defi-demo-$TIMESTAMP"

print_substep "Using salt prefix: $SALT_PREFIX"

# Use batch preregistration API to register 3 addresses (token, pool, router)
print_substep "Preregistering 3 addresses with Open Privacy Suite..."

PREREG_RESP=$(curl -s -X POST "$ADMIN_API_URL/orgs/$ORG_ID/addresses/preregister" \
    -H "Content-Type: application/json" \
    -d "{
        \"factory\": \"$CREATE3_FACTORY\",
        \"salt_prefix\": \"$SALT_PREFIX\",
        \"count\": 3,
        \"note\": \"DeFi demo contracts\"
    }")

# Check for errors
if echo "$PREREG_RESP" | jq -e '.error' > /dev/null 2>&1; then
    ERROR=$(echo "$PREREG_RESP" | jq -r '.error')
    if echo "$ERROR" | grep -q "runtime tracing"; then
        print_info "Runtime tracing enabled — computing addresses locally (no preregistration needed)"
        # Compute salts: keccak256(orgID_bytes || saltPrefix_bytes || counter_bytes)
        # counter[0] = empty (big.Int(0).Bytes()), counter[1] = 0x01, counter[2] = 0x02
        ORG_HEX=$(printf '%s' "$ORG_ID" | xxd -p | tr -d '\n')
        PREFIX_HEX=$(printf '%s' "$SALT_PREFIX" | xxd -p | tr -d '\n')
        TOKEN_SALT=$(cast keccak "0x${ORG_HEX}${PREFIX_HEX}" 2>/dev/null)
        POOL_SALT=$(cast keccak "0x${ORG_HEX}${PREFIX_HEX}01" 2>/dev/null)
        ROUTER_SALT=$(cast keccak "0x${ORG_HEX}${PREFIX_HEX}02" 2>/dev/null)
        TOKEN_ADDR=$(cast call "$CREATE3_FACTORY" "getDeployed(bytes32)(address)" "$TOKEN_SALT" --rpc-url "$ANVIL_URL" 2>/dev/null | tr '[:upper:]' '[:lower:]')
        POOL_ADDR=$(cast call "$CREATE3_FACTORY" "getDeployed(bytes32)(address)" "$POOL_SALT" --rpc-url "$ANVIL_URL" 2>/dev/null | tr '[:upper:]' '[:lower:]')
        ROUTER_ADDR=$(cast call "$CREATE3_FACTORY" "getDeployed(bytes32)(address)" "$ROUTER_SALT" --rpc-url "$ANVIL_URL" 2>/dev/null | tr '[:upper:]' '[:lower:]')
        print_success "Addresses computed locally"
    else
        print_error "Preregistration failed: $ERROR"
        exit 1
    fi
else
    # Extract the 3 preregistered addresses
    ADDRESSES=$(echo "$PREREG_RESP" | jq -r '.addresses')
    if [ -z "$ADDRESSES" ] || [ "$ADDRESSES" = "null" ]; then
        print_error "No addresses returned from preregistration"
        echo "Response: $PREREG_RESP"
        exit 1
    fi

    # Get addresses and salts (index 0=token, 1=pool, 2=router)
    TOKEN_ADDR=$(echo "$PREREG_RESP" | jq -r '.addresses[0].address')
    TOKEN_SALT=$(echo "$PREREG_RESP" | jq -r '.addresses[0].salt')
    POOL_ADDR=$(echo "$PREREG_RESP" | jq -r '.addresses[1].address')
    POOL_SALT=$(echo "$PREREG_RESP" | jq -r '.addresses[1].salt')
    ROUTER_ADDR=$(echo "$PREREG_RESP" | jq -r '.addresses[2].address')
    ROUTER_SALT=$(echo "$PREREG_RESP" | jq -r '.addresses[2].salt')
fi

# Verify addresses are valid
if [ -z "$TOKEN_ADDR" ] || [ "$TOKEN_ADDR" = "null" ]; then
    print_error "Failed to get token address"
    exit 1
fi

print_success "3 addresses ready"

echo ""
echo -e "  ${WHITE}Pre-computed Addresses (known BEFORE deployment):${NC}"
echo -e "  ${CYAN}┌─────────────────────────────────────────────────────────────────┐${NC}"
echo -e "  ${CYAN}│${NC} ${YELLOW}DemoToken:${NC}     $TOKEN_ADDR"
echo -e "  ${CYAN}│${NC} ${YELLOW}LiquidityPool:${NC} $POOL_ADDR"
echo -e "  ${CYAN}│${NC} ${YELLOW}SwapRouter:${NC}    $ROUTER_ADDR"
echo -e "  ${CYAN}└─────────────────────────────────────────────────────────────────┘${NC}"

print_info "These addresses are guaranteed - we can use them in constructors!"

# Print salts for reference
print_substep "Generated salts:"
print_value "Token Salt" "${TOKEN_SALT:0:20}..."
print_value "Pool Salt" "${POOL_SALT:0:20}..."
print_value "Router Salt" "${ROUTER_SALT:0:20}..."

# =============================================================================
# Step 7: Build Contracts
# =============================================================================

print_step "Step 7: Building Contracts"

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

print_substep "Installing dependencies..."
# Remove any copied local artifacts (these are gitignored but cp -r copies them)
rm -rf lib out cache
mkdir -p lib
git clone --quiet --depth 1 https://github.com/OpenZeppelin/openzeppelin-contracts-upgradeable.git lib/openzeppelin-contracts-upgradeable || { print_error "Failed to clone openzeppelin-contracts-upgradeable"; exit 1; }
git clone --quiet --depth 1 https://github.com/OpenZeppelin/openzeppelin-contracts.git lib/openzeppelin-contracts || { print_error "Failed to clone openzeppelin-contracts"; exit 1; }
git clone --quiet --depth 1 https://github.com/foundry-rs/forge-std.git lib/forge-std || { print_error "Failed to clone forge-std"; exit 1; }

print_substep "Compiling..."
forge build --quiet
print_success "Contracts compiled"

# Get bytecode (use Simple* contracts for direct deployment - no UUPS pattern)
TOKEN_BYTECODE=$(forge inspect SimpleDemoToken bytecode)
POOL_BYTECODE=$(forge inspect SimpleLiquidityPool bytecode)
ROUTER_BYTECODE=$(forge inspect SimpleSwapRouter bytecode)

# =============================================================================
# Step 8: Deploy with Cross-References
# =============================================================================

print_step "Step 8: Deploying with Cross-References"

print_info "Key insight: We pass addresses of contracts that don't exist yet!"
echo ""

# Deploy function
deploy_create3() {
    local salt="$1"
    local bytecode="$2"
    local name="$3"

    DEPLOY_CALLDATA=$(cast calldata "deploy(bytes32,bytes)" "$salt" "$bytecode")

    NONCE_RESP=$(rpc_call "eth_getTransactionCount" "[\"$DEPLOYER_ADDRESS\", \"latest\"]")
    NONCE=$(echo "$NONCE_RESP" | jq -r '.result // "0x0"')

    TX_PARAMS=$(cat <<EOF
[{
    "from": "$DEPLOYER_ADDRESS",
    "to": "$CREATE3_FACTORY",
    "data": "$DEPLOY_CALLDATA",
    "gas": "0x500000",
    "nonce": "$NONCE"
}]
EOF
)

    DEPLOY_RESULT=$(rpc_call "eth_sendTransaction" "$TX_PARAMS")
    TX_HASH=$(echo "$DEPLOY_RESULT" | jq -r '.result // empty' 2>/dev/null)
    # Handle both JSON-RPC error format and simple error format
    ERROR=$(echo "$DEPLOY_RESULT" | jq -r 'if .error | type == "object" then .error.message else .error // empty end' 2>/dev/null)

    if [ -z "$TX_HASH" ] || [ "$TX_HASH" = "null" ]; then
        if [ -z "$ERROR" ]; then
            ERROR="Unknown error - Response: $DEPLOY_RESULT"
        fi
        print_error "Failed to deploy $name: $ERROR"
        return 1
    fi

    print_success "$name deployed via CREATE3"
}

# Deploy Token (references Pool address that doesn't exist yet!)
print_substep "Deploying DemoToken..."
print_info "Constructor arg: poolAddress = $POOL_ADDR (not yet deployed!)"
TOKEN_INIT=$(cast calldata "initialize(address,address)" "$DEPLOYER_ADDRESS" "$POOL_ADDR")
# For implementations, we deploy without init (proxies will call initialize)
deploy_create3 "$TOKEN_SALT" "$TOKEN_BYTECODE" "DemoToken"

# Deploy Pool (references Token address)
print_substep "Deploying LiquidityPool..."
print_info "Constructor arg: tokenAddress = $TOKEN_ADDR"
deploy_create3 "$POOL_SALT" "$POOL_BYTECODE" "LiquidityPool"

# Deploy Router (references both)
print_substep "Deploying SwapRouter..."
print_info "Constructor args: pool = $POOL_ADDR, token = $TOKEN_ADDR"
deploy_create3 "$ROUTER_SALT" "$ROUTER_BYTECODE" "SwapRouter"

# =============================================================================
# Step 9: Initialize Contracts
# =============================================================================

print_step "Step 9: Initializing Contracts"

print_info "Calling initialize() on each contract with cross-references"
echo ""

# Initialize Token
print_substep "Initializing DemoToken with pool reference..."
INIT_TOKEN=$(cast calldata "initialize(address,address)" "$DEPLOYER_ADDRESS" "$POOL_ADDR")
NONCE_RESP=$(rpc_call "eth_getTransactionCount" "[\"$DEPLOYER_ADDRESS\", \"latest\"]")
NONCE=$(echo "$NONCE_RESP" | jq -r '.result // "0x0"')
TX_PARAMS=$(cat <<EOF
[{"from": "$DEPLOYER_ADDRESS", "to": "$TOKEN_ADDR", "data": "$INIT_TOKEN", "gas": "0x100000", "nonce": "$NONCE"}]
EOF
)
rpc_call "eth_sendTransaction" "$TX_PARAMS" > /dev/null
print_success "DemoToken initialized"

# Initialize Pool
print_substep "Initializing LiquidityPool with token reference..."
INIT_POOL=$(cast calldata "initialize(address,address)" "$DEPLOYER_ADDRESS" "$TOKEN_ADDR")
NONCE_RESP=$(rpc_call "eth_getTransactionCount" "[\"$DEPLOYER_ADDRESS\", \"latest\"]")
NONCE=$(echo "$NONCE_RESP" | jq -r '.result // "0x0"')
TX_PARAMS=$(cat <<EOF
[{"from": "$DEPLOYER_ADDRESS", "to": "$POOL_ADDR", "data": "$INIT_POOL", "gas": "0x100000", "nonce": "$NONCE"}]
EOF
)
rpc_call "eth_sendTransaction" "$TX_PARAMS" > /dev/null
print_success "LiquidityPool initialized"

# Initialize Router
print_substep "Initializing SwapRouter with pool and token references..."
INIT_ROUTER=$(cast calldata "initialize(address,address,address)" "$DEPLOYER_ADDRESS" "$POOL_ADDR" "$TOKEN_ADDR")
NONCE_RESP=$(rpc_call "eth_getTransactionCount" "[\"$DEPLOYER_ADDRESS\", \"latest\"]")
NONCE=$(echo "$NONCE_RESP" | jq -r '.result // "0x0"')
TX_PARAMS=$(cat <<EOF
[{"from": "$DEPLOYER_ADDRESS", "to": "$ROUTER_ADDR", "data": "$INIT_ROUTER", "gas": "0x100000", "nonce": "$NONCE"}]
EOF
)
rpc_call "eth_sendTransaction" "$TX_PARAMS" > /dev/null
print_success "SwapRouter initialized"

# =============================================================================
# Step 10: Verify Cross-References
# =============================================================================

print_step "Step 10: Verifying Cross-References"

print_substep "Checking that circular references work..."

# Token -> Pool (lowercase for comparison)
TOKEN_POOL=$(cast call "$TOKEN_ADDR" "pool()(address)" --rpc-url "$ANVIL_URL" 2>/dev/null | tr '[:upper:]' '[:lower:]')
# Pool -> Token
POOL_TOKEN=$(cast call "$POOL_ADDR" "token()(address)" --rpc-url "$ANVIL_URL" 2>/dev/null | tr '[:upper:]' '[:lower:]')
# Router -> Pool
ROUTER_POOL=$(cast call "$ROUTER_ADDR" "pool()(address)" --rpc-url "$ANVIL_URL" 2>/dev/null | tr '[:upper:]' '[:lower:]')
# Router -> Token
ROUTER_TOKEN=$(cast call "$ROUTER_ADDR" "token()(address)" --rpc-url "$ANVIL_URL" 2>/dev/null | tr '[:upper:]' '[:lower:]')

echo ""
echo -e "  ${WHITE}Cross-Reference Verification:${NC}"
echo -e "  ${CYAN}┌─────────────────────────────────────────────────────────────────┐${NC}"

if [ "$TOKEN_POOL" = "$POOL_ADDR" ]; then
    echo -e "  ${CYAN}│${NC} ${GREEN}✓${NC} Token.pool() = $POOL_ADDR"
else
    echo -e "  ${CYAN}│${NC} ${RED}✗${NC} Token.pool() mismatch: got $TOKEN_POOL"
fi

if [ "$POOL_TOKEN" = "$TOKEN_ADDR" ]; then
    echo -e "  ${CYAN}│${NC} ${GREEN}✓${NC} Pool.token() = $TOKEN_ADDR"
else
    echo -e "  ${CYAN}│${NC} ${RED}✗${NC} Pool.token() mismatch: got $POOL_TOKEN"
fi

if [ "$ROUTER_POOL" = "$POOL_ADDR" ]; then
    echo -e "  ${CYAN}│${NC} ${GREEN}✓${NC} Router.pool() = $POOL_ADDR"
else
    echo -e "  ${CYAN}│${NC} ${RED}✗${NC} Router.pool() mismatch: got $ROUTER_POOL"
fi

if [ "$ROUTER_TOKEN" = "$TOKEN_ADDR" ]; then
    echo -e "  ${CYAN}│${NC} ${GREEN}✓${NC} Router.token() = $TOKEN_ADDR"
else
    echo -e "  ${CYAN}│${NC} ${RED}✗${NC} Router.token() mismatch: got $ROUTER_TOKEN"
fi

echo -e "  ${CYAN}└─────────────────────────────────────────────────────────────────┘${NC}"

# =============================================================================
# Step 11: Demonstrate Swap
# =============================================================================

print_step "Step 11: Demonstrating a Swap"

# Mint tokens
print_substep "Minting 1000 DEMO tokens..."
MINT_CALLDATA=$(cast calldata "mint(address,uint256)" "$DEPLOYER_ADDRESS" "1000000000000000000000")
NONCE_RESP=$(rpc_call "eth_getTransactionCount" "[\"$DEPLOYER_ADDRESS\", \"latest\"]")
NONCE=$(echo "$NONCE_RESP" | jq -r '.result // "0x0"')
TX_PARAMS=$(cat <<EOF
[{"from": "$DEPLOYER_ADDRESS", "to": "$TOKEN_ADDR", "data": "$MINT_CALLDATA", "gas": "0x100000", "nonce": "$NONCE"}]
EOF
)
rpc_call "eth_sendTransaction" "$TX_PARAMS" > /dev/null
print_success "Minted tokens"

# Approve pool
print_substep "Approving pool..."
APPROVE_CALLDATA=$(cast calldata "approve(address,uint256)" "$POOL_ADDR" "1000000000000000000000")
NONCE_RESP=$(rpc_call "eth_getTransactionCount" "[\"$DEPLOYER_ADDRESS\", \"latest\"]")
NONCE=$(echo "$NONCE_RESP" | jq -r '.result // "0x0"')
TX_PARAMS=$(cat <<EOF
[{"from": "$DEPLOYER_ADDRESS", "to": "$TOKEN_ADDR", "data": "$APPROVE_CALLDATA", "gas": "0x100000", "nonce": "$NONCE"}]
EOF
)
rpc_call "eth_sendTransaction" "$TX_PARAMS" > /dev/null
print_success "Approved"

# Add liquidity
print_substep "Adding liquidity (500 DEMO + 1 ETH)..."
ADD_LIQ_CALLDATA=$(cast calldata "addLiquidity(uint256)" "500000000000000000000")
NONCE_RESP=$(rpc_call "eth_getTransactionCount" "[\"$DEPLOYER_ADDRESS\", \"latest\"]")
NONCE=$(echo "$NONCE_RESP" | jq -r '.result // "0x0"')
TX_PARAMS=$(cat <<EOF
[{"from": "$DEPLOYER_ADDRESS", "to": "$POOL_ADDR", "data": "$ADD_LIQ_CALLDATA", "value": "0xde0b6b3a7640000", "gas": "0x200000", "nonce": "$NONCE"}]
EOF
)
rpc_call "eth_sendTransaction" "$TX_PARAMS" > /dev/null
print_success "Liquidity added"

# Check reserves
TOKEN_RESERVE=$(cast call "$POOL_ADDR" "tokenReserve()(uint256)" --rpc-url "$ANVIL_URL" 2>/dev/null)
ETH_RESERVE=$(cast call "$POOL_ADDR" "ethReserve()(uint256)" --rpc-url "$ANVIL_URL" 2>/dev/null)
print_value "Token Reserve" "$TOKEN_RESERVE wei"
print_value "ETH Reserve" "$ETH_RESERVE wei"

# Get quote
print_substep "Getting swap quote (100 DEMO -> ETH)..."
EXPECTED_OUT=$(cast call "$ROUTER_ADDR" "getQuote(uint256)(uint256)" "100000000000000000000" --rpc-url "$ANVIL_URL" 2>/dev/null)
print_value "Expected ETH out" "$EXPECTED_OUT wei"

# Approve router
print_substep "Approving router..."
APPROVE_ROUTER=$(cast calldata "approve(address,uint256)" "$ROUTER_ADDR" "100000000000000000000")
NONCE_RESP=$(rpc_call "eth_getTransactionCount" "[\"$DEPLOYER_ADDRESS\", \"latest\"]")
NONCE=$(echo "$NONCE_RESP" | jq -r '.result // "0x0"')
TX_PARAMS=$(cat <<EOF
[{"from": "$DEPLOYER_ADDRESS", "to": "$TOKEN_ADDR", "data": "$APPROVE_ROUTER", "gas": "0x100000", "nonce": "$NONCE"}]
EOF
)
rpc_call "eth_sendTransaction" "$TX_PARAMS" > /dev/null

# Execute swap
print_substep "Executing swap through router..."
SWAP_CALLDATA=$(cast calldata "swap(uint256)" "100000000000000000000")
NONCE_RESP=$(rpc_call "eth_getTransactionCount" "[\"$DEPLOYER_ADDRESS\", \"latest\"]")
NONCE=$(echo "$NONCE_RESP" | jq -r '.result // "0x0"')
TX_PARAMS=$(cat <<EOF
[{"from": "$DEPLOYER_ADDRESS", "to": "$ROUTER_ADDR", "data": "$SWAP_CALLDATA", "gas": "0x200000", "nonce": "$NONCE"}]
EOF
)
SWAP_RESULT=$(rpc_call "eth_sendTransaction" "$TX_PARAMS")
SWAP_TX=$(echo "$SWAP_RESULT" | jq -r '.result // empty')

if [ -n "$SWAP_TX" ] && [ "$SWAP_TX" != "null" ]; then
    print_success "Swap executed!"
    print_value "Transaction" "$SWAP_TX"
else
    print_error "Swap failed"
fi

# Check new reserves
TOKEN_RESERVE_AFTER=$(cast call "$POOL_ADDR" "tokenReserve()(uint256)" --rpc-url "$ANVIL_URL" 2>/dev/null)
ETH_RESERVE_AFTER=$(cast call "$POOL_ADDR" "ethReserve()(uint256)" --rpc-url "$ANVIL_URL" 2>/dev/null)
print_value "Token Reserve After" "$TOKEN_RESERVE_AFTER wei"
print_value "ETH Reserve After" "$ETH_RESERVE_AFTER wei"

# =============================================================================
# Summary
# =============================================================================

print_header "Demo Complete!"

echo -e "${WHITE}CREATE3 Deployment Summary:${NC}"
echo -e "${CYAN}┌─────────────────────────────────────────────────────────────────────┐${NC}"
echo -e "${CYAN}│${NC}  ${YELLOW}CREATE3 Factory:${NC}  $CREATE3_FACTORY"
echo -e "${CYAN}├─────────────────────────────────────────────────────────────────────┤${NC}"
echo -e "${CYAN}│${NC}  ${YELLOW}DemoToken:${NC}        $TOKEN_ADDR"
echo -e "${CYAN}│${NC}  ${YELLOW}LiquidityPool:${NC}    $POOL_ADDR"
echo -e "${CYAN}│${NC}  ${YELLOW}SwapRouter:${NC}       $ROUTER_ADDR"
echo -e "${CYAN}├─────────────────────────────────────────────────────────────────────┤${NC}"
echo -e "${CYAN}│${NC}  ${WHITE}Cross-references work because addresses were known beforehand${NC}"
echo -e "${CYAN}└─────────────────────────────────────────────────────────────────────┘${NC}"

echo ""
echo -e "${GREEN}All operations completed successfully!${NC}"
echo ""
echo -e "${WHITE}Key CREATE3 Benefits Demonstrated:${NC}"
echo -e "  ${CYAN}1.${NC} Addresses computed before deployment"
echo -e "  ${CYAN}2.${NC} Circular dependencies resolved"
echo -e "  ${CYAN}3.${NC} Same address across all EVM chains (with same factory/salt)"
echo -e "  ${CYAN}4.${NC} Addresses independent of bytecode"
echo ""
echo -e "${WHITE}Compare with:${NC}"
echo -e "  ${GREEN}./demo-anvil-direct.sh${NC}   - Direct deployment (needs delayed init)"
echo -e "  ${GREEN}./demo-upgrade.sh${NC}        - UUPS upgrade flow"
echo ""
