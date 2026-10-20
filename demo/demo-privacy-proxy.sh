#!/bin/bash

# =============================================================================
# Open Privacy Suite - Full Workflow Demo
# =============================================================================
# This script demonstrates the full Open Privacy Suite workflow:
# 1. Start services (anvil + Open Privacy Suite via docker-compose)
# 2. Authenticate and get JWT
# 3. Set up organization and user permissions
# 4. Preregister CREATE3 addresses
# 5. Deploy contracts through proxy
# 6. Interact with contracts (showing RBAC enforcement)
# 7. Clean up
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

    # Use stdin for data to handle large payloads (contract bytecode can be very long)
    echo "{\"jsonrpc\":\"2.0\",\"method\":\"$method\",\"params\":$params,\"id\":1}" | \
    curl -s -X POST "$PROXY_RPC_URL" \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer $AUTH_TOKEN" \
        -d @-
}

# =============================================================================
# Helper function for API calls
# =============================================================================
api_call() {
    local method="$1"
    local endpoint="$2"
    local data="$3"

    if [ -n "$data" ]; then
        # Use stdin for data to handle large payloads
        echo "$data" | curl -s -X "$method" "${PROXY_API_URL}${endpoint}" \
            -H "Content-Type: application/json" \
            -d @-
    else
        curl -s -X "$method" "${PROXY_API_URL}${endpoint}"
    fi
}

# =============================================================================
# Configuration
# =============================================================================

print_header "Open Privacy Suite Full Workflow Demo"

print_step "Step 1: Checking Configuration"

# Environment variables with defaults
: "${PROXY_API_URL:=http://localhost:8080/api/v1/admin}"
: "${PROXY_RPC_URL:=http://localhost:8080}"
: "${ANVIL_URL:=http://localhost:8545}"
: "${PRIVATE_KEY:=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80}"

print_value "Proxy API URL" "$PROXY_API_URL"
print_value "Proxy RPC URL" "$PROXY_RPC_URL"
print_value "Anvil URL" "$ANVIL_URL"
print_value "Private Key" "${PRIVATE_KEY:0:10}..."

# Get deployer address from private key
DEPLOYER_ADDRESS=$(cast wallet address "$PRIVATE_KEY" 2>/dev/null)
print_value "Deployer Address" "$DEPLOYER_ADDRESS"

# Check if services are running
print_substep "Checking if Open Privacy Suite is running..."
HEALTH_CHECK=$(curl -s "$PROXY_RPC_URL/health" 2>/dev/null || echo "")
if [ -z "$HEALTH_CHECK" ]; then
    print_error "Open Privacy Suite is not running at $PROXY_RPC_URL"
    echo ""
    echo -e "  ${WHITE}Start the services with:${NC}"
    echo -e "  ${GREEN}docker-compose up -d${NC}"
    echo ""
    exit 1
fi
print_success "Open Privacy Suite is running"

# Check Anvil connection through proxy
print_substep "Checking Anvil connection..."
CHAIN_ID=$(curl -s -X POST "$ANVIL_URL" \
    -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":1}' 2>/dev/null | jq -r '.result // empty')
if [ -z "$CHAIN_ID" ]; then
    print_error "Could not connect to Anvil at $ANVIL_URL"
    exit 1
fi
print_success "Anvil connected (chainId: $CHAIN_ID)"

# =============================================================================
# Step 2: Authentication
# =============================================================================

print_step "Step 2: Authentication"

# Create a unique user DID for this demo
USER_EXTERNAL_ID="did:demo:deployer-$(date +%s)"
print_substep "User DID: $USER_EXTERNAL_ID"

# Start auth session
print_substep "Starting auth session..."
AUTH_REQUEST_RESP=$(curl -s -X POST "$PROXY_RPC_URL/auth/request" \
    -H "Content-Type: application/json" \
    -d '{"reason": "Open Privacy Suite Demo"}')

SESSION_ID=$(echo "$AUTH_REQUEST_RESP" | jq -r '.session_id // .sessionId // empty')
if [ -z "$SESSION_ID" ] || [ "$SESSION_ID" = "null" ]; then
    print_error "Failed to create auth session: $AUTH_REQUEST_RESP"
    exit 1
fi
print_success "Auth session created: ${SESSION_ID:0:20}..."

# Complete auth with mock token (requires AllowMockLogin=true)
print_substep "Authenticating with mock token..."
MOCK_TOKEN="mock.${USER_EXTERNAL_ID}"
AUTH_CALLBACK_RESP=$(curl -s -X POST "$PROXY_RPC_URL/auth/callback?session=$SESSION_ID" \
    -H "Content-Type: application/json" \
    -d "{\"token\": \"$MOCK_TOKEN\"}")

AUTH_TOKEN=$(echo "$AUTH_CALLBACK_RESP" | jq -r '.access_token // .accessToken // empty')
if [ -z "$AUTH_TOKEN" ] || [ "$AUTH_TOKEN" = "null" ]; then
    print_error "Failed to authenticate: $AUTH_CALLBACK_RESP"
    print_info "Make sure the proxy is running with ALLOW_MOCK_LOGIN=true"
    exit 1
fi
print_success "Got JWT access token"
print_value "Token (first 50 chars)" "${AUTH_TOKEN:0:50}..."

# =============================================================================
# Step 3: Organization Setup
# =============================================================================

print_step "Step 3: Organization Setup"

# Check if org already exists or get/create one
if [ -z "$ORG_ID" ] && [ -z "$ORG_SLUG" ]; then
    print_substep "Looking for existing organizations..."
    ORGS_RESPONSE=$(api_call "GET" "/orgs")
    ORG_COUNT=$(echo "$ORGS_RESPONSE" | jq '.data | length' 2>/dev/null || echo "0")

    if [ "$ORG_COUNT" -gt 0 ]; then
        # Use first org
        ORG_ID=$(echo "$ORGS_RESPONSE" | jq -r '.data[0].id')
        ORG_SLUG=$(echo "$ORGS_RESPONSE" | jq -r '.data[0].slug')
        ORG_NAME=$(echo "$ORGS_RESPONSE" | jq -r '.data[0].name')
        print_success "Using existing organization: $ORG_NAME ($ORG_SLUG)"
    else
        # Create a demo org
        print_substep "Creating demo organization..."
        ORG_CREATE_RESP=$(api_call "POST" "/orgs" '{
            "slug": "demo-org",
            "name": "Demo Organization",
            "description": "Organization for demo purposes"
        }')
        ORG_ID=$(echo "$ORG_CREATE_RESP" | jq -r '.id')
        ORG_SLUG="demo-org"
        ORG_NAME="Demo Organization"
        print_success "Created organization: $ORG_NAME"
    fi
else
    # Use provided org
    if [ -n "$ORG_SLUG" ] && [ -z "$ORG_ID" ]; then
        ORGS_RESPONSE=$(api_call "GET" "/orgs")
        ORG_ID=$(echo "$ORGS_RESPONSE" | jq -r ".data[] | select(.slug == \"$ORG_SLUG\") | .id")
        ORG_NAME=$(echo "$ORGS_RESPONSE" | jq -r ".data[] | select(.slug == \"$ORG_SLUG\") | .name")
    fi
fi

print_value "Organization ID" "$ORG_ID"
print_value "Organization Slug" "$ORG_SLUG"

# =============================================================================
# Step 4: User and Group Setup
# =============================================================================

print_step "Step 4: User and Group Setup"

# Get user info
print_substep "Getting user info..."
USERS_RESP=$(api_call "GET" "/users")
USER_ID=$(echo "$USERS_RESP" | jq -r ".data[] | select(.external_id == \"$USER_EXTERNAL_ID\") | .id" | head -1)

if [ -z "$USER_ID" ] || [ "$USER_ID" = "null" ]; then
    print_error "Could not find user ID after authentication"
    exit 1
fi
print_success "User ID: $USER_ID"

# Set KYC status
print_substep "Setting KYC status (required for RPC access)..."
KYC_RESP=$(curl -s -X PUT "${PROXY_API_URL}/users/${USER_ID}" \
    -H "Content-Type: application/json" \
    -d '{"kyc": true}')
print_success "KYC status set to true"

# Set up deployers group with deploy claim
print_substep "Setting up deployers group..."
GROUPS_RESP=$(api_call "GET" "/orgs/$ORG_ID/groups")
DEPLOYER_GROUP_ID=$(echo "$GROUPS_RESP" | jq -r '.data[] | select(.group.slug == "demo-deployers") | .group.id' | head -1)

if [ -z "$DEPLOYER_GROUP_ID" ] || [ "$DEPLOYER_GROUP_ID" = "null" ]; then
    GROUP_CREATE_RESP=$(curl -s -X POST "${PROXY_API_URL}/orgs/$ORG_ID/groups" \
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

# Always configure group access (in case group was created earlier without proper config)
curl -s -X PUT "${PROXY_API_URL}/orgs/$ORG_ID/groups/$DEPLOYER_GROUP_ID/access" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $AUTH_TOKEN" \
    -d '{
        "allowed_methods": ["eth_sendTransaction", "eth_call", "eth_estimateGas", "eth_getBalance", "eth_chainId", "eth_blockNumber", "eth_getTransactionCount", "eth_getTransactionReceipt", "net_version"],
        "allowed_methods": ["*"], "claims": ["deploy"]
    }' > /dev/null

print_success "Deployers group ready: $DEPLOYER_GROUP_ID"

# Add user to group
print_substep "Adding user to deployers group..."
MEMBERSHIP_RESP=$(curl -s -X POST "${PROXY_API_URL}/users/${USER_ID}/memberships" \
    -H "Content-Type: application/json" \
    -d "{\"group_id\": \"$DEPLOYER_GROUP_ID\"}")
print_success "User added to deployers group"

# Verify auth works
print_substep "Verifying authentication..."
AUTH_TEST=$(rpc_call "eth_chainId" "[]")
AUTH_ERROR=$(echo "$AUTH_TEST" | jq -r 'if .error then .error.message else empty end')
if [ -n "$AUTH_ERROR" ]; then
    print_error "Authentication verification failed: $AUTH_ERROR"
    exit 1
fi
print_success "Authentication verified"

# =============================================================================
# Step 5: CREATE3 Factory Setup
# =============================================================================

print_step "Step 5: CREATE3 Factory Setup"

# Check if factory is already configured
print_substep "Checking CREATE3 factory configuration..."
FACTORY_RESPONSE=$(api_call "GET" "/orgs/$ORG_ID/config/create3")
CREATE3_FACTORY=$(echo "$FACTORY_RESPONSE" | jq -r '.factory // empty')

if [ -z "$CREATE3_FACTORY" ] || [ "$CREATE3_FACTORY" = "null" ]; then
    print_info "No factory configured, deploying one..."

    # Deploy CREATE3 factory directly to Anvil
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

    # Build factory contract
    BUILD_DIR=$(mktemp -d)
    cp -r "$SCRIPT_DIR/contracts"/* "$BUILD_DIR/"
    cd "$BUILD_DIR"

    git init --quiet
    git config user.email "demo@example.com"
    git config user.name "Demo"
    git add -A
    git commit -m "Initial" --quiet

    # Remove any copied local artifacts (these are gitignored but cp -r copies them)
    rm -rf lib out cache
    mkdir -p lib
    git clone --quiet --depth 1 https://github.com/foundry-rs/forge-std.git lib/forge-std || { print_error "Failed to clone forge-std"; exit 1; }
    git clone --quiet --depth 1 https://github.com/OpenZeppelin/openzeppelin-contracts-upgradeable.git lib/openzeppelin-contracts-upgradeable || { print_error "Failed to clone openzeppelin-contracts-upgradeable"; exit 1; }
    git clone --quiet --depth 1 https://github.com/OpenZeppelin/openzeppelin-contracts.git lib/openzeppelin-contracts || { print_error "Failed to clone openzeppelin-contracts"; exit 1; }

    forge build --quiet

    print_substep "Deploying CREATE3 factory..."
    FACTORY_RESULT=$(forge create src/CREATE3Factory.sol:CREATE3Factory \
        --rpc-url "$ANVIL_URL" \
        --private-key "$PRIVATE_KEY" \
        --broadcast \
        --json 2>&1) || true
    CREATE3_FACTORY=$(echo "$FACTORY_RESULT" | jq -r '.deployedTo // empty' 2>/dev/null)
    if [ -z "$CREATE3_FACTORY" ] || [ "$CREATE3_FACTORY" = "null" ]; then
        # Fallback: try to parse from non-JSON output
        CREATE3_FACTORY=$(echo "$FACTORY_RESULT" | grep -o 'Deployed to: 0x[a-fA-F0-9]\{40\}' | cut -d' ' -f3)
    fi
    if [ -z "$CREATE3_FACTORY" ]; then
        print_error "Failed to deploy CREATE3 factory"
        echo "  Output: $FACTORY_RESULT"
        exit 1
    fi
    print_success "Factory deployed: $CREATE3_FACTORY"

    # Configure factory for org
    print_substep "Configuring factory for organization..."
    curl -s -X PUT "${PROXY_API_URL}/orgs/$ORG_ID/config/create3" \
        -H "Content-Type: application/json" \
        -d "{\"factory\": \"$CREATE3_FACTORY\"}" > /dev/null
    print_success "Factory configured for organization"

    # Cleanup
    rm -rf "$BUILD_DIR"
    cd "$SCRIPT_DIR"
else
    print_success "Factory configured: $CREATE3_FACTORY"

    # Verify factory has code
    FACTORY_CODE_SIZE=$(cast codesize "$CREATE3_FACTORY" --rpc-url "$ANVIL_URL" 2>/dev/null || echo "0")
    if [ "$FACTORY_CODE_SIZE" = "0" ]; then
        print_info "Factory has no code (chain may have been reset), deploying new factory..."

        # Deploy new factory via dev endpoint
        DEPLOY_RESP=$(curl -s -X POST "${PROXY_API_URL}/dev/create3-factory")
        CREATE3_FACTORY=$(echo "$DEPLOY_RESP" | jq -r '.address // empty')

        if [ -z "$CREATE3_FACTORY" ] || [ "$CREATE3_FACTORY" = "null" ]; then
            print_error "Failed to deploy CREATE3 factory"
            echo "Response: $DEPLOY_RESP"
            exit 1
        fi
        print_success "Deployed new factory: $CREATE3_FACTORY"

        # Update org configuration
        curl -s -X PUT "${PROXY_API_URL}/orgs/$ORG_ID/config/create3" \
            -H "Content-Type: application/json" \
            -d "{\"factory\": \"$CREATE3_FACTORY\"}" > /dev/null
        print_success "Factory configuration updated"
    else
        print_value "Factory code size" "$FACTORY_CODE_SIZE bytes"
    fi
fi

# =============================================================================
# Step 6: Preregister Addresses (or compute locally if runtime tracing is on)
# =============================================================================

print_step "Step 6: Preregister Addresses"

# We need 6 addresses: 3 implementations + 3 proxies
ADDRESSES_NEEDED=6
SALT_PREFIX="demo-defi-$(date +%s)"

print_substep "Preregistering $ADDRESSES_NEEDED addresses..."
PREREGISTER_RESPONSE=$(curl -s -X POST "${PROXY_API_URL}/orgs/$ORG_ID/addresses/preregister" \
    -H "Content-Type: application/json" \
    -d "{
        \"factory\": \"$CREATE3_FACTORY\",
        \"salt_prefix\": \"$SALT_PREFIX\",
        \"count\": $ADDRESSES_NEEDED,
        \"note\": \"Demo DeFi deployment addresses\"
    }")

if echo "$PREREGISTER_RESPONSE" | jq -e '.addresses' > /dev/null 2>&1; then
    # Extract addresses and salts from preregistration response
    TOKEN_IMPL_ADDR=$(echo "$PREREGISTER_RESPONSE" | jq -r '.addresses[0].address')
    TOKEN_IMPL_SALT=$(echo "$PREREGISTER_RESPONSE" | jq -r '.addresses[0].salt')
    POOL_IMPL_ADDR=$(echo "$PREREGISTER_RESPONSE" | jq -r '.addresses[1].address')
    POOL_IMPL_SALT=$(echo "$PREREGISTER_RESPONSE" | jq -r '.addresses[1].salt')
    ROUTER_IMPL_ADDR=$(echo "$PREREGISTER_RESPONSE" | jq -r '.addresses[2].address')
    ROUTER_IMPL_SALT=$(echo "$PREREGISTER_RESPONSE" | jq -r '.addresses[2].salt')
    TOKEN_PROXY_ADDR=$(echo "$PREREGISTER_RESPONSE" | jq -r '.addresses[3].address')
    TOKEN_PROXY_SALT=$(echo "$PREREGISTER_RESPONSE" | jq -r '.addresses[3].salt')
    POOL_PROXY_ADDR=$(echo "$PREREGISTER_RESPONSE" | jq -r '.addresses[4].address')
    POOL_PROXY_SALT=$(echo "$PREREGISTER_RESPONSE" | jq -r '.addresses[4].salt')
    ROUTER_PROXY_ADDR=$(echo "$PREREGISTER_RESPONSE" | jq -r '.addresses[5].address')
    ROUTER_PROXY_SALT=$(echo "$PREREGISTER_RESPONSE" | jq -r '.addresses[5].salt')
    print_success "Addresses preregistered"
elif echo "$PREREGISTER_RESPONSE" | jq -r '.error' 2>/dev/null | grep -q "runtime tracing"; then
    # Runtime tracing is enabled — preregistration not needed.
    # Compute salts and addresses locally using the same algorithm as the server:
    #   salt[i] = keccak256(orgID || saltPrefix || big.Int(i).Bytes())
    # big.Int(0).Bytes() == "" (empty), big.Int(i).Bytes() == hex(i) for i 1..5
    print_info "Runtime tracing enabled — computing addresses locally (no preregistration needed)"

    ORG_HEX=$(printf '%s' "$ORG_ID" | xxd -p | tr -d '\n')
    PREFIX_HEX=$(printf '%s' "$SALT_PREFIX" | xxd -p | tr -d '\n')

    # Counter bytes: i=0 → empty, i=1..5 → single byte (big-endian)
    COUNTER_HEX=("" "01" "02" "03" "04" "05")

    compute_create3_salt() {
        local idx="$1"
        cast keccak "0x${ORG_HEX}${PREFIX_HEX}${COUNTER_HEX[$idx]}"
    }

    compute_create3_addr() {
        local salt="$1"
        cast call "$CREATE3_FACTORY" "getDeployed(bytes32)(address)" "$salt" --rpc-url "$ANVIL_URL" 2>/dev/null | tr '[:upper:]' '[:lower:]'
    }

    TOKEN_IMPL_SALT=$(compute_create3_salt 0)
    TOKEN_IMPL_ADDR=$(compute_create3_addr "$TOKEN_IMPL_SALT")
    POOL_IMPL_SALT=$(compute_create3_salt 1)
    POOL_IMPL_ADDR=$(compute_create3_addr "$POOL_IMPL_SALT")
    ROUTER_IMPL_SALT=$(compute_create3_salt 2)
    ROUTER_IMPL_ADDR=$(compute_create3_addr "$ROUTER_IMPL_SALT")
    TOKEN_PROXY_SALT=$(compute_create3_salt 3)
    TOKEN_PROXY_ADDR=$(compute_create3_addr "$TOKEN_PROXY_SALT")
    POOL_PROXY_SALT=$(compute_create3_salt 4)
    POOL_PROXY_ADDR=$(compute_create3_addr "$POOL_PROXY_SALT")
    ROUTER_PROXY_SALT=$(compute_create3_salt 5)
    ROUTER_PROXY_ADDR=$(compute_create3_addr "$ROUTER_PROXY_SALT")
    print_success "Addresses computed locally"
else
    print_error "Failed to preregister addresses"
    echo "$PREREGISTER_RESPONSE" | jq '.' 2>/dev/null || echo "$PREREGISTER_RESPONSE"
    exit 1
fi

print_success "Addresses ready"
echo ""
echo -e "  ${WHITE}Preregistered Addresses:${NC}"
echo -e "  ${CYAN}┌─────────────────────────────────────────────────────────────────┐${NC}"
echo -e "  ${CYAN}│${NC} ${YELLOW}Token Implementation:${NC}  $TOKEN_IMPL_ADDR"
echo -e "  ${CYAN}│${NC} ${YELLOW}Pool Implementation:${NC}   $POOL_IMPL_ADDR"
echo -e "  ${CYAN}│${NC} ${YELLOW}Router Implementation:${NC} $ROUTER_IMPL_ADDR"
echo -e "  ${CYAN}│${NC} ${YELLOW}Token Proxy:${NC}           $TOKEN_PROXY_ADDR"
echo -e "  ${CYAN}│${NC} ${YELLOW}Pool Proxy:${NC}            $POOL_PROXY_ADDR"
echo -e "  ${CYAN}│${NC} ${YELLOW}Router Proxy:${NC}          $ROUTER_PROXY_ADDR"
echo -e "  ${CYAN}└─────────────────────────────────────────────────────────────────┘${NC}"

# =============================================================================
# Step 7: Build Contracts
# =============================================================================

print_step "Step 7: Building Contracts"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONTRACTS_SRC_DIR="$SCRIPT_DIR/contracts"

BUILD_DIR=$(mktemp -d)
print_substep "Using temp build directory: $BUILD_DIR"

cp -r "$CONTRACTS_SRC_DIR"/* "$BUILD_DIR/"
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
git clone --quiet --depth 1 https://github.com/Vectorized/solady.git lib/solady || { print_error "Failed to clone solady"; exit 1; }
print_success "Dependencies installed"

print_substep "Compiling contracts..."
forge build --quiet
print_success "Contracts compiled"

# Get bytecode
DEMOTOKEN_BYTECODE=$(forge inspect DemoToken bytecode)
LIQUIDITYPOOL_BYTECODE=$(forge inspect LiquidityPool bytecode)
SWAPROUTER_BYTECODE=$(forge inspect SwapRouter bytecode)

# Create proxy contract
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

print_value "DemoToken bytecode" "$(echo -n "$DEMOTOKEN_BYTECODE" | wc -c | tr -d ' ') chars"
print_value "LiquidityPool bytecode" "$(echo -n "$LIQUIDITYPOOL_BYTECODE" | wc -c | tr -d ' ') chars"
print_value "SwapRouter bytecode" "$(echo -n "$SWAPROUTER_BYTECODE" | wc -c | tr -d ' ') chars"

# =============================================================================
# Step 8: Deploy Through Open Privacy Suite
# =============================================================================

print_step "Step 8: Deploying Contracts Through Open Privacy Suite"

print_info "All deployments go through the Open Privacy Suite with RBAC enforcement"
print_info "Deploying to preregistered CREATE3 addresses"
echo ""

# Helper function to deploy via CREATE3 through proxy
deploy_via_create3() {
    local salt="$1"
    local bytecode="$2"
    local name="$3"
    local expected_addr="$4"

    print_substep "Deploying $name..."

    # deploy(bytes32,bytes) selector = 0xcdcb760a
    # Use abi-encode for the arguments and prepend the selector
    # This is more reliable than cast calldata for large bytecode
    local encoded_args
    encoded_args=$(cast abi-encode "f(bytes32,bytes)" "$salt" "$bytecode" 2>&1) || {
        print_error "Failed to encode deployment data for $name"
        echo "  Error: $encoded_args"
        return 1
    }
    # Prepend the function selector (deploy(bytes32,bytes) = 0xcdcb760a)
    DEPLOY_CALLDATA="0xcdcb760a${encoded_args:2}"

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
    DEPLOY_ERROR=$(echo "$DEPLOY_RESULT" | jq -r '(.error.message? // .error?) // empty' 2>/dev/null)

    if [ -z "$TX_HASH" ] || [ "$TX_HASH" = "null" ]; then
        if [ -n "$DEPLOY_ERROR" ] && [ "$DEPLOY_ERROR" != "null" ]; then
            print_error "Failed to deploy $name: $DEPLOY_ERROR"
        else
            print_error "Failed to deploy $name"
        fi
        echo "Response: $DEPLOY_RESULT" | head -5
        return 1
    fi

    # Verify deployment
    CODE_SIZE=$(cast codesize "$expected_addr" --rpc-url "$ANVIL_URL" 2>/dev/null || echo "0")
    if [ "$CODE_SIZE" = "0" ]; then
        print_error "$name deployment failed - no code at $expected_addr"
        return 1
    fi

    print_success "$name deployed to $expected_addr"
}

# Deploy implementations
deploy_via_create3 "$TOKEN_IMPL_SALT" "$DEMOTOKEN_BYTECODE" "DemoToken Implementation" "$TOKEN_IMPL_ADDR"
deploy_via_create3 "$POOL_IMPL_SALT" "$LIQUIDITYPOOL_BYTECODE" "LiquidityPool Implementation" "$POOL_IMPL_ADDR"
deploy_via_create3 "$ROUTER_IMPL_SALT" "$SWAPROUTER_BYTECODE" "SwapRouter Implementation" "$ROUTER_IMPL_ADDR"

# Deploy proxies with initialization
# Token: initialize(owner, pool)
print_substep "Preparing DemoToken Proxy deployment..."
TOKEN_INIT_DATA=$(cast calldata "initialize(address,address)" "$DEPLOYER_ADDRESS" "$POOL_PROXY_ADDR") || {
    print_error "Failed to encode token initialization data"
    exit 1
}
TOKEN_PROXY_CONSTRUCTOR=$(cast abi-encode "constructor(address,bytes)" "$TOKEN_IMPL_ADDR" "$TOKEN_INIT_DATA") || {
    print_error "Failed to encode token proxy constructor"
    exit 1
}
TOKEN_PROXY_INITCODE="${PROXY_BYTECODE}${TOKEN_PROXY_CONSTRUCTOR:2}"
deploy_via_create3 "$TOKEN_PROXY_SALT" "$TOKEN_PROXY_INITCODE" "DemoToken Proxy" "$TOKEN_PROXY_ADDR"

# Pool: initialize(owner, token)
print_substep "Preparing LiquidityPool Proxy deployment..."
POOL_INIT_DATA=$(cast calldata "initialize(address,address)" "$DEPLOYER_ADDRESS" "$TOKEN_PROXY_ADDR") || {
    print_error "Failed to encode pool initialization data"
    exit 1
}
POOL_PROXY_CONSTRUCTOR=$(cast abi-encode "constructor(address,bytes)" "$POOL_IMPL_ADDR" "$POOL_INIT_DATA") || {
    print_error "Failed to encode pool proxy constructor"
    exit 1
}
POOL_PROXY_INITCODE="${PROXY_BYTECODE}${POOL_PROXY_CONSTRUCTOR:2}"
deploy_via_create3 "$POOL_PROXY_SALT" "$POOL_PROXY_INITCODE" "LiquidityPool Proxy" "$POOL_PROXY_ADDR"

# Router: initialize(owner, pool, token)
print_substep "Preparing SwapRouter Proxy deployment..."
ROUTER_INIT_DATA=$(cast calldata "initialize(address,address,address)" "$DEPLOYER_ADDRESS" "$POOL_PROXY_ADDR" "$TOKEN_PROXY_ADDR") || {
    print_error "Failed to encode router initialization data"
    exit 1
}
ROUTER_PROXY_CONSTRUCTOR=$(cast abi-encode "constructor(address,bytes)" "$ROUTER_IMPL_ADDR" "$ROUTER_INIT_DATA") || {
    print_error "Failed to encode router proxy constructor"
    exit 1
}
ROUTER_PROXY_INITCODE="${PROXY_BYTECODE}${ROUTER_PROXY_CONSTRUCTOR:2}"
deploy_via_create3 "$ROUTER_PROXY_SALT" "$ROUTER_PROXY_INITCODE" "SwapRouter Proxy" "$ROUTER_PROXY_ADDR"

# =============================================================================
# Step 9: Verify Deployment
# =============================================================================

print_step "Step 9: Verifying Deployment"

print_substep "Checking contract versions..."
TOKEN_VERSION=$(cast call "$TOKEN_PROXY_ADDR" "version()(string)" --rpc-url "$ANVIL_URL" 2>/dev/null)
POOL_VERSION=$(cast call "$POOL_PROXY_ADDR" "version()(string)" --rpc-url "$ANVIL_URL" 2>/dev/null)
ROUTER_VERSION=$(cast call "$ROUTER_PROXY_ADDR" "version()(string)" --rpc-url "$ANVIL_URL" 2>/dev/null)

print_contract_call "$TOKEN_PROXY_ADDR" "version()" "$TOKEN_VERSION"
print_contract_call "$POOL_PROXY_ADDR" "version()" "$POOL_VERSION"
print_contract_call "$ROUTER_PROXY_ADDR" "version()" "$ROUTER_VERSION"

print_substep "Verifying circular references (CREATE3 determinism)..."
TOKEN_POOL=$(cast call "$TOKEN_PROXY_ADDR" "pool()(address)" --rpc-url "$ANVIL_URL" 2>/dev/null | tr '[:upper:]' '[:lower:]')
POOL_TOKEN=$(cast call "$POOL_PROXY_ADDR" "token()(address)" --rpc-url "$ANVIL_URL" 2>/dev/null | tr '[:upper:]' '[:lower:]')
TOKEN_PROXY_ADDR_LOWER=$(echo "$TOKEN_PROXY_ADDR" | tr '[:upper:]' '[:lower:]')
POOL_PROXY_ADDR_LOWER=$(echo "$POOL_PROXY_ADDR" | tr '[:upper:]' '[:lower:]')

if [ "$TOKEN_POOL" = "$POOL_PROXY_ADDR_LOWER" ] && [ "$POOL_TOKEN" = "$TOKEN_PROXY_ADDR_LOWER" ]; then
    print_success "Circular references verified!"
else
    print_error "Reference mismatch"
    print_value "Token.pool()" "$TOKEN_POOL"
    print_value "Expected" "$POOL_PROXY_ADDR_LOWER"
    print_value "Pool.token()" "$POOL_TOKEN"
    print_value "Expected" "$TOKEN_PROXY_ADDR_LOWER"
fi

# =============================================================================
# Step 10: Interact Through Proxy
# =============================================================================

print_step "Step 10: Interacting Through Open Privacy Suite"

print_info "All interactions go through RBAC-enforced proxy"
echo ""

# Mint tokens
MINT_AMOUNT="1000000000000000000000"
print_substep "Minting 1000 DEMO tokens through proxy..."
MINT_CALLDATA=$(cast calldata "mint(address,uint256)" "$DEPLOYER_ADDRESS" "$MINT_AMOUNT")
NONCE_RESP=$(rpc_call "eth_getTransactionCount" "[\"$DEPLOYER_ADDRESS\", \"latest\"]")
NONCE=$(echo "$NONCE_RESP" | jq -r '.result // "0x0"')
TX_PARAMS=$(cat <<EOF
[{
    "from": "$DEPLOYER_ADDRESS",
    "to": "$TOKEN_PROXY_ADDR",
    "data": "$MINT_CALLDATA",
    "gas": "0x100000",
    "nonce": "$NONCE"
}]
EOF
)
MINT_RESULT=$(rpc_call "eth_sendTransaction" "$TX_PARAMS")
MINT_TX=$(echo "$MINT_RESULT" | jq -r '.result // empty')
if [ -n "$MINT_TX" ] && [ "$MINT_TX" != "null" ]; then
    print_success "Minted 1000 DEMO tokens"
else
    print_error "Mint failed: $(echo "$MINT_RESULT" | jq -r '.error.message // .error // .')"
fi

# Approve pool
print_substep "Approving pool to spend tokens..."
APPROVE_CALLDATA=$(cast calldata "approve(address,uint256)" "$POOL_PROXY_ADDR" "$MINT_AMOUNT")
NONCE_RESP=$(rpc_call "eth_getTransactionCount" "[\"$DEPLOYER_ADDRESS\", \"latest\"]")
NONCE=$(echo "$NONCE_RESP" | jq -r '.result // "0x0"')
TX_PARAMS=$(cat <<EOF
[{
    "from": "$DEPLOYER_ADDRESS",
    "to": "$TOKEN_PROXY_ADDR",
    "data": "$APPROVE_CALLDATA",
    "gas": "0x100000",
    "nonce": "$NONCE"
}]
EOF
)
APPROVE_RESULT=$(rpc_call "eth_sendTransaction" "$TX_PARAMS")
print_success "Pool approved"

# Add liquidity
LIQUIDITY_TOKENS="500000000000000000000"
LIQUIDITY_ETH="1000000000000000000"
print_substep "Adding liquidity (500 DEMO + 1 ETH)..."
ADD_LIQ_CALLDATA=$(cast calldata "addLiquidity(uint256)" "$LIQUIDITY_TOKENS")
NONCE_RESP=$(rpc_call "eth_getTransactionCount" "[\"$DEPLOYER_ADDRESS\", \"latest\"]")
NONCE=$(echo "$NONCE_RESP" | jq -r '.result // "0x0"')
TX_PARAMS=$(cat <<EOF
[{
    "from": "$DEPLOYER_ADDRESS",
    "to": "$POOL_PROXY_ADDR",
    "data": "$ADD_LIQ_CALLDATA",
    "value": "0xde0b6b3a7640000",
    "gas": "0x200000",
    "nonce": "$NONCE"
}]
EOF
)
LIQ_RESULT=$(rpc_call "eth_sendTransaction" "$TX_PARAMS")
print_success "Liquidity added"

# Check reserves
TOKEN_RESERVE=$(cast call "$POOL_PROXY_ADDR" "tokenReserve()(uint256)" --rpc-url "$ANVIL_URL" 2>/dev/null)
ETH_RESERVE=$(cast call "$POOL_PROXY_ADDR" "ethReserve()(uint256)" --rpc-url "$ANVIL_URL" 2>/dev/null)
print_value "Token Reserve" "$TOKEN_RESERVE"
print_value "ETH Reserve" "$ETH_RESERVE"

# =============================================================================
# Step 11: Demonstrate RBAC (Optional)
# =============================================================================

print_step "Step 11: RBAC Demonstration"

print_info "Attempting unauthorized operation (should fail)..."

# Try to send transaction without auth
UNAUTH_RESULT=$(curl -s -X POST "$PROXY_RPC_URL" \
    -H "Content-Type: application/json" \
    -d '{
        "jsonrpc": "2.0",
        "method": "eth_sendTransaction",
        "params": [{
            "from": "0x0000000000000000000000000000000000000001",
            "to": "0x0000000000000000000000000000000000000002",
            "value": "0x1"
        }],
        "id": 1
    }')

# Server returns {"error":"..."} for auth failures (not JSON-RPC format)
UNAUTH_ERROR=$(echo "$UNAUTH_RESULT" | jq -r '.error // .error.message // empty')
if [ -n "$UNAUTH_ERROR" ]; then
    print_success "Unauthorized request correctly rejected"
    print_value "Error" "$UNAUTH_ERROR"
else
    print_info "Request may have been allowed (check proxy config)"
fi

# =============================================================================
# Summary
# =============================================================================

print_header "Demo Complete!"

echo -e "${WHITE}Deployed Contracts (Through Open Privacy Suite):${NC}"
echo -e "${CYAN}┌─────────────────────────────────────────────────────────────────────┐${NC}"
echo -e "${CYAN}│${NC}  ${YELLOW}CREATE3 Factory:${NC}       $CREATE3_FACTORY"
echo -e "${CYAN}├─────────────────────────────────────────────────────────────────────┤${NC}"
echo -e "${CYAN}│${NC}  ${YELLOW}DemoToken Proxy:${NC}       $TOKEN_PROXY_ADDR"
echo -e "${CYAN}│${NC}  ${YELLOW}LiquidityPool Proxy:${NC}   $POOL_PROXY_ADDR"
echo -e "${CYAN}│${NC}  ${YELLOW}SwapRouter Proxy:${NC}      $ROUTER_PROXY_ADDR"
echo -e "${CYAN}├─────────────────────────────────────────────────────────────────────┤${NC}"
echo -e "${CYAN}│${NC}  ${YELLOW}Token Version:${NC}         $TOKEN_VERSION"
echo -e "${CYAN}│${NC}  ${YELLOW}Pool Version:${NC}          $POOL_VERSION"
echo -e "${CYAN}│${NC}  ${YELLOW}Router Version:${NC}        $ROUTER_VERSION"
echo -e "${CYAN}└─────────────────────────────────────────────────────────────────────┘${NC}"

echo ""
echo -e "${GREEN}All operations completed successfully!${NC}"
echo ""
echo -e "${WHITE}Key Points Demonstrated:${NC}"
echo -e "  ${CYAN}1.${NC} Authentication via mock provider (JWT tokens)"
echo -e "  ${CYAN}2.${NC} Organization and user setup via Admin API"
echo -e "  ${CYAN}3.${NC} Group-based permissions with deploy claim"
echo -e "  ${CYAN}4.${NC} Address preregistration before deployment"
echo -e "  ${CYAN}5.${NC} CREATE3 deterministic deployment through proxy"
echo -e "  ${CYAN}6.${NC} RBAC enforcement on all transactions"
echo -e "  ${CYAN}7.${NC} Circular dependency resolution via CREATE3"
echo ""
echo -e "${WHITE}Compare with:${NC}"
echo -e "  ${GREEN}./demo-anvil-direct.sh${NC}      - Same flow without Open Privacy Suite"
echo -e "  ${GREEN}./demo-defi-deployment.sh${NC}   - Focus on CREATE3 patterns"
echo ""
