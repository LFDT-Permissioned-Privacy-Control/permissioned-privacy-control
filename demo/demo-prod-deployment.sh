#!/bin/bash

# =============================================================================
# Open Privacy Suite - Production-Style Contract Deployment
# =============================================================================
# This script demonstrates deploying contracts through the Open Privacy Suite
# as a real user would in production:
#
# 1. User has already authenticated via Privado ID (ZK proof)
# 2. User has a JWT token from the web UI
# 3. User signs transactions locally with their private key
# 4. Transactions go through the proxy via eth_sendRawTransaction
#
# Prerequisites:
#   - User authenticated and has JWT token (from web UI or mock auth)
#   - User has 'deploy' permission in their organization
#     (if not, script will attempt to set up permissions via admin API)
#   - Private key with funded account
#
# Usage:
#   export ETH_RPC_HEADERS="Authorization: Bearer eyJ..."  # From web UI "Copy for Foundry" button
#   export PRIVATE_KEY="0x..."     # Your deployer private key
#   export ORG_ID="174601bb-..."   # Optional: org ID (required if user has multiple orgs)
#   ./demo-prod-deployment.sh
# =============================================================================

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m'
BOLD='\033[1m'

print_header() {
    echo ""
    echo -e "${CYAN}══════════════════════════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}${WHITE}  $1${NC}"
    echo -e "${CYAN}══════════════════════════════════════════════════════════════════════${NC}"
    echo ""
}

print_step() {
    echo -e "\n${YELLOW}▶${NC} ${BOLD}$1${NC}"
}

print_success() {
    echo -e "  ${GREEN}✓${NC} $1"
}

print_error() {
    echo -e "  ${RED}✗${NC} $1"
}

print_info() {
    echo -e "  ${CYAN}ℹ${NC} $1"
}

print_value() {
    echo -e "  ${WHITE}$1:${NC} ${GREEN}$2${NC}"
}

# =============================================================================
# Configuration
# =============================================================================

print_header "Production-Style Contract Deployment"

# Required environment variables
if [ -z "$ETH_RPC_HEADERS" ]; then
    echo -e "${RED}Error: ETH_RPC_HEADERS not set${NC}"
    echo ""
    echo "To get your token:"
    echo "  1. Go to http://localhost:5173"
    echo "  2. Authenticate with Privado ID"
    echo "  3. Click 'Copy for Foundry/Hardhat' button"
    echo "  4. Paste the export command in your terminal"
    echo ""
    echo "Then run this script again."
    exit 1
fi

if [ -z "$PRIVATE_KEY" ]; then
    echo -e "${RED}Error: PRIVATE_KEY not set${NC}"
    echo ""
    echo "Set your deployer private key:"
    echo "  export PRIVATE_KEY=\"0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80\""
    echo ""
    echo "(The above is Anvil's default account #0 for testing)"
    exit 1
fi

# Configuration with defaults
: "${PROXY_BASE_URL:=http://localhost:8080}"
: "${CHAIN_ID:=31337}"

# Build RPC URL - append org_id if specified (required for multi-org users)
if [ -n "$ORG_ID" ]; then
    PROXY_RPC_URL="${PROXY_BASE_URL}/rpc/${ORG_ID}"
else
    PROXY_RPC_URL="${PROXY_BASE_URL}/rpc"
fi

print_step "Step 1: Checking Configuration"

print_value "Proxy RPC URL" "$PROXY_RPC_URL"
print_value "Chain ID" "$CHAIN_ID"
if [ -n "$ORG_ID" ]; then
    print_value "Organization ID" "$ORG_ID"
else
    print_info "No ORG_ID set (using default org)"
fi

# Extract token from ETH_RPC_HEADERS for display
TOKEN_PREVIEW=$(echo "$ETH_RPC_HEADERS" | sed 's/Authorization: Bearer //' | head -c 20)
print_value "Auth Header" "${TOKEN_PREVIEW}..."

DEPLOYER_ADDRESS=$(cast wallet address "$PRIVATE_KEY" 2>/dev/null)
print_value "Deployer Address" "$DEPLOYER_ADDRESS"

# Set ETH_RPC_URL for Foundry
export ETH_RPC_URL="$PROXY_RPC_URL"

# Extract JWT token from ETH_RPC_HEADERS
AUTH_TOKEN=$(echo "$ETH_RPC_HEADERS" | sed 's/Authorization: Bearer //')

# =============================================================================
# Step 2: Verify Connection
# =============================================================================

print_step "Step 2: Verifying Connection to Open Privacy Suite"

print_info "Testing RPC connection..."
CHAIN_RESULT=$(cast chain-id --rpc-url "$PROXY_RPC_URL" 2>&1) && CONNECTION_OK=0 || CONNECTION_OK=1

if [ $CONNECTION_OK -eq 0 ]; then
    print_success "Connected to chain $CHAIN_RESULT"

    # Auto-detect org for users when ORG_ID not set
    if [ -z "$ORG_ID" ]; then
        MY_ORGS=$(curl -s -H "Authorization: Bearer $AUTH_TOKEN" "${PROXY_BASE_URL}/api/v1/me/orgs" 2>/dev/null)
        ORG_COUNT=$(echo "$MY_ORGS" | jq -r '.organizations | length' 2>/dev/null)
        if [ -n "$ORG_COUNT" ] && [ "$ORG_COUNT" -gt 1 ] 2>/dev/null; then
            print_error "User belongs to $ORG_COUNT organizations - ORG_ID required"
            echo ""
            echo "Your organizations:"
            echo "$MY_ORGS" | jq -r '.organizations[] | "  - \(.name): export ORG_ID=\"\(.id)\""'
            echo ""
            echo "Set ORG_ID to the org with deploy permissions and re-run."
            exit 1
        elif [ -n "$ORG_COUNT" ] && [ "$ORG_COUNT" -eq 1 ] 2>/dev/null; then
            ORG_ID=$(echo "$MY_ORGS" | jq -r '.organizations[0].id')
            ORG_SLUG=$(echo "$MY_ORGS" | jq -r '.organizations[0].slug')
            PROXY_RPC_URL="${PROXY_BASE_URL}/rpc/${ORG_ID}"
            export ETH_RPC_URL="$PROXY_RPC_URL"
            print_info "Auto-selected org: $ORG_SLUG ($ORG_ID)"
        fi
    fi

    print_info "User has working permissions - skipping setup"
else
    # Connection failed - try to set up permissions via admin API (mock auth only)
    print_info "Connection failed, attempting permissions setup via admin API..."

    API_BASE_URL="${PROXY_BASE_URL}/api"

    # Decode the JWT to get the external ID (JWT payload is base64url-encoded, 2nd segment)
    JWT_B64=$(echo "$AUTH_TOKEN" | cut -d'.' -f2 | tr '_-' '/+')
    # Pad base64 to multiple of 4
    while [ $((${#JWT_B64} % 4)) -ne 0 ]; do JWT_B64="${JWT_B64}="; done
    JWT_PAYLOAD=$(echo "$JWT_B64" | base64 -D 2>/dev/null || echo "$JWT_B64" | base64 -d 2>/dev/null || echo "{}")
    USER_EXTERNAL_ID=$(echo "$JWT_PAYLOAD" | jq -r '.sub // empty' 2>/dev/null)

    if [ -z "$USER_EXTERNAL_ID" ]; then
        print_error "Could not decode user from JWT token"
        print_error "Original connection error: $CHAIN_RESULT"
        exit 1
    fi

    # Find the user
    print_info "Looking up user..."
    USERS_RESP=$(curl -s "${API_BASE_URL}/v1/users")
    USER_ID=$(echo "$USERS_RESP" | jq -r ".data[] | select(.external_id == \"$USER_EXTERNAL_ID\") | .id" | head -1)
    if [ -z "$USER_ID" ] || [ "$USER_ID" = "null" ]; then
        print_error "Connection failed and user not found via admin API"
        print_error "Original connection error: $CHAIN_RESULT"
        echo ""
        echo "If you authenticated via Privado ID, ensure your permissions"
        echo "are configured in the admin UI before running this script."
        exit 1
    fi
    print_success "User: $USER_ID ($USER_EXTERNAL_ID)"

    # Find or determine the org
    if [ -z "$ORG_ID" ]; then
        MEMBERSHIPS_RESP=$(curl -s "${API_BASE_URL}/v1/users/${USER_ID}/memberships")
        ORG_ID=$(echo "$MEMBERSHIPS_RESP" | jq -r '.[0].group.org_id // empty' 2>/dev/null)

        if [ -z "$ORG_ID" ] || [ "$ORG_ID" = "null" ]; then
            ORGS_RESP=$(curl -s "${API_BASE_URL}/v1/orgs")
            ORG_ID=$(echo "$ORGS_RESP" | jq -r '.data[0].id // empty')

            if [ -z "$ORG_ID" ] || [ "$ORG_ID" = "null" ]; then
                print_info "Creating demo organization..."
                ORG_CREATE_RESP=$(curl -s -X POST "${API_BASE_URL}/orgs" \
                    -H "Content-Type: application/json" \
                    -d '{"slug": "demo-org", "name": "Demo Organization"}')
                ORG_ID=$(echo "$ORG_CREATE_RESP" | jq -r '.id')
            fi
        fi
    fi
    print_value "Organization" "$ORG_ID"

    # Set KYC
    curl -s -X PUT "${API_BASE_URL}/v1/users/${USER_ID}" \
        -H "Content-Type: application/json" \
        -d '{"kyc": true}' > /dev/null

    # Find or create deployers group with deploy claim
    GROUPS_RESP=$(curl -s "${API_BASE_URL}/v1/orgs/$ORG_ID/groups")
    DEPLOYER_GROUP_ID=$(echo "$GROUPS_RESP" | jq -r '.data[] | select(.group.slug == "demo-deployers") | .group.id' | head -1)

    if [ -z "$DEPLOYER_GROUP_ID" ] || [ "$DEPLOYER_GROUP_ID" = "null" ]; then
        GROUP_CREATE_RESP=$(curl -s -X POST "${API_BASE_URL}/v1/orgs/$ORG_ID/groups" \
            -H "Content-Type: application/json" \
            -d '{"slug": "demo-deployers", "name": "Demo Deployers"}')
        DEPLOYER_GROUP_ID=$(echo "$GROUP_CREATE_RESP" | jq -r '.id')
    fi

    if [ -z "$DEPLOYER_GROUP_ID" ] || [ "$DEPLOYER_GROUP_ID" = "null" ]; then
        print_error "Failed to create or find deployers group"
        exit 1
    fi

    # Configure group access
    curl -s -X PUT "${API_BASE_URL}/v1/orgs/$ORG_ID/groups/$DEPLOYER_GROUP_ID/access" \
        -H "Content-Type: application/json" \
        -d '{
            "allowed_methods": ["eth_sendRawTransaction", "eth_sendTransaction", "eth_call", "eth_estimateGas", "eth_getBalance", "eth_chainId", "eth_blockNumber", "eth_getTransactionCount", "eth_getTransactionReceipt", "eth_getTransactionByHash", "eth_getCode", "eth_feeHistory", "eth_gasPrice", "net_version"],
            "claims": ["deploy"]
        }' > /dev/null

    # Add user to group
    curl -s -X POST "${API_BASE_URL}/v1/users/${USER_ID}/memberships" \
        -H "Content-Type: application/json" \
        -d "{\"group_id\": \"$DEPLOYER_GROUP_ID\"}" > /dev/null 2>&1

    print_success "Deploy permissions configured"

    # Refresh JWT token to pick up new permissions
    print_info "Refreshing auth token..."
    AUTH_REQUEST_RESP=$(curl -s -X POST "${PROXY_BASE_URL}/auth/request" \
        -H "Content-Type: application/json" \
        -d '{"reason": "Token refresh"}')
    SESSION_ID=$(echo "$AUTH_REQUEST_RESP" | jq -r '.session_id // .sessionId // empty')
    if [ -n "$SESSION_ID" ] && [ "$SESSION_ID" != "null" ]; then
        MOCK_TOKEN="mock.${USER_EXTERNAL_ID}"
        AUTH_CALLBACK_RESP=$(curl -s -X POST "${PROXY_BASE_URL}/auth/callback?session=$SESSION_ID" \
            -H "Content-Type: application/json" \
            -d "{\"token\": \"$MOCK_TOKEN\"}")
        NEW_TOKEN=$(echo "$AUTH_CALLBACK_RESP" | jq -r '.access_token // .accessToken // empty')
        if [ -n "$NEW_TOKEN" ] && [ "$NEW_TOKEN" != "null" ]; then
            AUTH_TOKEN="$NEW_TOKEN"
            export ETH_RPC_HEADERS="Authorization: Bearer $AUTH_TOKEN"
            print_success "Auth token refreshed with deploy permissions"
        fi
    fi

    # Update RPC URL with org context
    if [ -n "$ORG_ID" ]; then
        PROXY_RPC_URL="${PROXY_BASE_URL}/rpc/${ORG_ID}"
        export ETH_RPC_URL="$PROXY_RPC_URL"
    fi

    # Verify connection after setup
    print_info "Verifying connection after setup..."
    CHAIN_RESULT=$(cast chain-id --rpc-url "$PROXY_RPC_URL" 2>&1) || {
        print_error "Still failed to connect after permissions setup"
        echo -e "  ${RED}Response: $CHAIN_RESULT${NC}"
        exit 1
    }
    print_success "Connected to chain $CHAIN_RESULT"
fi

# Check balance
BALANCE=$(cast balance "$DEPLOYER_ADDRESS" --rpc-url "$PROXY_RPC_URL" 2>/dev/null)
print_value "Deployer Balance" "$BALANCE"

if [ "$BALANCE" = "0" ]; then
    print_error "Deployer has no funds. Fund the account first."
    exit 1
fi

# =============================================================================
# Step 3: Build Contracts
# =============================================================================

print_step "Step 3: Building Demo Contracts"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR/contracts"

# Install dependencies if not present (lib/ is gitignored)
if [ ! -d "lib/forge-std" ]; then
    print_info "Installing Solidity dependencies..."
    rm -rf lib
    mkdir -p lib
    git clone --quiet --depth 1 https://github.com/foundry-rs/forge-std.git lib/forge-std || { print_error "Failed to clone forge-std"; exit 1; }
    git clone --quiet --depth 1 https://github.com/OpenZeppelin/openzeppelin-contracts.git lib/openzeppelin-contracts || { print_error "Failed to clone openzeppelin-contracts"; exit 1; }
    git clone --quiet --depth 1 https://github.com/OpenZeppelin/openzeppelin-contracts-upgradeable.git lib/openzeppelin-contracts-upgradeable || { print_error "Failed to clone openzeppelin-contracts-upgradeable"; exit 1; }
    git clone --quiet --depth 1 https://github.com/Vectorized/solady.git lib/solady || { print_error "Failed to clone solady"; exit 1; }
    print_success "Dependencies installed"
fi

print_info "Compiling contracts..."
forge build --quiet
print_success "Contracts compiled"

# =============================================================================
# Step 4: Deploy Contracts
# =============================================================================

print_step "Step 4: Deploying Contracts via Open Privacy Suite"

echo ""
echo -e "  ${WHITE}Deployment Flow:${NC}"
echo -e "  ${CYAN}┌─────────────────────────────────────────────────────────────────┐${NC}"
echo -e "  ${CYAN}│${NC}  1. forge signs transaction locally with your private key      ${CYAN}│${NC}"
echo -e "  ${CYAN}│${NC}  2. Sends via eth_sendRawTransaction to proxy                  ${CYAN}│${NC}"
echo -e "  ${CYAN}│${NC}  3. Proxy decodes, validates permissions, runs trace           ${CYAN}│${NC}"
echo -e "  ${CYAN}│${NC}  4. If valid, forwards to blockchain node                      ${CYAN}│${NC}"
echo -e "  ${CYAN}└─────────────────────────────────────────────────────────────────┘${NC}"
echo ""

# Deploy DemoToken (simple version without UUPS for demo)
print_info "Deploying SimpleDemoToken..."
TOKEN_DEPLOY=$(forge create src/token/SimpleDemoToken.sol:SimpleDemoToken \
    --rpc-url "$PROXY_RPC_URL" \
    --private-key "$PRIVATE_KEY" \
    --broadcast \
    --json 2>&1) || {
    print_error "Token deployment failed"
    echo "$TOKEN_DEPLOY"
    exit 1
}

TOKEN_ADDR=$(echo "$TOKEN_DEPLOY" | jq -r '.deployedTo // empty')
if [ -z "$TOKEN_ADDR" ] || [ "$TOKEN_ADDR" = "null" ]; then
    print_error "Failed to get token address"
    echo "$TOKEN_DEPLOY"
    exit 1
fi
print_success "SimpleDemoToken deployed at: $TOKEN_ADDR"

# Deploy LiquidityPool
print_info "Deploying SimpleLiquidityPool..."
POOL_DEPLOY=$(forge create src/pool/SimpleLiquidityPool.sol:SimpleLiquidityPool \
    --rpc-url "$PROXY_RPC_URL" \
    --private-key "$PRIVATE_KEY" \
    --broadcast \
    --json 2>&1) || {
    print_error "Pool deployment failed"
    echo "$POOL_DEPLOY"
    exit 1
}

POOL_ADDR=$(echo "$POOL_DEPLOY" | jq -r '.deployedTo // empty')
if [ -z "$POOL_ADDR" ] || [ "$POOL_ADDR" = "null" ]; then
    print_error "Failed to get pool address"
    echo "$POOL_DEPLOY"
    exit 1
fi
print_success "SimpleLiquidityPool deployed at: $POOL_ADDR"

# Deploy SwapRouter
print_info "Deploying SimpleSwapRouter..."
ROUTER_DEPLOY=$(forge create src/router/SimpleSwapRouter.sol:SimpleSwapRouter \
    --rpc-url "$PROXY_RPC_URL" \
    --private-key "$PRIVATE_KEY" \
    --broadcast \
    --json 2>&1) || {
    print_error "Router deployment failed"
    echo "$ROUTER_DEPLOY"
    exit 1
}

ROUTER_ADDR=$(echo "$ROUTER_DEPLOY" | jq -r '.deployedTo // empty')
if [ -z "$ROUTER_ADDR" ] || [ "$ROUTER_ADDR" = "null" ]; then
    print_error "Failed to get router address"
    echo "$ROUTER_DEPLOY"
    exit 1
fi
print_success "SimpleSwapRouter deployed at: $ROUTER_ADDR"

# =============================================================================
# Step 5: Register Contracts to Organization
# =============================================================================

if [ -n "$ORG_ID" ]; then
    print_step "Step 5: Registering Contracts to Organization"

    CONTRACTS_API_URL="${PROXY_BASE_URL}/api/orgs/${ORG_ID}/contracts"

    register_contract() {
        local addr="$1"
        local name="$2"
        local response
        response=$(curl -s -X POST "$CONTRACTS_API_URL" \
            -H "Content-Type: application/json" \
            -H "Authorization: Bearer $AUTH_TOKEN" \
            -d "{\"address\": \"$addr\", \"name\": \"$name\"}" 2>&1)

        if echo "$response" | grep -q '"id"'; then
            print_success "Registered $name at $addr"
        elif echo "$response" | grep -q 'already exists'; then
            print_info "$name already registered"
        else
            print_error "Failed to register $name: $response"
        fi
    }

    upload_abi() {
        local addr="$1"
        local name="$2"
        local contract_file="$3"
        local abi_json
        local response

        # Get ABI from forge output
        abi_json=$(jq -c '.abi' "out/${contract_file}/${name}.json" 2>/dev/null) || {
            print_info "No ABI found for $name"
            return
        }

        # Upload ABI to API
        response=$(curl -s -X PUT "${CONTRACTS_API_URL}/${addr}/abi" \
            -H "Content-Type: application/json" \
            -H "Authorization: Bearer $AUTH_TOKEN" \
            -d "{\"abi\": $(echo "$abi_json" | jq -Rs .)}" 2>&1)

        if echo "$response" | grep -q '"id"'; then
            local func_count=$(echo "$abi_json" | jq '[.[] | select(.type == "function")] | length')
            print_success "Uploaded ABI for $name ($func_count functions)"
        else
            print_error "Failed to upload ABI for $name: $response"
        fi
    }

    print_info "Registering contracts to org $ORG_ID..."
    register_contract "$TOKEN_ADDR" "SimpleDemoToken"
    register_contract "$POOL_ADDR" "SimpleLiquidityPool"
    register_contract "$ROUTER_ADDR" "SimpleSwapRouter"

    print_info "Uploading contract ABIs..."
    upload_abi "$TOKEN_ADDR" "SimpleDemoToken" "SimpleDemoToken.sol"
    upload_abi "$POOL_ADDR" "SimpleLiquidityPool" "SimpleLiquidityPool.sol"
    upload_abi "$ROUTER_ADDR" "SimpleSwapRouter" "SimpleSwapRouter.sol"

else
    print_step "Step 5: Skipping Contract Registration"
    print_info "No ORG_ID set - contracts accessible via deploy claim (unregistered)"
fi

# =============================================================================
# Step 6: Initialize Contracts
# =============================================================================

print_step "Step 6: Initializing Contracts"

# Initialize Token
print_info "Initializing token with pool reference..."
cast send "$TOKEN_ADDR" "initialize(address,address)" "$DEPLOYER_ADDRESS" "$POOL_ADDR" \
    --rpc-url "$PROXY_RPC_URL" \
    --private-key "$PRIVATE_KEY" \
    --quiet 2>/dev/null || print_info "Token may already be initialized"
print_success "Token initialized"

# Initialize Pool
print_info "Initializing pool with token reference..."
cast send "$POOL_ADDR" "initialize(address,address)" "$DEPLOYER_ADDRESS" "$TOKEN_ADDR" \
    --rpc-url "$PROXY_RPC_URL" \
    --private-key "$PRIVATE_KEY" \
    --quiet 2>/dev/null || print_info "Pool may already be initialized"
print_success "Pool initialized"

# Initialize Router
print_info "Initializing router with pool and token references..."
cast send "$ROUTER_ADDR" "initialize(address,address,address)" "$DEPLOYER_ADDRESS" "$POOL_ADDR" "$TOKEN_ADDR" \
    --rpc-url "$PROXY_RPC_URL" \
    --private-key "$PRIVATE_KEY" \
    --quiet 2>/dev/null || print_info "Router may already be initialized"
print_success "Router initialized"

# =============================================================================
# Step 7: Verify Deployment
# =============================================================================

print_step "Step 7: Verifying Deployment"

# Verify code exists
TOKEN_CODE=$(cast codesize "$TOKEN_ADDR" --rpc-url "$PROXY_RPC_URL" 2>/dev/null || echo "0")
POOL_CODE=$(cast codesize "$POOL_ADDR" --rpc-url "$PROXY_RPC_URL" 2>/dev/null || echo "0")
ROUTER_CODE=$(cast codesize "$ROUTER_ADDR" --rpc-url "$PROXY_RPC_URL" 2>/dev/null || echo "0")

print_value "Token code size" "$TOKEN_CODE bytes"
print_value "Pool code size" "$POOL_CODE bytes"
print_value "Router code size" "$ROUTER_CODE bytes"

# Verify cross-references
print_info "Verifying cross-references..."
POOL_TOKEN=$(cast call "$POOL_ADDR" "token()(address)" --rpc-url "$PROXY_RPC_URL" 2>/dev/null | tr '[:upper:]' '[:lower:]')
ROUTER_POOL=$(cast call "$ROUTER_ADDR" "pool()(address)" --rpc-url "$PROXY_RPC_URL" 2>/dev/null | tr '[:upper:]' '[:lower:]')

if [ "$POOL_TOKEN" = "$(echo $TOKEN_ADDR | tr '[:upper:]' '[:lower:]')" ]; then
    print_success "Pool correctly references Token"
else
    print_error "Pool token reference mismatch"
fi

if [ "$ROUTER_POOL" = "$(echo $POOL_ADDR | tr '[:upper:]' '[:lower:]')" ]; then
    print_success "Router correctly references Pool"
else
    print_error "Router pool reference mismatch"
fi

# =============================================================================
# Step 8: Test Interaction
# =============================================================================

print_step "Step 8: Testing Contract Interaction"

# Mint some tokens
print_info "Minting 1000 tokens..."
cast send "$TOKEN_ADDR" "mint(address,uint256)" "$DEPLOYER_ADDRESS" "1000000000000000000000" \
    --rpc-url "$PROXY_RPC_URL" \
    --private-key "$PRIVATE_KEY" \
    --quiet 2>/dev/null
print_success "Tokens minted"

# Check balance
TOKEN_BALANCE=$(cast call "$TOKEN_ADDR" "balanceOf(address)(uint256)" "$DEPLOYER_ADDRESS" \
    --rpc-url "$PROXY_RPC_URL" 2>/dev/null)
print_value "Token balance" "$TOKEN_BALANCE"

# =============================================================================
# Summary
# =============================================================================

print_header "Deployment Complete!"

echo -e "${WHITE}Deployed Contracts:${NC}"
echo -e "${CYAN}┌─────────────────────────────────────────────────────────────────────┐${NC}"
echo -e "${CYAN}│${NC}  ${YELLOW}SimpleDemoToken:${NC}     $TOKEN_ADDR"
echo -e "${CYAN}│${NC}  ${YELLOW}SimpleLiquidityPool:${NC} $POOL_ADDR"
echo -e "${CYAN}│${NC}  ${YELLOW}SimpleSwapRouter:${NC}    $ROUTER_ADDR"
echo -e "${CYAN}└─────────────────────────────────────────────────────────────────────┘${NC}"

echo ""
echo -e "${WHITE}What happened:${NC}"
echo -e "  ${GREEN}1.${NC} Transactions signed locally with your private key"
echo -e "  ${GREEN}2.${NC} Sent via eth_sendRawTransaction through Open Privacy Suite"
echo -e "  ${GREEN}3.${NC} Proxy validated your JWT token and permissions"
echo -e "  ${GREEN}4.${NC} Proxy ran debug_traceCall to verify cross-org isolation"
echo -e "  ${GREEN}5.${NC} Contracts deployed to the blockchain"

echo ""
echo -e "${WHITE}To interact with contracts:${NC}"
echo -e "  ${CYAN}# Check token balance${NC}"
echo -e "  cast call $TOKEN_ADDR \"balanceOf(address)(uint256)\" $DEPLOYER_ADDRESS --rpc-url \$ETH_RPC_URL"
echo ""
echo -e "  ${CYAN}# Transfer tokens${NC}"
echo -e "  cast send $TOKEN_ADDR \"transfer(address,uint256)\" 0xRECIPIENT 100 --rpc-url \$ETH_RPC_URL --private-key \$PRIVATE_KEY"
echo ""
