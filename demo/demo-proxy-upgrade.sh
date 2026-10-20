#!/bin/bash

# =============================================================================
# Open Privacy Suite - CREATE3 Proxy Upgrade Demo
# =============================================================================
# This script demonstrates the full flow of:
# 1. Preregistering addresses via CREATE3
# 2. Deploying an upgradeable proxy contract
# 3. Making calls before upgrade
# 4. Upgrading the implementation
# 5. Making calls after upgrade
# =============================================================================

set -e

# Default to allowing preregistration in demo mode
# In production, only org admins would have this capability
ALLOW_PREREGISTER="${ALLOW_PREREGISTER:-true}"

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

print_header "CREATE3 Proxy Upgrade Demo"

print_step "Checking Configuration"

# Environment variables with defaults
# IMPORTANT: PROXY_RPC_URL is the Open Privacy Suite (for RBAC), ANVIL_RPC_URL is direct to node (for read-only)
: "${ADMIN_API_URL:=http://localhost:8080/api}"
: "${PROXY_RPC_URL:=http://localhost:8080}"
: "${ANVIL_RPC_URL:=http://localhost:8545}"
: "${DEPLOYER_PRIVATE_KEY:=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80}"

# For read-only operations (checking code size, etc.), we can use Anvil directly
RPC_URL="$ANVIL_RPC_URL"

# Organization: can specify either ORG_SLUG (preferred) or ORG_ID
# ORG_SLUG is what you see in the UI, ORG_ID is the internal UUID
if [ -z "$ORG_ID" ] && [ -z "$ORG_SLUG" ]; then
    echo -e "${RED}Error: Either ORG_SLUG or ORG_ID environment variable is required${NC}"
    echo ""
    echo "Usage:"
    echo "  export ORG_SLUG=\"your-org-slug\"  # Recommended - this is what you see in the UI"
    echo "  ./demo-proxy-upgrade.sh"
    echo ""
    echo "Or:"
    echo "  export ORG_ID=\"uuid-of-org\""
    echo "  ./demo-proxy-upgrade.sh"
    exit 1
fi

# Optional: CREATE3 factory address (will be fetched from org config if not set)
CREATE3_FACTORY="${CREATE3_FACTORY:-}"

print_value "Admin API URL" "$ADMIN_API_URL"
print_value "Proxy RPC URL" "$PROXY_RPC_URL"
print_value "Anvil RPC URL" "$ANVIL_RPC_URL"

# If ORG_SLUG is provided, fetch ORG_ID from the API
if [ -n "$ORG_SLUG" ] && [ -z "$ORG_ID" ]; then
    print_substep "Looking up organization by slug: $ORG_SLUG"

    ORGS_RESPONSE=$(curl -s "$ADMIN_API_URL/v1/orgs")
    ORG_ID=$(echo "$ORGS_RESPONSE" | jq -r ".data[] | select(.slug == \"$ORG_SLUG\") | .id")

    if [ -z "$ORG_ID" ] || [ "$ORG_ID" = "null" ]; then
        print_error "Organization with slug '$ORG_SLUG' not found"
        echo ""
        echo -e "  ${WHITE}Available organizations:${NC}"
        echo "$ORGS_RESPONSE" | jq -r '.data[] | "  │ \(.slug) (id: \(.id))"' 2>/dev/null || echo "  │ (none found or API error)"
        exit 1
    fi

    ORG_NAME=$(echo "$ORGS_RESPONSE" | jq -r ".data[] | select(.slug == \"$ORG_SLUG\") | .name")
    print_success "Found organization: $ORG_NAME"
fi

print_value "Organization Slug" "${ORG_SLUG:-<not set>}"
print_value "Organization ID" "$ORG_ID"
print_value "Deployer Key" "${DEPLOYER_PRIVATE_KEY:0:10}..."

# Get deployer address from private key
DEPLOYER_ADDRESS=$(cast wallet address "$DEPLOYER_PRIVATE_KEY" 2>/dev/null)
print_value "Deployer Address" "$DEPLOYER_ADDRESS"

# =============================================================================
# Step 0: Authenticate and set up RBAC user with deploy permissions
# =============================================================================

print_step "Step 0: Authentication & RBAC Setup"

# Create a unique user DID for this demo
USER_EXTERNAL_ID="did:demo:deployer-$(date +%s)"
print_substep "User DID: $USER_EXTERNAL_ID"

# Step 0a: Start auth session to get session ID
print_substep "Starting auth session..."
AUTH_REQUEST_RESP=$(curl -s -X POST "$PROXY_RPC_URL/auth/request" \
    -H "Content-Type: application/json" \
    -d '{"reason": "Demo deployment test"}')

SESSION_ID=$(echo "$AUTH_REQUEST_RESP" | jq -r '.session_id // .sessionId // empty')
if [ -z "$SESSION_ID" ] || [ "$SESSION_ID" = "null" ]; then
    print_error "Failed to create auth session: $AUTH_REQUEST_RESP"
    exit 1
fi
print_success "Auth session created: ${SESSION_ID:0:20}..."

# Step 0b: Complete auth with mock token (requires AllowMockLogin=true)
# Mock token format: mock.{userDID}
print_substep "Authenticating with mock token..."
MOCK_TOKEN="mock.${USER_EXTERNAL_ID}"
AUTH_CALLBACK_RESP=$(curl -s -X POST "$PROXY_RPC_URL/auth/callback?session=$SESSION_ID" \
    -H "Content-Type: application/json" \
    -d "{\"token\": \"$MOCK_TOKEN\"}")

AUTH_TOKEN=$(echo "$AUTH_CALLBACK_RESP" | jq -r '.access_token // .accessToken // empty')
if [ -z "$AUTH_TOKEN" ] || [ "$AUTH_TOKEN" = "null" ]; then
    print_error "Failed to authenticate: $AUTH_CALLBACK_RESP"
    print_info "Make sure the proxy is running with ALLOW_MOCK_LOGIN=true (dev mode)"
    exit 1
fi
print_success "Got JWT access token"
print_value "Token (first 50 chars)" "${AUTH_TOKEN:0:50}..."

# Step 0c: Get the user's internal ID (created during auth)
print_substep "Getting user info..."
# The user was created during auth via EnsureUserExists
# We need to find the user by external ID to get the internal UUID
USERS_RESP=$(curl -s "$ADMIN_API_URL/v1/users?search=${USER_EXTERNAL_ID}")
USER_ID=$(echo "$USERS_RESP" | jq -r '.data[0].id // empty')

if [ -z "$USER_ID" ] || [ "$USER_ID" = "null" ]; then
    # Try without the search param - list all and filter
    USERS_RESP=$(curl -s "$ADMIN_API_URL/v1/users")
    USER_ID=$(echo "$USERS_RESP" | jq -r ".data[] | select(.external_id == \"$USER_EXTERNAL_ID\") | .id" | head -1)
fi

if [ -z "$USER_ID" ] || [ "$USER_ID" = "null" ]; then
    print_error "Could not find user ID after authentication"
    print_info "User response: $USERS_RESP"
    exit 1
fi
print_success "User ID: $USER_ID"

# Step 0d: Set KYC status FIRST (required before any RPC calls)
print_substep "Setting KYC status (required for RPC access)..."
KYC_RESP=$(curl -s -X PUT "$ADMIN_API_URL/v1/users/${USER_ID}" \
    -H "Content-Type: application/json" \
    -d '{"kyc": true}')
KYC_ERROR=$(echo "$KYC_RESP" | jq -r '.error // empty')
if [ -n "$KYC_ERROR" ] && [ "$KYC_ERROR" != "null" ]; then
    print_error "Failed to set KYC: $KYC_ERROR"
    exit 1
fi
print_success "KYC status set to true"

# Step 0e: Verify auth works by calling eth_chainId
print_substep "Verifying authentication..."
AUTH_TEST=$(rpc_call "eth_chainId" "[]")
CHAIN_ID=$(echo "$AUTH_TEST" | jq -r '.result // empty')
AUTH_ERROR=$(echo "$AUTH_TEST" | jq -r 'if .error then (if .error | type == "object" then .error.message else .error end) else empty end')
if [ -z "$CHAIN_ID" ] || [ -n "$AUTH_ERROR" ]; then
    print_error "Authentication verification failed: $AUTH_TEST"
    exit 1
fi
print_success "Authentication verified (chainId: $CHAIN_ID)"

# Step 0f: Set up deployers group with deploy claim
print_substep "Setting up group with deploy permissions..."
GROUPS_RESP=$(curl -s "$ADMIN_API_URL/v1/orgs/$ORG_ID/groups")
DEPLOYER_GROUP_ID=$(echo "$GROUPS_RESP" | jq -r '.data[] | select(.group.slug == "deployers" or .group.slug == "demo-deployers") | .group.id' | head -1)

if [ -z "$DEPLOYER_GROUP_ID" ] || [ "$DEPLOYER_GROUP_ID" = "null" ]; then
    # Create a deployers group
    GROUP_CREATE_RESP=$(curl -s -X POST "$ADMIN_API_URL/v1/orgs/$ORG_ID/groups" \
        -H "Content-Type: application/json" \
        -d '{
            "slug": "demo-deployers",
            "name": "Demo Deployers"
        }')
    DEPLOYER_GROUP_ID=$(echo "$GROUP_CREATE_RESP" | jq -r '.id')

    if [ -z "$DEPLOYER_GROUP_ID" ] || [ "$DEPLOYER_GROUP_ID" = "null" ]; then
        # Group might already exist, try to find it
        GROUPS_RESP=$(curl -s "$ADMIN_API_URL/v1/orgs/$ORG_ID/groups")
        DEPLOYER_GROUP_ID=$(echo "$GROUPS_RESP" | jq -r '.data[] | select(.group.slug == "demo-deployers") | .group.id')
    fi
fi

if [ -z "$DEPLOYER_GROUP_ID" ] || [ "$DEPLOYER_GROUP_ID" = "null" ]; then
    print_error "Failed to create or find deployers group"
    exit 1
fi

# Always configure group access (in case group was created earlier without proper config)
curl -s -X PUT "$ADMIN_API_URL/v1/orgs/$ORG_ID/groups/$DEPLOYER_GROUP_ID/access" \
    -H "Content-Type: application/json" \
    -d '{
        "allowed_methods": ["eth_sendTransaction", "eth_call", "eth_estimateGas", "eth_getBalance", "eth_chainId", "eth_blockNumber", "eth_getTransactionCount", "eth_getTransactionReceipt", "net_version"],
        "claims": ["deploy"]
    }' > /dev/null

print_success "Deployers group ready: $DEPLOYER_GROUP_ID"

# Step 0g: Add user to the deployers group
print_substep "Adding user to deployers group..."
MEMBERSHIP_RESP=$(curl -s -X POST "$ADMIN_API_URL/v1/users/${USER_ID}/memberships" \
    -H "Content-Type: application/json" \
    -d "{\"group_id\": \"$DEPLOYER_GROUP_ID\"}")
MEMBERSHIP_ERROR=$(echo "$MEMBERSHIP_RESP" | jq -r '.error // empty')
if [ -n "$MEMBERSHIP_ERROR" ] && [ "$MEMBERSHIP_ERROR" != "null" ] && ! echo "$MEMBERSHIP_ERROR" | grep -qi "already"; then
    print_error "Failed to add user to group: $MEMBERSHIP_ERROR"
    exit 1
fi
print_success "User added to deployers group"

# =============================================================================
# Step 1: Get or verify CREATE3 factory
# =============================================================================

print_step "Step 1: Checking CREATE3 Factory Configuration"

if [ -z "$CREATE3_FACTORY" ]; then
    print_substep "Fetching factory address from org config..."
    FACTORY_RESPONSE=$(curl -s "$ADMIN_API_URL/orgs/$ORG_ID/config/create3")
    CREATE3_FACTORY=$(echo "$FACTORY_RESPONSE" | jq -r '.factory // empty')
fi

# Check if we need to deploy a factory
NEED_FACTORY=false
if [ -z "$CREATE3_FACTORY" ] || [ "$CREATE3_FACTORY" = "null" ]; then
    NEED_FACTORY=true
else
    # Verify factory has code
    FACTORY_CODE_SIZE=$(cast codesize "$CREATE3_FACTORY" --rpc-url "$RPC_URL" 2>/dev/null || echo "0")
    if [ "$FACTORY_CODE_SIZE" = "0" ]; then
        print_info "Factory at $CREATE3_FACTORY has no code, deploying new factory..."
        NEED_FACTORY=true
    fi
fi

if [ "$NEED_FACTORY" = true ]; then
    print_substep "Deploying CREATE3 factory..."
    DEPLOY_RESP=$(curl -s -X POST "$ADMIN_API_URL/v1/dev/create3-factory")
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

print_success "CREATE3 Factory: $CREATE3_FACTORY"
FACTORY_CODE_SIZE=$(cast codesize "$CREATE3_FACTORY" --rpc-url "$RPC_URL" 2>/dev/null || echo "0")
print_success "Factory contract verified (code size: $FACTORY_CODE_SIZE bytes)"

# =============================================================================
# Step 2: Check for existing preregistered addresses
# =============================================================================

print_step "Step 2: Checking Preregistered Addresses"

print_substep "Fetching preregistered addresses from API..."
print_info "GET /orgs/$ORG_ID/addresses/preregistered"

PREREGISTERED_RESPONSE=$(curl -s "$ADMIN_API_URL/orgs/$ORG_ID/addresses/preregistered")
PREREGISTERED_COUNT=$(echo "$PREREGISTERED_RESPONSE" | jq 'length' 2>/dev/null || echo "0")

print_success "Found $PREREGISTERED_COUNT preregistered address(es)"

# We need at least 3 addresses: proxy, impl v1, impl v2
ADDRESSES_NEEDED=3

if [ "$PREREGISTERED_COUNT" -ge "$ADDRESSES_NEEDED" ]; then
    echo ""
    echo -e "  ${GREEN}Looking for unused preregistered addresses${NC}"
    echo -e "  ${WHITE}(In production, an org admin would have preregistered these)${NC}"
    echo ""

    # Find unused addresses that match the current factory (those without code deployed)
    UNUSED_ADDRESSES=""
    UNUSED_SALTS=""
    UNUSED_COUNT=0

    # Normalize factory address to lowercase for comparison
    FACTORY_LOWER=$(echo "$CREATE3_FACTORY" | tr '[:upper:]' '[:lower:]')

    print_substep "Checking which addresses are still available for factory $CREATE3_FACTORY..."
    for i in $(seq 0 $((PREREGISTERED_COUNT - 1))); do
        ADDR=$(echo "$PREREGISTERED_RESPONSE" | jq -r ".[$i].address")
        SALT=$(echo "$PREREGISTERED_RESPONSE" | jq -r ".[$i].salt")
        ADDR_FACTORY=$(echo "$PREREGISTERED_RESPONSE" | jq -r ".[$i].factory" | tr '[:upper:]' '[:lower:]')

        # Skip addresses that don't match the current factory
        if [ "$ADDR_FACTORY" != "$FACTORY_LOWER" ]; then
            continue
        fi

        CODE_SIZE=$(cast codesize "$ADDR" --rpc-url "$RPC_URL" 2>/dev/null || echo "0")

        if [ "$CODE_SIZE" = "0" ]; then
            UNUSED_ADDRESSES="$UNUSED_ADDRESSES $ADDR"
            UNUSED_SALTS="$UNUSED_SALTS $SALT"
            UNUSED_COUNT=$((UNUSED_COUNT + 1))
            if [ "$UNUSED_COUNT" -ge "$ADDRESSES_NEEDED" ]; then
                break
            fi
        fi
    done

    if [ "$UNUSED_COUNT" -lt "$ADDRESSES_NEEDED" ]; then
        # Check if ALLOW_PREREGISTER is set (admin mode) - allows preregistering for new factory
        if [ "${ALLOW_PREREGISTER:-false}" = "true" ]; then
            print_info "Found $UNUSED_COUNT unused address(es) for current factory, need $ADDRESSES_NEEDED"
            print_info "ALLOW_PREREGISTER=true - will preregister new addresses for the configured factory"

            SALT_PREFIX="demo-$(date +%s)"
            print_substep "Using salt prefix: $SALT_PREFIX"
            print_substep "Preregistering $ADDRESSES_NEEDED addresses..."

            PREREGISTER_RESPONSE=$(curl -s -X POST "$ADMIN_API_URL/orgs/$ORG_ID/addresses/preregister" \
                -H "Content-Type: application/json" \
                -d "{
                    \"factory\": \"$CREATE3_FACTORY\",
                    \"salt_prefix\": \"$SALT_PREFIX\",
                    \"count\": $ADDRESSES_NEEDED,
                    \"note\": \"Demo proxy upgrade addresses\"
                }")

            if echo "$PREREGISTER_RESPONSE" | jq -e '.addresses' > /dev/null 2>&1; then
                print_success "Addresses preregistered successfully!"

                PROXY_ADDR=$(echo "$PREREGISTER_RESPONSE" | jq -r '.addresses[0].address')
                IMPL_V1_ADDR=$(echo "$PREREGISTER_RESPONSE" | jq -r '.addresses[1].address')
                IMPL_V2_ADDR=$(echo "$PREREGISTER_RESPONSE" | jq -r '.addresses[2].address')

                PROXY_SALT=$(echo "$PREREGISTER_RESPONSE" | jq -r '.addresses[0].salt')
                IMPL_V1_SALT=$(echo "$PREREGISTER_RESPONSE" | jq -r '.addresses[1].salt')
                IMPL_V2_SALT=$(echo "$PREREGISTER_RESPONSE" | jq -r '.addresses[2].salt')

                echo ""
                echo -e "  ${WHITE}Newly preregistered addresses:${NC}"
                echo -e "  ${CYAN}┌─────────────────────────────────────────────────────────────────┐${NC}"
                echo -e "  ${CYAN}│${NC} ${YELLOW}Proxy:${NC}              $PROXY_ADDR"
                echo -e "  ${CYAN}│${NC} ${YELLOW}Implementation V1:${NC}  $IMPL_V1_ADDR"
                echo -e "  ${CYAN}│${NC} ${YELLOW}Implementation V2:${NC}  $IMPL_V2_ADDR"
                echo -e "  ${CYAN}└─────────────────────────────────────────────────────────────────┘${NC}"
            else
                print_error "Failed to preregister addresses"
                echo "$PREREGISTER_RESPONSE" | jq '.' 2>/dev/null || echo "$PREREGISTER_RESPONSE"
                exit 1
            fi
        else
            print_error "Not enough unused addresses available for the current factory"
            print_info "Found $UNUSED_COUNT unused address(es), need $ADDRESSES_NEEDED"
            print_info "The preregistered addresses may be for a different factory"
            print_info "Run with ALLOW_PREREGISTER=true to preregister new addresses"
            exit 1
        fi
    else
        # Enough unused addresses found - use them
        # Convert space-separated lists to arrays and extract addresses
        UNUSED_ADDRESSES_ARR=($UNUSED_ADDRESSES)
        UNUSED_SALTS_ARR=($UNUSED_SALTS)

        PROXY_ADDR="${UNUSED_ADDRESSES_ARR[0]}"
        IMPL_V1_ADDR="${UNUSED_ADDRESSES_ARR[1]}"
        IMPL_V2_ADDR="${UNUSED_ADDRESSES_ARR[2]}"

        PROXY_SALT="${UNUSED_SALTS_ARR[0]}"
        IMPL_V1_SALT="${UNUSED_SALTS_ARR[1]}"
        IMPL_V2_SALT="${UNUSED_SALTS_ARR[2]}"

        print_success "Found $UNUSED_COUNT unused address(es)"
        echo ""
        echo -e "  ${WHITE}Selected addresses for deployment:${NC}"
        echo -e "  ${CYAN}┌─────────────────────────────────────────────────────────────────┐${NC}"
        echo -e "  ${CYAN}│${NC} ${YELLOW}Proxy:${NC}              $PROXY_ADDR"
        echo -e "  ${CYAN}│${NC} ${YELLOW}Implementation V1:${NC}  $IMPL_V1_ADDR"
        echo -e "  ${CYAN}│${NC} ${YELLOW}Implementation V2:${NC}  $IMPL_V2_ADDR"
        echo -e "  ${CYAN}└─────────────────────────────────────────────────────────────────┘${NC}"
    fi

    if [ "$UNUSED_COUNT" -gt "$ADDRESSES_NEEDED" ]; then
        REMAINING=$((UNUSED_COUNT - ADDRESSES_NEEDED))
        print_info "$REMAINING additional unused address(es) available for future deployments"
    fi

else
    # Not enough preregistered addresses
    echo ""
    echo -e "  ${YELLOW}⚠ Not enough preregistered addresses available${NC}"
    echo -e "  ${WHITE}  Need: $ADDRESSES_NEEDED, Found: $PREREGISTERED_COUNT${NC}"
    echo ""

    if [ "$PREREGISTERED_COUNT" -gt 0 ]; then
        echo -e "  ${WHITE}Available addresses:${NC}"
        echo "$PREREGISTERED_RESPONSE" | jq -r '.[] | "  │ \(.address)"' 2>/dev/null
        echo ""
    fi

    # Check if ALLOW_PREREGISTER is set (admin mode)
    if [ "${ALLOW_PREREGISTER:-false}" = "true" ]; then
        print_step "Step 2b: Preregistering Addresses (Admin Mode)"
        echo -e "  ${YELLOW}⚠ ALLOW_PREREGISTER=true - running in admin mode${NC}"
        echo -e "  ${WHITE}  In production, only org admins should preregister addresses${NC}"
        echo ""

        SALT_PREFIX="demo-$(date +%s)"
        print_substep "Using salt prefix: $SALT_PREFIX"
        print_substep "Preregistering $ADDRESSES_NEEDED addresses..."

        PREREGISTER_RESPONSE=$(curl -s -X POST "$ADMIN_API_URL/orgs/$ORG_ID/addresses/preregister" \
            -H "Content-Type: application/json" \
            -d "{
                \"factory\": \"$CREATE3_FACTORY\",
                \"salt_prefix\": \"$SALT_PREFIX\",
                \"count\": $ADDRESSES_NEEDED,
                \"note\": \"Demo proxy upgrade addresses\"
            }")

        if echo "$PREREGISTER_RESPONSE" | jq -e '.addresses' > /dev/null 2>&1; then
            print_success "Addresses preregistered successfully!"

            PROXY_ADDR=$(echo "$PREREGISTER_RESPONSE" | jq -r '.addresses[0].address')
            IMPL_V1_ADDR=$(echo "$PREREGISTER_RESPONSE" | jq -r '.addresses[1].address')
            IMPL_V2_ADDR=$(echo "$PREREGISTER_RESPONSE" | jq -r '.addresses[2].address')

            PROXY_SALT=$(echo "$PREREGISTER_RESPONSE" | jq -r '.addresses[0].salt')
            IMPL_V1_SALT=$(echo "$PREREGISTER_RESPONSE" | jq -r '.addresses[1].salt')
            IMPL_V2_SALT=$(echo "$PREREGISTER_RESPONSE" | jq -r '.addresses[2].salt')

            echo ""
            echo -e "  ${WHITE}Newly preregistered addresses:${NC}"
            echo -e "  ${CYAN}┌─────────────────────────────────────────────────────────────────┐${NC}"
            echo -e "  ${CYAN}│${NC} ${YELLOW}Proxy:${NC}              $PROXY_ADDR"
            echo -e "  ${CYAN}│${NC} ${YELLOW}Implementation V1:${NC}  $IMPL_V1_ADDR"
            echo -e "  ${CYAN}│${NC} ${YELLOW}Implementation V2:${NC}  $IMPL_V2_ADDR"
            echo -e "  ${CYAN}└─────────────────────────────────────────────────────────────────┘${NC}"
        else
            print_error "Failed to preregister addresses"
            echo "$PREREGISTER_RESPONSE" | jq '.' 2>/dev/null || echo "$PREREGISTER_RESPONSE"
            exit 1
        fi
    else
        echo -e "  ${RED}Cannot proceed without preregistered addresses.${NC}"
        echo ""
        echo -e "  ${WHITE}Options:${NC}"
        echo -e "  ${CYAN}1.${NC} Ask your org admin to preregister addresses via the UI"
        echo -e "  ${CYAN}2.${NC} Run with ALLOW_PREREGISTER=true to preregister (admin only):"
        echo ""
        echo -e "     ${GREEN}ALLOW_PREREGISTER=true ./demo-proxy-upgrade.sh${NC}"
        echo ""
        exit 1
    fi
fi

# =============================================================================
# Step 3: Build contracts
# =============================================================================

print_step "Step 3: Building Contracts"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONTRACTS_SRC_DIR="$SCRIPT_DIR/contracts"

# Create a temp directory for building (keeps repo clean)
BUILD_DIR=$(mktemp -d)
print_substep "Using temp build directory: $BUILD_DIR"

# Copy contracts to temp dir
cp -r "$CONTRACTS_SRC_DIR"/* "$BUILD_DIR/"
cd "$BUILD_DIR"

# Cleanup on exit
cleanup() {
    if [ -n "$BUILD_DIR" ] && [ -d "$BUILD_DIR" ]; then
        rm -rf "$BUILD_DIR"
    fi
}
trap cleanup EXIT

# Initialize git repo (required for forge install)
print_substep "Initializing git repository for forge..."
git init --quiet
git config user.email "demo@example.com"
git config user.name "Demo"
git add -A
git commit -m "Initial" --quiet

# Install dependencies using git clone directly (forge install has interactive prompts)
print_substep "Installing dependencies..."
# Remove any copied local artifacts (these are gitignored but cp -r copies them)
rm -rf lib out cache
mkdir -p lib
git clone --quiet --depth 1 https://github.com/OpenZeppelin/openzeppelin-contracts-upgradeable.git lib/openzeppelin-contracts-upgradeable || {
    print_error "Failed to clone openzeppelin-contracts-upgradeable"
    exit 1
}
git clone --quiet --depth 1 https://github.com/OpenZeppelin/openzeppelin-contracts.git lib/openzeppelin-contracts || {
    print_error "Failed to clone openzeppelin-contracts"
    exit 1
}
git clone --quiet --depth 1 https://github.com/foundry-rs/forge-std.git lib/forge-std || {
    print_error "Failed to clone forge-std"
    exit 1
}
print_success "Dependencies installed"

print_substep "Compiling contracts..."
forge build --quiet

print_success "Contracts compiled successfully"

# Get bytecode
BOXV1_BYTECODE=$(forge inspect BoxV1 bytecode)
BOXV2_BYTECODE=$(forge inspect BoxV2 bytecode)

print_value "BoxV1 bytecode size" "$(echo -n "$BOXV1_BYTECODE" | wc -c | tr -d ' ') chars"
print_value "BoxV2 bytecode size" "$(echo -n "$BOXV2_BYTECODE" | wc -c | tr -d ' ') chars"

# =============================================================================
# Step 5: Deploy Implementation V1
# =============================================================================

print_step "Step 4: Deploying Implementation V1"

print_substep "Deploying BoxV1 to preregistered address via CREATE3..."
print_info "Target address: $IMPL_V1_ADDR"
print_info "Salt: ${IMPL_V1_SALT:0:20}..."
print_info "Factory: $CREATE3_FACTORY"
print_info "Bytecode length: ${#BOXV1_BYTECODE} chars"

# Verify variables are set
if [ -z "$IMPL_V1_SALT" ]; then
    print_error "IMPL_V1_SALT is empty!"
    exit 1
fi
if [ -z "$BOXV1_BYTECODE" ]; then
    print_error "BOXV1_BYTECODE is empty!"
    exit 1
fi

# Deploy via CREATE3 factory
# The factory.deploy(bytes32 salt, bytes creationCode) function
print_substep "Building deployment calldata..."
set +e
DEPLOY_CALLDATA=$(cast calldata "deploy(bytes32,bytes)" "$IMPL_V1_SALT" "$BOXV1_BYTECODE" 2>&1)
CALLDATA_EXIT_CODE=$?
set -e

if [ "$CALLDATA_EXIT_CODE" -ne 0 ] || [ -z "$DEPLOY_CALLDATA" ]; then
    print_error "Failed to build deployment calldata (exit code: $CALLDATA_EXIT_CODE)"
    echo -e "  ${WHITE}Salt:${NC} $IMPL_V1_SALT"
    echo -e "  ${WHITE}Bytecode length:${NC} ${#BOXV1_BYTECODE}"
    echo -e "  ${WHITE}Error:${NC} $DEPLOY_CALLDATA"
    exit 1
fi

print_substep "Sending deployment transaction through Open Privacy Suite..."

# Get the nonce for the deployer
NONCE_RESP=$(rpc_call "eth_getTransactionCount" "[\"$DEPLOYER_ADDRESS\", \"latest\"]")
NONCE=$(echo "$NONCE_RESP" | jq -r '.result // "0x0"')

# Build the transaction parameters
TX_PARAMS=$(cat <<EOF
[{
    "from": "$DEPLOYER_ADDRESS",
    "to": "$CREATE3_FACTORY",
    "data": "$DEPLOY_CALLDATA",
    "gas": "0x300000",
    "nonce": "$NONCE"
}]
EOF
)

# Send transaction through the proxy (this goes through RBAC!)
DEPLOY_RESULT=$(rpc_call "eth_sendTransaction" "$TX_PARAMS")

TX_HASH_V1=$(echo "$DEPLOY_RESULT" | jq -r '.result // empty')
DEPLOY_ERROR=$(echo "$DEPLOY_RESULT" | jq -r 'if .error then (if .error | type == "object" then .error.message else .error end) else empty end')

if [ -z "$TX_HASH_V1" ] || [ "$TX_HASH_V1" = "null" ] || [ -n "$DEPLOY_ERROR" ]; then
    print_error "Failed to deploy BoxV1"
    echo -e "  ${WHITE}Error details:${NC}"
    echo "$DEPLOY_RESULT" | jq . 2>/dev/null || echo "$DEPLOY_RESULT"
    echo ""
    echo -e "  ${WHITE}Possible causes:${NC}"
    echo -e "  ${CYAN}1.${NC} CREATE3 factory not deployed (chain was reset?)"
    echo -e "  ${CYAN}2.${NC} Salt already used (address already has code)"
    echo -e "  ${CYAN}3.${NC} Missing deploy claim for target address"
    echo -e "  ${CYAN}4.${NC} Address not preregistered for this org"
    echo -e "  ${CYAN}5.${NC} RPC connection issue"
    exit 1
fi

print_success "BoxV1 deployed!"
print_value "Transaction" "$TX_HASH_V1"
print_value "Address" "$IMPL_V1_ADDR"

# Verify deployment
CODE_SIZE=$(cast codesize "$IMPL_V1_ADDR" --rpc-url "$RPC_URL" 2>/dev/null || echo "0")
print_value "Contract code size" "$CODE_SIZE bytes"

# =============================================================================
# Step 6: Deploy ERC1967 Proxy
# =============================================================================

print_step "Step 5: Deploying ERC1967 Proxy"

print_substep "Building proxy deployment bytecode..."

# Initialize data for BoxV1.initialize(owner)
INIT_DATA=$(cast calldata "initialize(address)" "$DEPLOYER_ADDRESS")

# ERC1967Proxy constructor takes (implementation, data)
# We need to deploy a proxy that points to our V1 implementation
# Using OpenZeppelin's ERC1967Proxy pattern

# For simplicity, let's use a minimal UUPS proxy bytecode
# This is a simplified version - in production you'd use OZ's proxy

print_info "Target proxy address: $PROXY_ADDR"
print_info "Implementation: $IMPL_V1_ADDR"

# Get the ERC1967Proxy bytecode and encode constructor args
# We'll need to compile a proxy contract
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
# Encode constructor args: (implementation, initData)
CONSTRUCTOR_ARGS=$(cast abi-encode "constructor(address,bytes)" "$IMPL_V1_ADDR" "$INIT_DATA")
# Remove 0x prefix from constructor args
CONSTRUCTOR_ARGS_NO_PREFIX="${CONSTRUCTOR_ARGS:2}"
PROXY_INIT_CODE="${PROXY_BYTECODE}${CONSTRUCTOR_ARGS_NO_PREFIX}"

print_substep "Deploying proxy via CREATE3 through Open Privacy Suite..."

DEPLOY_PROXY_CALLDATA=$(cast calldata "deploy(bytes32,bytes)" "$PROXY_SALT" "$PROXY_INIT_CODE")

# Get the nonce for the deployer
NONCE_RESP=$(rpc_call "eth_getTransactionCount" "[\"$DEPLOYER_ADDRESS\", \"latest\"]")
NONCE=$(echo "$NONCE_RESP" | jq -r '.result // "0x0"')

# Build the transaction parameters
TX_PARAMS=$(cat <<EOF
[{
    "from": "$DEPLOYER_ADDRESS",
    "to": "$CREATE3_FACTORY",
    "data": "$DEPLOY_PROXY_CALLDATA",
    "gas": "0x300000",
    "nonce": "$NONCE"
}]
EOF
)

# Send transaction through the proxy (this goes through RBAC!)
DEPLOY_PROXY_RESULT=$(rpc_call "eth_sendTransaction" "$TX_PARAMS")

TX_HASH_PROXY=$(echo "$DEPLOY_PROXY_RESULT" | jq -r '.result // empty')
DEPLOY_PROXY_ERROR=$(echo "$DEPLOY_PROXY_RESULT" | jq -r 'if .error then (if .error | type == "object" then .error.message else .error end) else empty end')

if [ -z "$TX_HASH_PROXY" ] || [ "$TX_HASH_PROXY" = "null" ] || [ -n "$DEPLOY_PROXY_ERROR" ]; then
    print_error "Failed to deploy proxy"
    echo -e "  ${WHITE}Error details:${NC}"
    echo "$DEPLOY_PROXY_RESULT" | jq . 2>/dev/null || echo "$DEPLOY_PROXY_RESULT"
    exit 1
fi

print_success "Proxy deployed!"
print_value "Transaction" "$TX_HASH_PROXY"
print_value "Proxy Address" "$PROXY_ADDR"

# =============================================================================
# Step 7: Interact with V1
# =============================================================================

print_step "Step 6: Interacting with Contract (V1)"

print_substep "Calling version()..."
VERSION_V1=$(cast call "$PROXY_ADDR" "version()(string)" --rpc-url "$RPC_URL" 2>/dev/null || echo "error")
print_contract_call "$PROXY_ADDR" "version()" "$VERSION_V1"

print_substep "Calling store(42) through Open Privacy Suite..."
STORE_CALLDATA=$(cast calldata "store(uint256)" 42)

# Get the nonce for the deployer
NONCE_RESP=$(rpc_call "eth_getTransactionCount" "[\"$DEPLOYER_ADDRESS\", \"latest\"]")
NONCE=$(echo "$NONCE_RESP" | jq -r '.result // "0x0"')

TX_PARAMS=$(cat <<EOF
[{
    "from": "$DEPLOYER_ADDRESS",
    "to": "$PROXY_ADDR",
    "data": "$STORE_CALLDATA",
    "gas": "0x100000",
    "nonce": "$NONCE"
}]
EOF
)
STORE_RESULT=$(rpc_call "eth_sendTransaction" "$TX_PARAMS")
STORE_TX=$(echo "$STORE_RESULT" | jq -r '.result // empty')
if [ -z "$STORE_TX" ] || [ "$STORE_TX" = "null" ]; then
    print_error "Failed to call store(42): $(echo "$STORE_RESULT" | jq -r '.error // .')"
    exit 1
fi
print_success "Stored value: 42"

print_substep "Calling retrieve()..."
STORED_VALUE=$(cast call "$PROXY_ADDR" "retrieve()(uint256)" --rpc-url "$RPC_URL" 2>/dev/null)
print_contract_call "$PROXY_ADDR" "retrieve()" "$STORED_VALUE"

# =============================================================================
# Step 8: Deploy Implementation V2
# =============================================================================

print_step "Step 7: Deploying Implementation V2"

print_substep "Deploying BoxV2 to preregistered address via CREATE3 through Open Privacy Suite..."
print_info "Target address: $IMPL_V2_ADDR"

DEPLOY_V2_CALLDATA=$(cast calldata "deploy(bytes32,bytes)" "$IMPL_V2_SALT" "$BOXV2_BYTECODE")

# Get the nonce for the deployer
NONCE_RESP=$(rpc_call "eth_getTransactionCount" "[\"$DEPLOYER_ADDRESS\", \"latest\"]")
NONCE=$(echo "$NONCE_RESP" | jq -r '.result // "0x0"')

# Build the transaction parameters
TX_PARAMS=$(cat <<EOF
[{
    "from": "$DEPLOYER_ADDRESS",
    "to": "$CREATE3_FACTORY",
    "data": "$DEPLOY_V2_CALLDATA",
    "gas": "0x300000",
    "nonce": "$NONCE"
}]
EOF
)

# Send transaction through the proxy (this goes through RBAC!)
DEPLOY_V2_RESULT=$(rpc_call "eth_sendTransaction" "$TX_PARAMS")

TX_HASH_V2=$(echo "$DEPLOY_V2_RESULT" | jq -r '.result // empty')
DEPLOY_V2_ERROR=$(echo "$DEPLOY_V2_RESULT" | jq -r 'if .error then (if .error | type == "object" then .error.message else .error end) else empty end')

if [ -z "$TX_HASH_V2" ] || [ "$TX_HASH_V2" = "null" ] || [ -n "$DEPLOY_V2_ERROR" ]; then
    print_error "Failed to deploy BoxV2"
    echo -e "  ${WHITE}Error details:${NC}"
    echo "$DEPLOY_V2_RESULT" | jq . 2>/dev/null || echo "$DEPLOY_V2_RESULT"
    exit 1
fi

print_success "BoxV2 deployed!"
print_value "Transaction" "$TX_HASH_V2"
print_value "Address" "$IMPL_V2_ADDR"

# =============================================================================
# Step 9: Upgrade Proxy to V2
# =============================================================================

print_step "Step 8: Upgrading Proxy to V2"

print_substep "Calling upgradeToAndCall() through Open Privacy Suite..."
print_info "Old implementation: $IMPL_V1_ADDR"
print_info "New implementation: $IMPL_V2_ADDR"

# UUPS upgrade - call upgradeToAndCall on the proxy
UPGRADE_CALLDATA=$(cast calldata "upgradeToAndCall(address,bytes)" "$IMPL_V2_ADDR" "0x")

# Get the nonce for the deployer
NONCE_RESP=$(rpc_call "eth_getTransactionCount" "[\"$DEPLOYER_ADDRESS\", \"latest\"]")
NONCE=$(echo "$NONCE_RESP" | jq -r '.result // "0x0"')

TX_PARAMS=$(cat <<EOF
[{
    "from": "$DEPLOYER_ADDRESS",
    "to": "$PROXY_ADDR",
    "data": "$UPGRADE_CALLDATA",
    "gas": "0x100000",
    "nonce": "$NONCE"
}]
EOF
)

UPGRADE_RESULT=$(rpc_call "eth_sendTransaction" "$TX_PARAMS")

TX_HASH_UPGRADE=$(echo "$UPGRADE_RESULT" | jq -r '.result // empty')
UPGRADE_ERROR=$(echo "$UPGRADE_RESULT" | jq -r 'if .error then (if .error | type == "object" then .error.message else .error end) else empty end')

if [ -z "$TX_HASH_UPGRADE" ] || [ "$TX_HASH_UPGRADE" = "null" ] || [ -n "$UPGRADE_ERROR" ]; then
    print_error "Failed to upgrade proxy"
    echo -e "  ${WHITE}Error details:${NC}"
    echo "$UPGRADE_RESULT" | jq . 2>/dev/null || echo "$UPGRADE_RESULT"
    exit 1
fi

print_success "Proxy upgraded to V2!"
print_value "Transaction" "$TX_HASH_UPGRADE"

# =============================================================================
# Step 10: Interact with V2
# =============================================================================

print_step "Step 9: Interacting with Contract (V2)"

print_substep "Calling version()..."
VERSION_V2=$(cast call "$PROXY_ADDR" "version()(string)" --rpc-url "$RPC_URL" 2>/dev/null || echo "error")
print_contract_call "$PROXY_ADDR" "version()" "$VERSION_V2"

print_substep "Calling retrieve() - value should be preserved..."
STORED_VALUE_V2=$(cast call "$PROXY_ADDR" "retrieve()(uint256)" --rpc-url "$RPC_URL" 2>/dev/null)
print_contract_call "$PROXY_ADDR" "retrieve()" "$STORED_VALUE_V2"

print_substep "Calling increment() - new V2 function through Open Privacy Suite..."
INCREMENT_CALLDATA=$(cast calldata "increment()")

# Get the nonce for the deployer
NONCE_RESP=$(rpc_call "eth_getTransactionCount" "[\"$DEPLOYER_ADDRESS\", \"latest\"]")
NONCE=$(echo "$NONCE_RESP" | jq -r '.result // "0x0"')

TX_PARAMS=$(cat <<EOF
[{
    "from": "$DEPLOYER_ADDRESS",
    "to": "$PROXY_ADDR",
    "data": "$INCREMENT_CALLDATA",
    "gas": "0x100000",
    "nonce": "$NONCE"
}]
EOF
)
INCREMENT_RESULT=$(rpc_call "eth_sendTransaction" "$TX_PARAMS")
INCREMENT_TX=$(echo "$INCREMENT_RESULT" | jq -r '.result // empty')
if [ -z "$INCREMENT_TX" ] || [ "$INCREMENT_TX" = "null" ]; then
    print_error "Failed to call increment(): $(echo "$INCREMENT_RESULT" | jq -r '.error // .')"
    exit 1
fi
print_success "Called increment()"

print_substep "Calling retrieve() after increment..."
STORED_VALUE_AFTER=$(cast call "$PROXY_ADDR" "retrieve()(uint256)" --rpc-url "$RPC_URL" 2>/dev/null)
print_contract_call "$PROXY_ADDR" "retrieve()" "$STORED_VALUE_AFTER"

# =============================================================================
# Summary
# =============================================================================

print_header "Demo Complete!"

echo -e "${WHITE}Summary:${NC}"
echo -e "${CYAN}┌─────────────────────────────────────────────────────────────────────┐${NC}"
echo -e "${CYAN}│${NC}  ${YELLOW}CREATE3 Factory:${NC}     $CREATE3_FACTORY"
echo -e "${CYAN}│${NC}  ${YELLOW}Proxy Address:${NC}       $PROXY_ADDR"
echo -e "${CYAN}│${NC}  ${YELLOW}Implementation V1:${NC}   $IMPL_V1_ADDR"
echo -e "${CYAN}│${NC}  ${YELLOW}Implementation V2:${NC}   $IMPL_V2_ADDR"
echo -e "${CYAN}├─────────────────────────────────────────────────────────────────────┤${NC}"
echo -e "${CYAN}│${NC}  ${GREEN}Version before upgrade:${NC}  $VERSION_V1"
echo -e "${CYAN}│${NC}  ${GREEN}Version after upgrade:${NC}   $VERSION_V2"
echo -e "${CYAN}│${NC}  ${GREEN}Value preserved:${NC}         $STORED_VALUE_V2"
echo -e "${CYAN}│${NC}  ${GREEN}Value after increment:${NC}   $STORED_VALUE_AFTER"
echo -e "${CYAN}└─────────────────────────────────────────────────────────────────────┘${NC}"

echo ""
echo -e "${GREEN}All operations completed successfully!${NC}"
echo ""
echo -e "${WHITE}Key Points Demonstrated:${NC}"
echo -e "  ${CYAN}1.${NC} Addresses were preregistered before deployment"
echo -e "  ${CYAN}2.${NC} Contracts deployed to deterministic CREATE3 addresses"
echo -e "  ${CYAN}3.${NC} Proxy pattern preserves state across upgrades"
echo -e "  ${CYAN}4.${NC} New functionality (increment) available after upgrade"
echo ""
