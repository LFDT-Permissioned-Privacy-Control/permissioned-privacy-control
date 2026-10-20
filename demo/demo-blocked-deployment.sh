#!/bin/bash

# =============================================================================
# Open Privacy Suite - Bytecode Validation Security Demo
# =============================================================================
# This script demonstrates the bytecode validation security of the Open Privacy Suite.
#
# The MaliciousBox contract:
# 1. Contains a hardcoded CALL to 0xDeaDbeeF (not owned by the org)
# 2. Attempts deployment via CREATE3 factory
#
# Expected behavior:
# - The Open Privacy Suite BLOCKS the deployment because the bytecode contains
#   a CALL to an address that is not owned by or preregistered for the org.
#
# This demonstrates:
# - Bytecode analysis detects external call targets
# - Deployments with calls to unauthorized addresses are BLOCKED
# - The proxy validates bytecode BEFORE allowing factory deployments
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

print_warning() {
    echo -e "  ${YELLOW}⚠${NC} $1"
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

print_header "Bytecode Validation Security Demo"

print_step "Checking Configuration"

# Environment variables with defaults
# IMPORTANT: PROXY_RPC_URL is the Open Privacy Suite, ANVIL_RPC_URL is direct to node
: "${ADMIN_API_URL:=http://localhost:8080/api/v1/admin}"
: "${PROXY_RPC_URL:=http://localhost:8080}"
: "${ANVIL_RPC_URL:=http://localhost:8545}"
: "${DEPLOYER_PRIVATE_KEY:=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80}"

# For checking contract code, we can use Anvil directly (read-only)
RPC_URL="$ANVIL_RPC_URL"

print_value "Admin API URL" "$ADMIN_API_URL"
print_value "Proxy RPC URL" "$PROXY_RPC_URL"
print_value "Anvil RPC URL" "$ANVIL_RPC_URL"

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
    if [ -z "$ORG_ID" ] || [ "$ORG_ID" = "null" ]; then
        print_error "Organization with slug '$ORG_SLUG' not found"
        exit 1
    fi
fi

print_value "Organization ID" "$ORG_ID"

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
USERS_RESP=$(curl -s "$ADMIN_API_URL/users?search=${USER_EXTERNAL_ID}")
USER_ID=$(echo "$USERS_RESP" | jq -r '.data[0].id // empty')

if [ -z "$USER_ID" ] || [ "$USER_ID" = "null" ]; then
    # Try without the search param - list all and filter
    USERS_RESP=$(curl -s "$ADMIN_API_URL/users")
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
KYC_RESP=$(curl -s -X PUT "$ADMIN_API_URL/users/${USER_ID}" \
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
# Handle both .result and .error (which can be string or object)
CHAIN_ID=$(echo "$AUTH_TEST" | jq -r '.result // empty')
AUTH_ERROR=$(echo "$AUTH_TEST" | jq -r 'if .error then (if .error | type == "object" then .error.message else .error end) else empty end')
if [ -z "$CHAIN_ID" ] || [ -n "$AUTH_ERROR" ]; then
    print_error "Authentication verification failed: $AUTH_TEST"
    exit 1
fi
print_success "Authentication verified (chainId: $CHAIN_ID)"

# Step 0f: Set up deployers group with deploy claim (after KYC is set)
print_substep "Setting up group with deploy permissions..."
GROUPS_RESP=$(curl -s "$ADMIN_API_URL/orgs/$ORG_ID/groups")
DEPLOYER_GROUP_ID=$(echo "$GROUPS_RESP" | jq -r '.data[] | select(.group.slug == "deployers" or .group.slug == "demo-deployers") | .group.id' | head -1)

if [ -z "$DEPLOYER_GROUP_ID" ] || [ "$DEPLOYER_GROUP_ID" = "null" ]; then
    # Create a deployers group
    GROUP_CREATE_RESP=$(curl -s -X POST "$ADMIN_API_URL/orgs/$ORG_ID/groups" \
        -H "Content-Type: application/json" \
        -d '{
            "slug": "demo-deployers",
            "name": "Demo Deployers"
        }')
    DEPLOYER_GROUP_ID=$(echo "$GROUP_CREATE_RESP" | jq -r '.id')

    if [ -z "$DEPLOYER_GROUP_ID" ] || [ "$DEPLOYER_GROUP_ID" = "null" ]; then
        # Group might already exist, try to find it
        GROUPS_RESP=$(curl -s "$ADMIN_API_URL/orgs/$ORG_ID/groups")
        DEPLOYER_GROUP_ID=$(echo "$GROUPS_RESP" | jq -r '.data[] | select(.group.slug == "demo-deployers") | .group.id')
    fi
fi

if [ -z "$DEPLOYER_GROUP_ID" ] || [ "$DEPLOYER_GROUP_ID" = "null" ]; then
    print_error "Failed to create or find deployers group"
    exit 1
fi

# Always configure group access (in case group was created earlier without proper config)
curl -s -X PUT "$ADMIN_API_URL/orgs/$ORG_ID/groups/$DEPLOYER_GROUP_ID/access" \
    -H "Content-Type: application/json" \
    -d '{
        "allowed_methods": ["eth_sendTransaction", "eth_call", "eth_estimateGas", "eth_getBalance", "eth_chainId", "eth_blockNumber", "eth_getTransactionCount", "net_version"],
        "allowed_methods": ["*"], "claims": ["deploy"]
    }' > /dev/null

print_success "Deployers group ready: $DEPLOYER_GROUP_ID"

# Step 0g: Add user to the deployers group
print_substep "Adding user to deployers group..."
MEMBERSHIP_RESP=$(curl -s -X POST "$ADMIN_API_URL/users/${USER_ID}/memberships" \
    -H "Content-Type: application/json" \
    -d "{\"group_id\": \"$DEPLOYER_GROUP_ID\"}")

MEMBERSHIP_ID=$(echo "$MEMBERSHIP_RESP" | jq -r '.id // empty')
MEMBERSHIP_ERROR=$(echo "$MEMBERSHIP_RESP" | jq -r '.error // empty')

if [ -n "$MEMBERSHIP_ID" ] && [ "$MEMBERSHIP_ID" != "null" ]; then
    print_success "User added to deployers group"
elif echo "$MEMBERSHIP_ERROR" | grep -qi "already\|exists\|duplicate"; then
    print_success "User already in deployers group"
else
    print_warning "Membership response: $MEMBERSHIP_RESP"
fi

# =============================================================================
# Step 1: Get CREATE3 factory
# =============================================================================

print_step "Step 1: Checking CREATE3 Factory"

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
    FACTORY_CODE_SIZE=$(cast codesize "$CREATE3_FACTORY" --rpc-url "$ANVIL_RPC_URL" 2>/dev/null || echo "0")
    if [ "$FACTORY_CODE_SIZE" = "0" ]; then
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

print_success "CREATE3 Factory: $CREATE3_FACTORY"
FACTORY_CODE_SIZE=$(cast codesize "$CREATE3_FACTORY" --rpc-url "$ANVIL_RPC_URL" 2>/dev/null || echo "0")
print_success "Factory contract verified ($FACTORY_CODE_SIZE bytes)"

# =============================================================================
# Step 2: Get preregistered address
# =============================================================================

print_step "Step 2: Getting Preregistered Address"

print_substep "Fetching preregistered addresses..."
PREREGISTERED_RESPONSE=$(curl -s "$ADMIN_API_URL/orgs/$ORG_ID/addresses/preregistered")
FACTORY_LOWER=$(echo "$CREATE3_FACTORY" | tr '[:upper:]' '[:lower:]')

# Find an unused address for the current factory
MALICIOUS_ADDR=""
MALICIOUS_SALT=""

# Support both plain array and {data:[...]} response formats
PREREGISTERED_LIST=$(echo "$PREREGISTERED_RESPONSE" | jq 'if type=="array" then . else (.data // []) end' 2>/dev/null || echo "[]")
PREREGISTERED_COUNT=$(echo "$PREREGISTERED_LIST" | jq 'length' 2>/dev/null || echo "0")

for i in $(seq 0 $((PREREGISTERED_COUNT - 1))); do
    ADDR=$(echo "$PREREGISTERED_LIST" | jq -r ".[$i].address")
    SALT=$(echo "$PREREGISTERED_LIST" | jq -r ".[$i].salt")
    ADDR_FACTORY=$(echo "$PREREGISTERED_LIST" | jq -r ".[$i].factory" | tr '[:upper:]' '[:lower:]')

    if [ "$ADDR_FACTORY" != "$FACTORY_LOWER" ]; then
        continue
    fi

    # Check code size using Anvil directly (read-only)
    CODE_SIZE=$(cast codesize "$ADDR" --rpc-url "$ANVIL_RPC_URL" 2>/dev/null || echo "0")
    if [ "$CODE_SIZE" = "0" ]; then
        MALICIOUS_ADDR="$ADDR"
        MALICIOUS_SALT="$SALT"
        break
    fi
done

if [ -z "$MALICIOUS_ADDR" ]; then
    # No preregistered addresses — compute one locally (works when runtime tracing is enabled)
    print_info "No preregistered addresses found — computing address locally (runtime tracing mode)"
    TIMESTAMP=$(date +%s)
    SALT_PREFIX="malicious-box-$TIMESTAMP"
    ORG_HEX=$(printf '%s' "$ORG_ID" | xxd -p | tr -d '\n')
    PREFIX_HEX=$(printf '%s' "$SALT_PREFIX" | xxd -p | tr -d '\n')
    MALICIOUS_SALT=$(cast keccak "0x${ORG_HEX}${PREFIX_HEX}" 2>/dev/null)
    MALICIOUS_ADDR=$(cast call "$CREATE3_FACTORY" "getDeployed(bytes32)(address)" "$MALICIOUS_SALT" --rpc-url "$ANVIL_RPC_URL" 2>/dev/null | tr '[:upper:]' '[:lower:]')
    if [ -z "$MALICIOUS_ADDR" ]; then
        print_error "Failed to compute target address for malicious contract"
        exit 1
    fi
fi

print_success "Found target address for malicious contract"
print_value "Target Address" "$MALICIOUS_ADDR"
print_value "Salt" "${MALICIOUS_SALT:0:20}..."

# =============================================================================
# Step 3: Build MaliciousBox contract
# =============================================================================

print_step "Step 3: Building MaliciousBox Contract"

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

# Initialize git repo
print_substep "Initializing git repository..."
git init --quiet
git config user.email "demo@example.com"
git config user.name "Demo"
git add -A
git commit -m "Initial" --quiet

# Install dependencies
print_substep "Installing dependencies..."
# Remove any copied local artifacts (these are gitignored but cp -r copies them)
rm -rf lib out cache
mkdir -p lib
git clone --quiet --depth 1 https://github.com/OpenZeppelin/openzeppelin-contracts-upgradeable.git lib/openzeppelin-contracts-upgradeable || { print_error "Failed to clone openzeppelin-contracts-upgradeable"; exit 1; }
git clone --quiet --depth 1 https://github.com/OpenZeppelin/openzeppelin-contracts.git lib/openzeppelin-contracts || { print_error "Failed to clone openzeppelin-contracts"; exit 1; }
git clone --quiet --depth 1 https://github.com/foundry-rs/forge-std.git lib/forge-std || { print_error "Failed to clone forge-std"; exit 1; }
print_success "Dependencies installed"

print_substep "Compiling MaliciousBox..."
forge build --quiet

print_success "Contract compiled"

MALICIOUS_BYTECODE=$(forge inspect MaliciousBox bytecode)
print_value "Bytecode size" "$(echo -n "$MALICIOUS_BYTECODE" | wc -c | tr -d ' ') chars"

# =============================================================================
# Step 4: Show what the contract does
# =============================================================================

print_step "Step 4: Understanding the Malicious Contract"

echo -e "  ${WHITE}The MaliciousBox contract contains:${NC}"
echo ""
echo -e "  ${CYAN}┌─────────────────────────────────────────────────────────────────┐${NC}"
echo -e "  ${CYAN}│${NC} ${YELLOW}Hardcoded external address:${NC}"
echo -e "  ${CYAN}│${NC}   0xDeaDbeefdEAdbeefdEadbEEFdeadbeEFdEaDbeeF"
echo -e "  ${CYAN}│${NC}"
echo -e "  ${CYAN}│${NC} ${YELLOW}In constructor:${NC}"
echo -e "  ${CYAN}│${NC}   (bool success, ) = EXTERNAL_TARGET.call(\"\");"
echo -e "  ${CYAN}│${NC}   externalCallMade = success;"
echo -e "  ${CYAN}│${NC}"
echo -e "  ${CYAN}│${NC} ${YELLOW}Also has callExternal() function for testing${NC}"
echo -e "  ${CYAN}│${NC}"
echo -e "  ${CYAN}│${NC} ${RED}External address is NOT preregistered!${NC}"
echo -e "  ${CYAN}└─────────────────────────────────────────────────────────────────┘${NC}"
echo ""

print_warning "The Open Privacy Suite should detect the external call and BLOCK the deployment"

# =============================================================================
# Step 5: Attempt deployment through proxy (should be BLOCKED)
# =============================================================================

print_step "Step 5: Attempting Deployment Through Proxy (Expected to be BLOCKED)"

print_substep "Deploying MaliciousBox via CREATE3..."
print_info "Target address: $MALICIOUS_ADDR"
print_info "External call target: 0xDeaDbeefdEAdbeefdEadbEEFdeadbeEFdEaDbeeF"
print_info "This address is NOT owned by or preregistered for the org!"

DEPLOY_CALLDATA=$(cast calldata "deploy(bytes32,bytes)" "$MALICIOUS_SALT" "$MALICIOUS_BYTECODE")

echo ""
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
    "gas": "0x200000",
    "nonce": "$NONCE"
}]
EOF
)

# Send transaction through the proxy (this should be BLOCKED by bytecode validation)
DEPLOY_RESULT=$(rpc_call "eth_sendTransaction" "$TX_PARAMS")

echo ""
print_substep "Proxy response:"
echo "$DEPLOY_RESULT" | jq . 2>/dev/null || echo "$DEPLOY_RESULT"
echo ""

# Check if the deployment was blocked
# Handle both .error as string and .error.message as object
ERROR_MSG=$(echo "$DEPLOY_RESULT" | jq -r 'if .error then (if .error | type == "object" then .error.message else .error end) else empty end')
TX_HASH=$(echo "$DEPLOY_RESULT" | jq -r '.result // empty')

if [ -n "$ERROR_MSG" ]; then
    # Deployment was blocked!
    echo ""
    echo -e "  ${GREEN}┌─────────────────────────────────────────────────────────────────┐${NC}"
    echo -e "  ${GREEN}│${NC}                    ${BOLD}${GREEN}DEPLOYMENT BLOCKED!${NC}                         ${GREEN}│${NC}"
    echo -e "  ${GREEN}└─────────────────────────────────────────────────────────────────┘${NC}"
    echo ""
    print_success "The Open Privacy Suite correctly blocked the deployment!"
    echo ""
    echo -e "  ${WHITE}Reason:${NC}"
    echo -e "  │ $ERROR_MSG"
    echo ""

    if echo "$ERROR_MSG" | grep -qi "deadbeef\|not allowed\|bytecode\|call target"; then
        print_success "Error message correctly identifies the unauthorized external call"
    fi

elif [ -n "$TX_HASH" ] && [ "$TX_HASH" != "null" ]; then
    # Transaction was sent - this is unexpected!
    echo ""
    echo -e "  ${RED}┌─────────────────────────────────────────────────────────────────┐${NC}"
    echo -e "  ${RED}│${NC}         ${BOLD}${RED}UNEXPECTED: DEPLOYMENT WAS NOT BLOCKED!${NC}               ${RED}│${NC}"
    echo -e "  ${RED}└─────────────────────────────────────────────────────────────────┘${NC}"
    echo ""
    print_error "The proxy should have blocked this deployment!"
    print_value "Transaction" "$TX_HASH"

    # Check if contract was actually deployed
    sleep 2  # Wait for block
    CODE_SIZE=$(cast codesize "$MALICIOUS_ADDR" --rpc-url "$ANVIL_RPC_URL" 2>/dev/null || echo "0")

    if [ "$CODE_SIZE" = "0" ]; then
        print_warning "Transaction was sent but deployment failed (code size = 0)"
    else
        print_error "Contract was deployed at $MALICIOUS_ADDR (code size: $CODE_SIZE bytes)"
        print_error "This is a SECURITY ISSUE - bytecode validation failed!"
    fi
else
    echo ""
    echo -e "  ${YELLOW}┌─────────────────────────────────────────────────────────────────┐${NC}"
    echo -e "  ${YELLOW}│${NC}              ${BOLD}${YELLOW}UNEXPECTED RESPONSE${NC}                              ${YELLOW}│${NC}"
    echo -e "  ${YELLOW}└─────────────────────────────────────────────────────────────────┘${NC}"
    echo ""
    print_warning "Could not parse proxy response"
    echo "$DEPLOY_RESULT"
fi

# =============================================================================
# Summary
# =============================================================================

print_header "Demo Complete"

echo -e "${WHITE}Summary:${NC}"
echo -e "${CYAN}┌─────────────────────────────────────────────────────────────────────┐${NC}"
echo -e "${CYAN}│${NC}  ${YELLOW}Contract:${NC}            MaliciousBox"
echo -e "${CYAN}│${NC}  ${YELLOW}External Target:${NC}     0xDeaDbeefdEAdbeefdEadbEEFdeadbeEFdEaDbeeF"
echo -e "${CYAN}│${NC}  ${YELLOW}Target Preregistered:${NC} ${RED}NO${NC}"
echo -e "${CYAN}├─────────────────────────────────────────────────────────────────────┤${NC}"
echo -e "${CYAN}│${NC}  ${GREEN}Deployment:${NC}          ${RED}BLOCKED${NC} (bytecode contains unauthorized CALL)"
echo -e "${CYAN}│${NC}  ${YELLOW}Reason:${NC}              External call to non-owned address detected"
echo -e "${CYAN}└─────────────────────────────────────────────────────────────────────┘${NC}"
echo ""
echo -e "${WHITE}Security Model - Bytecode Validation:${NC}"
echo -e "  ${CYAN}•${NC} Proxy analyzes bytecode BEFORE allowing deployment"
echo -e "  ${CYAN}•${NC} All CALL/DELEGATECALL targets are extracted from bytecode"
echo -e "  ${CYAN}•${NC} Each target must be: owned by org, preregistered, or a precompile"
echo -e "  ${CYAN}•${NC} Deployments with unauthorized external calls are ${RED}BLOCKED${NC}"
echo ""
echo -e "${WHITE}What IS protected:${NC}"
echo -e "  ${CYAN}•${NC} Users can only send transactions through the proxy RPC"
echo -e "  ${CYAN}•${NC} Factory deployments must target preregistered addresses"
echo -e "  ${CYAN}•${NC} Deployed bytecode cannot call unauthorized addresses"
echo -e "  ${CYAN}•${NC} CREATE/CREATE2 opcodes blocked (prevents nested deployments)"
echo -e "  ${CYAN}•${NC} Dynamic DELEGATECALL blocked (except for known proxy patterns)"
echo ""
echo -e "${WHITE}Note:${NC}"
echo -e "  ${CYAN}•${NC} This demo requires the Open Privacy Suite to be running"
echo -e "  ${CYAN}•${NC} Mock authentication must be enabled (dev mode)"
echo -e "  ${CYAN}•${NC} The org must have a CREATE3 factory configured"
echo ""
