#!/bin/bash

# =============================================================================
# Open Privacy Suite - Direct Anvil Deployment Demo (Baseline)
# =============================================================================
# This script demonstrates deployment directly to Anvil without Open Privacy Suite.
# Used as a baseline for comparison with the Open Privacy Suite workflow.
#
# Steps:
# 1. Start Anvil (or use existing instance)
# 2. Deploy DemoToken, LiquidityPool, SwapRouter contracts
# 3. Interact with them (mint tokens, add liquidity, swap)
# 4. Show success
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
# Configuration
# =============================================================================

print_header "Direct Anvil Deployment Demo (Baseline)"

print_step "Step 1: Checking Configuration"

# Environment variables with defaults
: "${ANVIL_URL:=http://localhost:8545}"
: "${PRIVATE_KEY:=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80}"

print_value "Anvil URL" "$ANVIL_URL"
print_value "Private Key" "${PRIVATE_KEY:0:10}..."

# Get deployer address from private key
DEPLOYER_ADDRESS=$(cast wallet address "$PRIVATE_KEY" 2>/dev/null)
print_value "Deployer Address" "$DEPLOYER_ADDRESS"

# Check Anvil is running
print_substep "Checking Anvil connection..."
CHAIN_ID=$(cast chain-id --rpc-url "$ANVIL_URL" 2>/dev/null || echo "")
if [ -z "$CHAIN_ID" ]; then
    print_error "Could not connect to Anvil at $ANVIL_URL"
    echo ""
    echo -e "  ${WHITE}Start Anvil with:${NC}"
    echo -e "  ${GREEN}anvil${NC}"
    echo ""
    exit 1
fi
print_success "Connected to Anvil (chainId: $CHAIN_ID)"

# Check deployer balance
BALANCE=$(cast balance "$DEPLOYER_ADDRESS" --rpc-url "$ANVIL_URL" 2>/dev/null)
print_value "Deployer Balance" "$BALANCE wei"

# =============================================================================
# Step 2: Build Contracts
# =============================================================================

print_step "Step 2: Building Contracts"

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

# Install dependencies using git clone directly
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

# Get bytecode for all contracts
DEMOTOKEN_BYTECODE=$(forge inspect DemoToken bytecode)
LIQUIDITYPOOL_BYTECODE=$(forge inspect LiquidityPool bytecode)
SWAPROUTER_BYTECODE=$(forge inspect SwapRouter bytecode)

print_value "DemoToken bytecode size" "$(echo -n "$DEMOTOKEN_BYTECODE" | wc -c | tr -d ' ') chars"
print_value "LiquidityPool bytecode size" "$(echo -n "$LIQUIDITYPOOL_BYTECODE" | wc -c | tr -d ' ') chars"
print_value "SwapRouter bytecode size" "$(echo -n "$SWAPROUTER_BYTECODE" | wc -c | tr -d ' ') chars"

# =============================================================================
# Step 3: Deploy Contracts Using CREATE2 (for address prediction)
# =============================================================================

print_step "Step 3: Deploying Contracts (Direct to Anvil)"

print_info "Note: Direct deployment uses regular CREATE opcode"
print_info "      Addresses are determined by nonce, not deterministically"
echo ""

# Helper function to deploy and extract address
# Usage: deploy_contract "path/to/Contract.sol:Contract" ["arg1 arg2 ..."]
deploy_contract() {
    local contract_path="$1"
    local constructor_args="$2"

    local result

    # Use non-JSON mode for more reliable parsing
    if [ -n "$constructor_args" ]; then
        # shellcheck disable=SC2086
        result=$(forge create "$contract_path" \
            --rpc-url "$ANVIL_URL" \
            --private-key "$PRIVATE_KEY" \
            --broadcast \
            --constructor-args $constructor_args 2>&1) || true
    else
        result=$(forge create "$contract_path" \
            --rpc-url "$ANVIL_URL" \
            --private-key "$PRIVATE_KEY" \
            --broadcast 2>&1) || true
    fi

    # Extract "Deployed to:" address from output
    local addr
    addr=$(echo "$result" | grep -o 'Deployed to: 0x[a-fA-F0-9]\{40\}' | sed 's/Deployed to: //' | head -1)

    if [ -z "$addr" ]; then
        print_error "Failed to deploy $contract_path"
        echo "  Output: $result" | head -5 >&2
        return 1
    fi

    echo "$addr"
}

# Deploy DemoToken Implementation
print_substep "Deploying DemoToken implementation..."
DEMOTOKEN_IMPL=$(deploy_contract "src/token/DemoToken.sol:DemoToken")
if [ -z "$DEMOTOKEN_IMPL" ]; then
    exit 1
fi
print_success "DemoToken impl: $DEMOTOKEN_IMPL"

# Deploy LiquidityPool Implementation
print_substep "Deploying LiquidityPool implementation..."
LIQUIDITYPOOL_IMPL=$(deploy_contract "src/pool/LiquidityPool.sol:LiquidityPool")
if [ -z "$LIQUIDITYPOOL_IMPL" ]; then
    exit 1
fi
print_success "LiquidityPool impl: $LIQUIDITYPOOL_IMPL"

# Deploy SwapRouter Implementation
print_substep "Deploying SwapRouter implementation..."
SWAPROUTER_IMPL=$(deploy_contract "src/router/SwapRouter.sol:SwapRouter")
if [ -z "$SWAPROUTER_IMPL" ]; then
    exit 1
fi
print_success "SwapRouter impl: $SWAPROUTER_IMPL"

# =============================================================================
# Step 4: Deploy Proxies and Initialize
# =============================================================================

print_step "Step 4: Deploying Proxies"

# Create proxy bytecode helper
cat > "$BUILD_DIR/src/DeployProxy.sol" << 'EOF'
// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

contract DeployableProxy is ERC1967Proxy {
    constructor(address implementation, bytes memory data) ERC1967Proxy(implementation, data) {}
}
EOF

forge build --quiet

# For circular dependencies with CREATE opcode, we predict future addresses
# using nonces. Then we can initialize each contract with the others' addresses
# during deployment.

PROXY_BYTECODE=$(forge inspect DeployableProxy bytecode)

print_substep "Computing future proxy addresses..."

# Get current nonce
CURRENT_NONCE=$(cast nonce "$DEPLOYER_ADDRESS" --rpc-url "$ANVIL_URL" 2>/dev/null)
print_value "Current nonce" "$CURRENT_NONCE"

# Compute addresses for the next 3 deployments
TOKEN_PROXY=$(cast compute-address "$DEPLOYER_ADDRESS" --nonce "$CURRENT_NONCE" --rpc-url "$ANVIL_URL" 2>/dev/null | grep -o '0x[a-fA-F0-9]\{40\}')
POOL_PROXY=$(cast compute-address "$DEPLOYER_ADDRESS" --nonce "$((CURRENT_NONCE + 1))" --rpc-url "$ANVIL_URL" 2>/dev/null | grep -o '0x[a-fA-F0-9]\{40\}')
ROUTER_PROXY=$(cast compute-address "$DEPLOYER_ADDRESS" --nonce "$((CURRENT_NONCE + 2))" --rpc-url "$ANVIL_URL" 2>/dev/null | grep -o '0x[a-fA-F0-9]\{40\}')

print_value "Predicted Token Proxy" "$TOKEN_PROXY"
print_value "Predicted Pool Proxy" "$POOL_PROXY"
print_value "Predicted Router Proxy" "$ROUTER_PROXY"

# Helper function to deploy proxy using cast send (avoids forge create argument parsing issues)
deploy_proxy() {
    local impl_addr="$1"
    local init_data="$2"

    # Get the proxy creation bytecode
    local proxy_bytecode
    proxy_bytecode=$(forge inspect DeployableProxy bytecode)

    # Encode constructor args: (address implementation, bytes memory _data)
    # Cast abi-encode handles the bytes parameter correctly
    local encoded_args
    encoded_args=$(cast abi-encode "constructor(address,bytes)" "$impl_addr" "$init_data")

    # Remove 0x prefix from encoded_args for concatenation
    local args_no_prefix="${encoded_args#0x}"

    # Full deployment data = bytecode + encoded constructor args
    local deploy_data="${proxy_bytecode}${args_no_prefix}"

    # Deploy via cast send --create (options must come before --create)
    local result
    result=$(cast send \
        --rpc-url "$ANVIL_URL" \
        --private-key "$PRIVATE_KEY" \
        --create "$deploy_data" 2>&1)

    # Extract contract address from result
    local addr
    addr=$(echo "$result" | grep -o 'contractAddress[[:space:]]*0x[a-fA-F0-9]\{40\}' | grep -o '0x[a-fA-F0-9]\{40\}' | head -1)
    if [ -z "$addr" ]; then
        # Try alternate format
        addr=$(echo "$result" | grep -oE '"contractAddress":\s*"0x[a-fA-F0-9]{40}"' | grep -o '0x[a-fA-F0-9]\{40\}' | head -1)
    fi
    if [ -z "$addr" ]; then
        echo "DEPLOY_ERROR: $result" >&2
        return 1
    fi
    echo "$addr"
}

# Deploy proxies WITH initialization data, using the predicted addresses
print_substep "Deploying DemoToken proxy..."
TOKEN_INIT_DATA=$(cast calldata "initialize(address,address)" "$DEPLOYER_ADDRESS" "$POOL_PROXY")
TOKEN_PROXY_ACTUAL=$(deploy_proxy "$DEMOTOKEN_IMPL" "$TOKEN_INIT_DATA")
if [ -z "$TOKEN_PROXY_ACTUAL" ] || [[ "$TOKEN_PROXY_ACTUAL" == "DEPLOY_ERROR:"* ]]; then
    print_error "Failed to deploy DemoToken proxy"
    echo "$TOKEN_PROXY_ACTUAL"
    exit 1
fi
print_success "DemoToken proxy: $TOKEN_PROXY_ACTUAL"

print_substep "Deploying LiquidityPool proxy..."
POOL_INIT_DATA=$(cast calldata "initialize(address,address)" "$DEPLOYER_ADDRESS" "$TOKEN_PROXY")
POOL_PROXY_ACTUAL=$(deploy_proxy "$LIQUIDITYPOOL_IMPL" "$POOL_INIT_DATA")
if [ -z "$POOL_PROXY_ACTUAL" ] || [[ "$POOL_PROXY_ACTUAL" == "DEPLOY_ERROR:"* ]]; then
    print_error "Failed to deploy LiquidityPool proxy"
    exit 1
fi
print_success "LiquidityPool proxy: $POOL_PROXY_ACTUAL"

print_substep "Deploying SwapRouter proxy..."
ROUTER_INIT_DATA=$(cast calldata "initialize(address,address,address)" "$DEPLOYER_ADDRESS" "$POOL_PROXY" "$TOKEN_PROXY")
ROUTER_PROXY_ACTUAL=$(deploy_proxy "$SWAPROUTER_IMPL" "$ROUTER_INIT_DATA")
if [ -z "$ROUTER_PROXY_ACTUAL" ] || [[ "$ROUTER_PROXY_ACTUAL" == "DEPLOY_ERROR:"* ]]; then
    print_error "Failed to deploy SwapRouter proxy"
    exit 1
fi
print_success "SwapRouter proxy: $ROUTER_PROXY_ACTUAL"

# Verify addresses match predictions
print_substep "Verifying address predictions..."
if [ "$TOKEN_PROXY" = "$TOKEN_PROXY_ACTUAL" ]; then
    print_success "Token proxy address matched prediction"
else
    print_info "Token proxy: predicted $TOKEN_PROXY, actual $TOKEN_PROXY_ACTUAL"
fi
if [ "$POOL_PROXY" = "$POOL_PROXY_ACTUAL" ]; then
    print_success "Pool proxy address matched prediction"
else
    print_info "Pool proxy: predicted $POOL_PROXY, actual $POOL_PROXY_ACTUAL"
fi
if [ "$ROUTER_PROXY" = "$ROUTER_PROXY_ACTUAL" ]; then
    print_success "Router proxy address matched prediction"
else
    print_info "Router proxy: predicted $ROUTER_PROXY, actual $ROUTER_PROXY_ACTUAL"
fi

# Use actual addresses for the rest of the script
TOKEN_PROXY="$TOKEN_PROXY_ACTUAL"
POOL_PROXY="$POOL_PROXY_ACTUAL"
ROUTER_PROXY="$ROUTER_PROXY_ACTUAL"

# =============================================================================
# Step 6: Verify Deployment
# =============================================================================

print_step "Step 6: Verifying Deployment"

# Check versions
print_substep "Checking contract versions..."
TOKEN_VERSION=$(cast call "$TOKEN_PROXY" "version()(string)" --rpc-url "$ANVIL_URL" 2>/dev/null)
POOL_VERSION=$(cast call "$POOL_PROXY" "version()(string)" --rpc-url "$ANVIL_URL" 2>/dev/null)
ROUTER_VERSION=$(cast call "$ROUTER_PROXY" "version()(string)" --rpc-url "$ANVIL_URL" 2>/dev/null)

print_contract_call "$TOKEN_PROXY" "version()" "$TOKEN_VERSION"
print_contract_call "$POOL_PROXY" "version()" "$POOL_VERSION"
print_contract_call "$ROUTER_PROXY" "version()" "$ROUTER_VERSION"

# Check cross-references
print_substep "Verifying cross-references..."
TOKEN_POOL=$(cast call "$TOKEN_PROXY" "pool()(address)" --rpc-url "$ANVIL_URL" 2>/dev/null)
POOL_TOKEN=$(cast call "$POOL_PROXY" "token()(address)" --rpc-url "$ANVIL_URL" 2>/dev/null)
ROUTER_POOL=$(cast call "$ROUTER_PROXY" "pool()(address)" --rpc-url "$ANVIL_URL" 2>/dev/null)
ROUTER_TOKEN=$(cast call "$ROUTER_PROXY" "token()(address)" --rpc-url "$ANVIL_URL" 2>/dev/null)

print_value "Token.pool" "$TOKEN_POOL"
print_value "Pool.token" "$POOL_TOKEN"
print_value "Router.pool" "$ROUTER_POOL"
print_value "Router.token" "$ROUTER_TOKEN"

# =============================================================================
# Step 7: Interact with Contracts
# =============================================================================

print_step "Step 7: Interacting with Contracts"

# Mint some tokens
MINT_AMOUNT="1000000000000000000000" # 1000 tokens (18 decimals)
print_substep "Minting 1000 DEMO tokens..."
cast send "$TOKEN_PROXY" "mint(address,uint256)" "$DEPLOYER_ADDRESS" "$MINT_AMOUNT" \
    --rpc-url "$ANVIL_URL" \
    --private-key "$PRIVATE_KEY" \
    --json > /dev/null 2>&1
print_success "Minted 1000 DEMO tokens"

# Check balance
TOKEN_BALANCE=$(cast call "$TOKEN_PROXY" "balanceOf(address)(uint256)" "$DEPLOYER_ADDRESS" --rpc-url "$ANVIL_URL" 2>/dev/null)
print_value "Token Balance" "$TOKEN_BALANCE (wei)"

# Approve pool to spend tokens
print_substep "Approving pool to spend tokens..."
cast send "$TOKEN_PROXY" "approve(address,uint256)" "$POOL_PROXY" "$MINT_AMOUNT" \
    --rpc-url "$ANVIL_URL" \
    --private-key "$PRIVATE_KEY" \
    --json > /dev/null 2>&1
print_success "Pool approved to spend tokens"

# Add liquidity
LIQUIDITY_TOKENS="500000000000000000000" # 500 tokens
LIQUIDITY_ETH="1000000000000000000" # 1 ETH
print_substep "Adding liquidity (500 DEMO + 1 ETH)..."
cast send "$POOL_PROXY" "addLiquidity(uint256)" "$LIQUIDITY_TOKENS" \
    --value "$LIQUIDITY_ETH" \
    --rpc-url "$ANVIL_URL" \
    --private-key "$PRIVATE_KEY" \
    --json > /dev/null 2>&1
print_success "Liquidity added"

# Check pool reserves
TOKEN_RESERVE=$(cast call "$POOL_PROXY" "tokenReserve()(uint256)" --rpc-url "$ANVIL_URL" 2>/dev/null)
ETH_RESERVE=$(cast call "$POOL_PROXY" "ethReserve()(uint256)" --rpc-url "$ANVIL_URL" 2>/dev/null)
print_value "Token Reserve" "$TOKEN_RESERVE"
print_value "ETH Reserve" "$ETH_RESERVE"

# Approve router to spend tokens
print_substep "Approving router to spend tokens..."
cast send "$TOKEN_PROXY" "approve(address,uint256)" "$ROUTER_PROXY" "$MINT_AMOUNT" \
    --rpc-url "$ANVIL_URL" \
    --private-key "$PRIVATE_KEY" \
    --json > /dev/null 2>&1
print_success "Router approved to spend tokens"

# Execute a swap through the router
SWAP_AMOUNT="100000000000000000000" # 100 tokens
print_substep "Swapping 100 DEMO for ETH through router..."
SWAP_RESULT=$(cast send "$ROUTER_PROXY" "swapExactTokensForEth(uint256,uint256)" "$SWAP_AMOUNT" "0" \
    --rpc-url "$ANVIL_URL" \
    --private-key "$PRIVATE_KEY" \
    --json 2>&1) || true
SWAP_TX=$(echo "$SWAP_RESULT" | jq -r '.transactionHash // empty' 2>/dev/null)
if [ -z "$SWAP_TX" ] || [ "$SWAP_TX" = "null" ]; then
    # Fallback: try to extract from non-JSON output
    SWAP_TX=$(echo "$SWAP_RESULT" | grep -o 'transactionHash.*0x[a-fA-F0-9]\{64\}' | grep -o '0x[a-fA-F0-9]\{64\}')
fi
print_success "Swap executed"
print_value "Transaction" "$SWAP_TX"

# Check new reserves
TOKEN_RESERVE_AFTER=$(cast call "$POOL_PROXY" "tokenReserve()(uint256)" --rpc-url "$ANVIL_URL" 2>/dev/null)
ETH_RESERVE_AFTER=$(cast call "$POOL_PROXY" "ethReserve()(uint256)" --rpc-url "$ANVIL_URL" 2>/dev/null)
print_value "Token Reserve After" "$TOKEN_RESERVE_AFTER"
print_value "ETH Reserve After" "$ETH_RESERVE_AFTER"

# =============================================================================
# Summary
# =============================================================================

print_header "Demo Complete!"

echo -e "${WHITE}Deployed Contracts (Direct to Anvil):${NC}"
echo -e "${CYAN}┌─────────────────────────────────────────────────────────────────────┐${NC}"
echo -e "${CYAN}│${NC}  ${YELLOW}DemoToken Proxy:${NC}      $TOKEN_PROXY"
echo -e "${CYAN}│${NC}  ${YELLOW}LiquidityPool Proxy:${NC}  $POOL_PROXY"
echo -e "${CYAN}│${NC}  ${YELLOW}SwapRouter Proxy:${NC}     $ROUTER_PROXY"
echo -e "${CYAN}├─────────────────────────────────────────────────────────────────────┤${NC}"
echo -e "${CYAN}│${NC}  ${YELLOW}DemoToken Impl:${NC}       $DEMOTOKEN_IMPL"
echo -e "${CYAN}│${NC}  ${YELLOW}LiquidityPool Impl:${NC}   $LIQUIDITYPOOL_IMPL"
echo -e "${CYAN}│${NC}  ${YELLOW}SwapRouter Impl:${NC}      $SWAPROUTER_IMPL"
echo -e "${CYAN}└─────────────────────────────────────────────────────────────────────┘${NC}"

echo ""
echo -e "${GREEN}All operations completed successfully!${NC}"
echo ""
echo -e "${WHITE}Key Points (Baseline):${NC}"
echo -e "  ${CYAN}1.${NC} Direct deployment uses CREATE opcode (nonce-based addresses)"
echo -e "  ${CYAN}2.${NC} No address preregistration or permission checks"
echo -e "  ${CYAN}3.${NC} Circular dependencies handled by delayed initialization"
echo -e "  ${CYAN}4.${NC} Anyone with ETH can deploy (no RBAC)"
echo ""
echo -e "${WHITE}Compare with:${NC}"
echo -e "  ${GREEN}./demo-privacy-proxy.sh${NC}     - Same flow through Open Privacy Suite with RBAC"
echo -e "  ${GREEN}./demo-defi-deployment.sh${NC}   - CREATE3 deterministic deployment"
echo ""
