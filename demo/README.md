# Open Privacy Suite Demo Scripts

Demo scripts showcasing contract deployment and RBAC features through the Open Privacy Suite.

## Deployment Modes

The proxy supports two deployment approaches:

| Mode | How It Works | Address Known Before Deploy? | Use Case |
|------|-------------|------------------------------|----------|
| **Regular CREATE** | Deploy via `eth_sendRawTransaction`, runtime-traced by proxy | No | Simple deployments, rapid prototyping |
| **CREATE3** | Preregister deterministic addresses, deploy via factory | Yes | Cross-chain consistency, admin/deployer separation |

Both modes require the `deploy` claim. Runtime tracing (`debug_traceCall`) validates all call targets for cross-org isolation.

## Demo Scripts Overview

| Script | Description | Auth Mode |
|--------|-------------|-----------|
| `demo-anvil-direct.sh` | Baseline deployment directly to Anvil (no proxy) | None |
| `demo-prod-deployment.sh` | **Production-style**: deploy with real JWT via `forge create` | JWT (Privado ID or mock) |
| `demo-privacy-proxy.sh` | Full CREATE3 workflow with preregistration | Mock auth |
| `demo-defi-deployment.sh` | CREATE3 deterministic DeFi deployment | Mock auth |
| `demo-upgrade.sh` | UUPS proxy upgrade demonstration | Mock auth |
| `demo-proxy-upgrade.sh` | Proxy upgrade with preregistered addresses | Mock auth |
| `demo-blocked-deployment.sh` | RBAC blocking unauthorized deploys | Mock auth |
| `demo-cross-org-attack.sh` | Cross-org isolation enforcement | Mock auth |

## Prerequisites

1. **Foundry** - Install from https://getfoundry.sh
2. **jq** - For JSON parsing
3. **curl** - For API calls
4. **Open Privacy Suite** running (`docker-compose up -d`)

Anvil must be started with `--steps-tracing` for runtime tracing support (the docker-compose files handle this automatically).

## Quick Start

### Production-style deployment (recommended starting point)

```bash
# 1. Start the proxy
docker-compose up -d

# 2. Authenticate via web UI (http://localhost:5173) and copy the JWT
#    Or use mock auth to get a token

# 3. Set environment and run
export ETH_RPC_HEADERS="Authorization: Bearer <your-jwt>"
export PRIVATE_KEY="0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
export ORG_ID="<your-org-id>"   # Required if user belongs to multiple orgs
./demo-prod-deployment.sh
```

### Other demos (use mock auth, self-contained)

```bash
./demo-privacy-proxy.sh       # Full CREATE3 flow
./demo-cross-org-attack.sh    # See cross-org isolation in action
./demo-blocked-deployment.sh  # See RBAC deny unauthorized deploys
```

## Script Details

### demo-prod-deployment.sh (Production-Style)

**Purpose:** Demonstrates how a real user deploys contracts through the proxy using their JWT token and private key — the closest to a production workflow.

**What it does:**
1. Verifies connection to proxy using the JWT
2. Auto-detects org (or prompts if user has multiple orgs)
3. Falls back to admin API setup if user has no permissions yet
4. Builds and deploys SimpleDemoToken, SimpleLiquidityPool, SimpleSwapRouter via `forge create` (regular CREATE)
5. Registers contracts to the organization and uploads ABIs
6. Initializes contracts and verifies cross-references
7. Tests contract interaction (mint + balance check)

**Key Points:**
- Uses regular CREATE deployment (not CREATE3) — simpler, no preregistration needed
- Deploy claim is sufficient — no explicit contract grants needed for deployers
- Works with both real Privado ID JWTs and mock auth tokens
- Multi-org users must set `ORG_ID`

---

### demo-anvil-direct.sh (Baseline)

**Purpose:** Baseline deployment directly to Anvil without RBAC — verifies contract logic works correctly.

**What it does:**
1. Compiles DemoToken, LiquidityPool, and SwapRouter contracts
2. Deploys implementations and UUPS proxies
3. Verifies circular references (Token <> Pool <> Router)
4. Tests interactions: mint, add liquidity, swap

---

### demo-privacy-proxy.sh (Full CREATE3 Workflow)

**Purpose:** Demonstrates the complete CREATE3 deployment flow with preregistration.

**What it does:**
1. Authenticates user via mock token
2. Sets up organization, group with deploy claim, and user permissions
3. Deploys/configures CREATE3 factory
4. Preregisters deterministic contract addresses
5. Deploys contracts through proxy to preregistered addresses
6. Verifies deployment and tests interactions

**When to use CREATE3:** When you need deterministic addresses across chains, or want admin/deployer separation (admin preregisters WHERE, deployer deploys WHAT).

---

### demo-defi-deployment.sh (CREATE3 Deterministic)

**Purpose:** Showcases CREATE3 deterministic deployment for DeFi contracts with circular dependencies.

**What it does:**
1. Computes addresses deterministically using CREATE3 (factory + salt)
2. Preregisters all addresses before any deployment
3. Deploys Token, Pool, Router with known addresses
4. Demonstrates that addresses are independent of bytecode

**Key Benefit:** Same addresses across all EVM chains when using same factory and salts.

---

### demo-upgrade.sh (UUPS Upgrade Flow)

**Purpose:** Demonstrates upgrading UUPS proxies from V1 to V2 implementations.

**What it does:**
1. Deploys V1 implementations and proxies
2. Interacts with V1 (version returns "1.0.0")
3. Deploys V2 implementations with new features
4. Upgrades proxies to V2
5. Verifies state preservation and new features

---

### demo-proxy-upgrade.sh (Preregistered Upgrade)

**Purpose:** Shows the admin/deployer separation for contract upgrades using preregistered addresses.

**Security Model:**
- **Org Admin**: Preregisters addresses (controls WHERE code can be deployed)
- **Deployer**: Deploys to preregistered addresses only

---

### demo-blocked-deployment.sh (RBAC Enforcement)

**Purpose:** Demonstrates RBAC blocking unauthorized deployments.

**What it shows:**
- Users without deploy claim cannot deploy contracts
- Write-only users are denied deployment
- Proper error messages for missing permissions

---

### demo-cross-org-attack.sh (Cross-Org Isolation)

**Purpose:** Demonstrates that the proxy prevents cross-organization access.

**What it shows:**
- Sets up two organizations with separate users and contracts
- User in Org A cannot access Org B's contracts
- Runtime tracing catches cross-org calls even through internal contract interactions

## Environment Variables

```bash
# For demo-prod-deployment.sh
export ETH_RPC_HEADERS="Authorization: Bearer <jwt>"  # From web UI "Copy for Foundry" button
export PRIVATE_KEY="0xac0974..."                       # Deployer private key
export ORG_ID="<uuid>"                                 # Required for multi-org users

# For other demo scripts (optional, defaults shown)
export ADMIN_API_URL="http://localhost:8080/api"
export PROXY_RPC_URL="http://localhost:8080"
export ANVIL_URL="http://localhost:8545"
export PRIVATE_KEY="0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
# Address: 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266
```

## RBAC Permission Model

```
Claims hierarchy:
  admin   -> full bypass (implies deploy + upgrade)
  deploy  -> may deploy new contracts
  upgrade -> may upgrade proxy contracts

Access rules:
  Method access           -> per-group method allowlist (allowed_methods)
  Contract visibility     -> a contract grant linking the group to the contract
  Unregistered contracts  -> deploy/admin users only
  Registered (other org)  -> always denied (cross-org isolation)
```

## Troubleshooting

### "Could not connect to Anvil"
```bash
docker-compose up -d   # Starts Anvil with --steps-tracing
```

### "missing required deploy claim"
The user's group needs the `deploy` claim (set on the group's access claims).

### "User belongs to N organizations - ORG_ID required"
Multi-org users must specify which org to use:
```bash
export ORG_ID="<org-id-with-deploy-permissions>"
```

### "access denied: missing required deploy claim for contract deployment"
The user has RPC access but lacks the `deploy` claim. Check group access configuration in the admin UI.

### "target address is not preregistered"
Only applies to CREATE3 factory deployments. Use `demo-prod-deployment.sh` for regular CREATE deploys that don't require preregistration.
