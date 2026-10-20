# Open Privacy Suite MCP Server

Open Privacy Suite includes an [MCP](https://modelcontextprotocol.io/) (Model Context Protocol) server that exposes the full admin API as 94 tools over stdio transport. It covers RBAC, compliance, disclosure, explorer, and operational management.

## Setup

### Claude Code

Copy `.mcp.json.example` in the repo root to `.mcp.json` (gitignored) and
fill in `PRIVACY_ADMIN_TOKEN` — for the quickstart stack it is the
`ADMIN_API_TOKEN` value in `.env.quickstart`. Open the project in Claude
Code and the tools are available. The proxy must be running
(`make quickstart` or `docker-compose up -d`; backend on `localhost:8080`
by default).

`PRIVACY_ADMIN_TOKEN` must equal the backend's `ADMIN_API_TOKEN` (the
quickstart generates and persists one; for a hand-rolled stack set both to
the same value, e.g. via `ADMIN_API_TOKEN` in a root `.env` file). If the
backend has no admin token configured, admin-backed tools return 401.

### Manual

The MCP server is its own Go module in `mcp/`, so run it with `-C` (or from
inside the directory) — `go run ./mcp` from the repo root does not work:

```bash
PRIVACY_URL=http://localhost:8080 \
PRIVACY_ADMIN_TOKEN=your-admin-token \
go run -C mcp .
```

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `PRIVACY_URL` | `http://localhost:8080` | Open Privacy Suite base URL (http/https only) |
| `PRIVACY_ADMIN_TOKEN` | _(empty)_ | Admin API token (sent as `X-Admin-Token` header) |

## Viewing data as a specific user (`viewer_jwt` / `jwt_token`)

The admin token authorizes *management* operations, but privacy-filtered
reads (all `explorer_*` tools, `viewable_addresses`) resolve the viewer
identity **only from a validated user JWT** — never from the admin token or
a wallet address (that would be a deanonymization oracle). Without a JWT
these tools return the anonymous view, which is mostly empty by design.

Pass a user's JWT as `viewer_jwt` to render that user's view — this is how
you demo "what does Bob see vs what does Alice see". The quickstart seed
(`make quickstart`) prints ready-to-use JWTs for every demo persona and
stores them in `.quickstart-demo.json`. `test_request` accepts the same
token as `jwt_token` to answer "would this user be allowed to do X?".

## Tools

### System (4 tools)

#### `health`
Check if the Open Privacy Suite is reachable.

#### `status`
Get proxy state, node connectivity, and security config.

#### `test_request`
Send a test JSON-RPC request through the full proxy pipeline (RBAC, compliance, filtering).

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `method` | string | Yes | JSON-RPC method (e.g. `eth_call`) |
| `params` | any | No | JSON-RPC params |
| `jwt_token` | string | No | User JWT to test as (identity from the validated token; omitted = the synthetic `test:dashboard` identity) |
| `org_id` | string | No | Org context (needed for multi-org users when the request has no target contract) |

#### `eth_address_collisions`
Check for ETH address linking collisions (same address linked to multiple DIDs).

### Organizations (5 tools)

#### `list_orgs`
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `limit` | number | No | Max entries (default 50) |
| `offset` | number | No | Pagination offset |

#### `get_org`
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `org_id` | string | Yes | Organization UUID |

#### `create_org`
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `slug` | string | Yes | URL-friendly identifier |
| `name` | string | Yes | Display name |
| `settings` | object | No | Settings map |

#### `update_org`
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `org_id` | string | Yes | Organization UUID |
| `slug` | string | No | New slug |
| `name` | string | No | New name |
| `settings` | object | No | New settings |

#### `delete_org`
**Destructive — requires two-step confirmation.**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `org_id` | string | Yes | Organization UUID |
| `confirm_token` | string | No | Token from first call |

### Groups (9 tools)

#### `list_groups`
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `org_id` | string | Yes | Organization UUID |
| `limit` | number | No | Max entries (default 50) |
| `offset` | number | No | Pagination offset |

#### `get_group`
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `org_id` | string | Yes | Organization UUID |
| `group_id` | string | Yes | Group UUID |

#### `create_group`
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `org_id` | string | Yes | Organization UUID |
| `slug` | string | Yes | URL-friendly identifier |
| `name` | string | Yes | Display name |
| `description` | string | No | Group description |
| `parent_id` | string | No | Parent group UUID (for nesting) |
| `is_org_admin` | boolean | No | Org admin privileges |

#### `update_group`
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `org_id` | string | Yes | Organization UUID |
| `group_id` | string | Yes | Group UUID |
| `name` | string | No | New name |
| `description` | string | No | New description |
| `is_org_admin` | boolean | No | Set org admin status |

#### `delete_group`
**Destructive — requires two-step confirmation.**

#### `get_group_access`
Get a group's allowed RPC methods, claims, and rate limits.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `org_id` | string | Yes | Organization UUID |
| `group_id` | string | Yes | Group UUID |

#### `set_group_access`
Set allowed methods, claims, and rate limits. Claims auto-expand (admin includes all).

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `org_id` | string | Yes | Organization UUID |
| `group_id` | string | Yes | Group UUID |
| `allowed_methods` | string[] | Yes | RPC methods (e.g. `eth_call`, `eth_sendTransaction`) |
| `claims` | string[] | Yes | Permission claims (`admin`, `upgrade`, `deploy`) |
| `rate_limit_rps` | number | No | Requests per second |
| `rate_limit_daily` | number | No | Daily request limit |

#### `batch_delete_groups_preview`
Preview what would be affected by a batch group deletion.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `org_id` | string | Yes | Organization UUID |
| `group_ids` | string[] | Yes | Group UUIDs to delete |

#### `batch_delete_groups`
**Destructive — requires two-step confirmation.**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `org_id` | string | Yes | Organization UUID |
| `group_ids` | string[] | Yes | Group UUIDs to delete |

### Users (11 tools)

#### `list_users`
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `limit` | number | No | Max entries (default 50) |
| `offset` | number | No | Pagination offset |
| `org_id` | string | No | Filter by organization |
| `search` | string | No | Search by DID or ETH address |

#### `get_user`
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `user_id` | string | Yes | User UUID |

#### `resolve_user`
Find a user by DID or ETH address.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `query` | string | Yes | DID, ETH address, or partial match |

#### `update_user`
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `user_id` | string | Yes | User UUID |
| `kyc` | boolean | No | Set KYC status |
| `banned` | boolean | No | Ban/unban (banning revokes all sessions) |
| `note` | string | No | Admin note |

#### `delete_user`
**Destructive — requires two-step confirmation.**

#### `user_addresses`
Get a user's linked Ethereum addresses.

#### `user_memberships`
List a user's group memberships.

#### `add_membership`
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `user_id` | string | Yes | User UUID |
| `group_id` | string | Yes | Group UUID |

#### `remove_membership`
**Destructive — requires two-step confirmation.**

#### `effective_permissions`
Get computed effective permissions: claims, allowed methods, contract access, rate limits.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `user_id` | string | Yes | User UUID |
| `org` | string | No | Organization slug (default: `default`) |

#### `check_access`
Check whether a user is allowed to perform a specific RPC call.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `user_external_id` | string | Yes | User DID |
| `method` | string | Yes | RPC method to check |
| `org_id` | string | No | Organization UUID |
| `target_address` | string | No | Contract address |
| `function_selector` | string | No | 4-byte function selector |
| `required_claims` | string[] | No | Claims to check |

### Contracts (12 tools)

#### `list_contracts`
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `org_id` | string | Yes | Organization UUID |

#### `get_contract`
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `org_id` | string | Yes | Organization UUID |
| `address` | string | Yes | Contract address (0x-prefixed) |

#### `create_contract`
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `org_id` | string | Yes | Organization UUID |
| `address` | string | Yes | Contract address |
| `name` | string | No | Contract name |
| `metadata` | object | No | Metadata |

#### `update_contract`
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `org_id` | string | Yes | Organization UUID |
| `address` | string | Yes | Contract address |
| `name` | string | No | New name |
| `metadata` | object | No | New metadata |

#### `update_contract_abi`
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `org_id` | string | Yes | Organization UUID |
| `address` | string | Yes | Contract address |
| `abi` | string | Yes | JSON ABI |

#### `delete_contract`
**Destructive — requires two-step confirmation.**

#### `lookup_contract`
Look up a contract by address across all organizations.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `address` | string | Yes | Contract address |

#### `grant_summary`
Overview of contract grants across an organization.

#### `check_contracts_on_chain`
Check which registered contracts exist on-chain.

#### `delete_stale_contracts`
**Destructive — requires two-step confirmation.** Remove contracts not found on-chain.

#### `batch_move_contracts`
**Destructive — requires two-step confirmation.** Move contracts between organizations.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `org_id` | string | Yes | Source organization UUID |
| `addresses` | string[] | Yes | Contract addresses to move |
| `target_org_id` | string | Yes | Target organization UUID |

### Contract Grants (4 tools)

#### `list_grants`
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `org_id` | string | Yes | Organization UUID |
| `address` | string | Yes | Contract address |

#### `create_grant`
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `org_id` | string | Yes | Organization UUID |
| `address` | string | Yes | Contract address |
| `group_id` | string | Yes | Group UUID |

#### `update_grant`
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `org_id` | string | Yes | Organization UUID |
| `address` | string | Yes | Contract address |
| `group_id` | string | Yes | Group UUID |
| `claims` | string[] | No | Permission claims |
| `functions` | string[] | No | Specific function selectors |

#### `delete_grant`
**Destructive — requires two-step confirmation.**

### Compliance (18 tools)

#### `compliance_config` / `update_compliance_config`
Get or update per-org compliance configuration (enabled, threshold).

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `org_id` | string | Yes | Organization UUID |
| `enabled` | boolean | No | Enable/disable compliance |
| `threshold_fiat` | number | No | Fiat threshold for travel rule |

#### `list_token_prices` / `set_token_price` / `delete_token_price`
Manage per-org token prices for compliance calculations.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `org_id` | string | Yes | Organization UUID |
| `address` | string | Yes | Token contract address |
| `symbol` | string | Yes | Token symbol (e.g. ETH, USDT) |
| `decimals` | number | No | Token decimals (default 18) |
| `prices` | object | Cond. | Price map by currency (`{usd: 3500, eur: 3200}`) |
| `coingecko_id` | string | Cond. | CoinGecko ID for auto-pricing |

Either `prices` or `coingecko_id` is required. Valid currencies: `usd`, `eur`, `chf`, `gbp`, `aed`.

#### `system_token_prices`
Get system-wide token prices (CoinGecko).

#### `compliance_currency` / `set_compliance_currency`
Get or set the base currency for compliance calculations.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `currency` | string | Yes | Currency code (`usd`, `eur`, `chf`, `gbp`, `aed`) |

#### `list_sanctions` / `add_sanction` / `delete_sanction`
Manage sanctioned address blocklist.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `address` | string | Yes | ETH address |
| `reason` | string | No | Reason for sanctioning |
| `source` | string | No | Source (e.g. OFAC, EU) |

#### `list_address_thresholds` / `set_address_threshold` / `delete_address_threshold`
Manage per-address compliance threshold overrides.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `org_id` | string | Yes | Organization UUID |
| `address` | string | Yes | ETH address |
| `threshold_fiat` | number | Yes | Fiat threshold override |

#### `compliance_logs`
Query compliance decision logs for an organization.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `org_id` | string | Yes | Organization UUID |
| `limit` | number | No | Max entries (default 50) |
| `offset` | number | No | Pagination offset |

#### `list_travel_rule_records` / `create_travel_rule_record` / `delete_travel_rule_record`
Manage IVMS101 travel rule records.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `org_id` | string | Yes | Organization UUID |
| `data` | object | Yes | IVMS101 record data |

### Disclosure (9 tools)

#### `create_disclosure_request`
Create a disclosure request for access to a user's data.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `requester_did` | string | Yes | DID of requesting entity |
| `target_user_id` | string | Yes | Target user UUID |
| `disclosure_level` | string | Yes | `full`, `pseudonymous`, or `redacted` |
| `reason` | string | Yes | Reason for disclosure |
| `legal_basis` | string | No | Legal basis (GDPR article, court order) |
| `methods` | string[] | No | Specific RPC methods to disclose |
| `addresses` | string[] | No | Specific contract addresses |
| `expires_in_hours` | number | No | Hours until expiry |

#### `list_disclosure_requests`
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `status` | string | No | Filter: `pending`, `approved`, `rejected`, `expired`, `revoked` |

#### `get_disclosure_request` / `delete_disclosure_request`

#### `list_disclosure_grants` / `revoke_disclosure_grant`

#### `disclosure_check_access`
Check if a DID has disclosure access to a user's data.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `did` | string | Yes | DID to check |
| `user_id` | string | Yes | Target user UUID |

#### `disclosure_grant_logs` / `disclosure_grant_summary` / `disclosure_grant_events` / `disclosure_grant_report`
Access grant audit data.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `grant_id` | string | Yes | Grant UUID |
| `report_type` | string | Yes (report only) | `summary`, `detailed`, `compliance` |

### Sessions & Auth (8 tools)

#### `list_sessions` / `delete_session`
Manage active auth sessions. Delete requires two-step confirmation.

#### `list_providers`
List enabled authentication providers (Privado ID, Azure AD).

#### `list_azure_tenants` / `get_azure_tenant` / `create_azure_tenant` / `update_azure_tenant` / `delete_azure_tenant`
Manage Azure AD tenant allowlist.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `tenant_id` | string | Yes | Azure AD tenant UUID |
| `label` | string | No | Display label |
| `default_org_id` | string | No | Default org for new users |
| `default_group_id` | string | No | Default group for new users |
| `auto_provision` | boolean | No | Auto-create users on first login |

### Explorer (11 tools)

All explorer responses are **privacy-filtered per viewer**. Every tool below
accepts an optional `viewer_jwt` (a user's JWT) selecting whose view to
render; without it the anonymous view is returned, which hides almost
everything by design. See "Viewing data as a specific user" above.

#### `explorer_sync_status`
Block explorer indexer sync status and progress.

#### `explorer_blocks` / `explorer_block`
List recent blocks or get a specific block.

#### `explorer_transactions` / `explorer_transaction`
List recent transactions or get a specific transaction by hash.

#### `explorer_address`
Address statistics: transaction count, balance, contract info.

#### `explorer_address_transactions` / `explorer_address_balance`
Transactions or balance for a specific address.

#### `explorer_tokens`
List tokens indexed by the explorer.

#### `viewable_addresses`
List the addresses a user can see: their own linked wallets plus addresses
disclosed to them via active disclosure grants.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `viewer_jwt` | string | Yes | JWT of the user whose visibility set to list |
| `wallet` | string | No | Wallet address, echoed back for display only |

#### `check_address_visibility`
Check if an address is visible to a viewer.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `address` | string | Yes | ETH address to check |

### Operational (3 tools)

#### `access_logs`
Recent access logs from the Open Privacy Suite.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `limit` | number | No | Max entries (default 50) |

#### `audit_logs`
RBAC audit logs. At least one filter required.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `resource_type` | string | Cond. | Filter by type — common values (not exhaustive): `organization`, `group`, `user`, `membership`, `contract`, `grant`, `disclosure_request`, `disclosure_grant`, `system_setting` |
| `actor_id` | string | Cond. | Filter by actor ID |
| `limit` | number | No | Max entries (default 100) |

#### `cache_stats`
RBAC cache statistics.

## Destructive Operations

All delete/revoke operations use two-step confirmation:

1. First call without `confirm_token` → returns a preview and a time-limited token (60s)
2. Second call with `confirm_token` → executes the operation

Tokens are single-use and cannot be replayed across different operations.

## Data Privacy

When using this MCP server with a cloud-hosted AI (Claude Code with Anthropic's API), tool responses become part of the conversation context sent to Anthropic's servers. This means admin data — org names, user DIDs, contract addresses, compliance configuration — transits through Anthropic's infrastructure.

**What is NOT sent:** The admin API token (`PRIVACY_ADMIN_TOKEN`) is never included in tool responses or conversation context. It exists only in the MCP server process memory and HTTP headers between the MCP server and the Open Privacy Suite API.

**What IS sent:** The content of every tool response — the same data you'd see from a `curl` call to the admin API. This includes org structure, user identities (DIDs), group memberships, contract addresses, compliance config, and disclosure metadata.

**This is inherent to how MCP works** — it applies equally to GitHub MCP (sends your code), Slack MCP (sends your messages), and database MCPs (send your query results).

**Mitigations:**
- Anthropic's API data is not used for model training (see Anthropic's data usage policy)
- Use a self-hosted LLM backend to keep all data on-premises
- Register only the tool domains you need (e.g. explorer-only, compliance-only)
- For maximum sensitivity, use the REST API directly instead of MCP

## Example Usage

With Claude Code, you can manage the full Open Privacy Suite conversationally:

- "List all organizations and their groups"
- "Create a new org called Acme Capital with a traders group"
- "What permissions does user X have in the acme-capital org?"
- "Add a sanction for address 0xBAD... with source OFAC"
- "Set the ACME token price to $1,250 USD"
- "Create a disclosure request for user Y from FinCEN"
- "Show me the compliance logs for the last hour"
- "Check if user did:privado:alice can call eth_sendTransaction on contract 0x123..."

Against the seeded quickstart stack (`make quickstart` — two banks and a
regulator; persona JWTs are printed by the seed and stored in
`.quickstart-demo.json`):

- "List the organizations and their groups — who can do what?"
- "Using Alice's JWT from .quickstart-demo.json, list her transactions in the explorer. Now do the same with Bob's JWT — why is his view empty?"
- "Using test_request with Bob's JWT, try to read the DemoToken balance — explain the denial."
- "Using Rita's JWT, list her viewable addresses — where does her access to Alice's wallet come from?"
- "Show the disclosure grants and the access logs for Rita's grant."
