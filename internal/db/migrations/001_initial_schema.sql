-- Initial schema for privacy-proxy
-- Consolidated schema including simplified RBAC tables

-- =============================================================================
-- Legacy tables (for backward compatibility)
-- =============================================================================

CREATE TABLE IF NOT EXISTS access_policies (
    external_id VARCHAR(255) PRIMARY KEY,
    kyc BOOLEAN NOT NULL DEFAULT false,
    allow_methods JSONB NOT NULL DEFAULT '[]'::jsonb,
    banned BOOLEAN NOT NULL DEFAULT false,
    note TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS access_logs (
    id SERIAL PRIMARY KEY,
    external_id VARCHAR(255) NOT NULL,
    method VARCHAR(100) NOT NULL,
    status_code INTEGER NOT NULL,
    ip_address VARCHAR(45),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS refresh_tokens (
    token_hash VARCHAR(255) PRIMARY KEY,
    subject VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NOT NULL,
    revoked BOOLEAN NOT NULL DEFAULT false,
    revoked_at TIMESTAMP
);

CREATE TABLE IF NOT EXISTS revoked_tokens (
    token_id VARCHAR(255) PRIMARY KEY,
    subject VARCHAR(255) NOT NULL,
    revoked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NOT NULL
);

-- =============================================================================
-- ETH Address Linking
-- =============================================================================

CREATE TABLE IF NOT EXISTS eth_address_links (
    id SERIAL PRIMARY KEY,
    did VARCHAR(255) NOT NULL,
    eth_address VARCHAR(42) NOT NULL,  -- Ethereum address with 0x prefix (lowercase)
    signature VARCHAR(512) NOT NULL,    -- EIP-191 personal_sign signature
    message_hash VARCHAR(66) NOT NULL,  -- Keccak256 hash of the signed message
    verified_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    revoked BOOLEAN DEFAULT false,
    revoked_at TIMESTAMP,
    ens_name VARCHAR(255),              -- Cached ENS name (if any)
    ens_resolved_at TIMESTAMP,          -- When ENS was last resolved
    UNIQUE(eth_address)  -- Each ETH address can only be linked to one DID
);

-- =============================================================================
-- RBAC tables (Simplified - Contract-Centric Model)
-- =============================================================================

-- Organizations: Top-level tenants
CREATE TABLE IF NOT EXISTS organizations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    slug VARCHAR(100) UNIQUE NOT NULL,
    name VARCHAR(255) NOT NULL,
    settings JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Groups: Hierarchical permission containers within organizations
-- Note: role_id removed - permissions now come from group_access and contract_grants
CREATE TABLE IF NOT EXISTS groups (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    parent_id UUID REFERENCES groups(id) ON DELETE CASCADE,
    slug VARCHAR(100) NOT NULL,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    depth INTEGER NOT NULL DEFAULT 0,
    path TEXT NOT NULL, -- Materialized path for efficient queries (e.g., "root.engineering.devops")
    is_org_admin BOOLEAN NOT NULL DEFAULT false, -- If true, members get all claims on all contracts in the org
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(org_id, slug)
);

-- Contracts: First-class resources representing deployed contracts
-- Note: "Ownership" is claims-based - a group with 'admin' claim on a contract is considered its owner
CREATE TABLE IF NOT EXISTS contracts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    address VARCHAR(42) NOT NULL, -- Ethereum address (lowercase, with 0x prefix)
    name VARCHAR(255),
    deployed_by_user_id UUID, -- Audit trail only (FK added after users table)
    deployed_at TIMESTAMP,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
-- Unique constraint on lowercase address per org (using functional index)
CREATE UNIQUE INDEX IF NOT EXISTS idx_contracts_org_address_unique ON contracts(org_id, lower(address));

-- Contract grants: Links groups to contracts with specific claims
-- Claims: 'admin', 'upgrade', 'deploy'
--   - admin: full control, considered "owner" of the contract
--   - upgrade: can upgrade proxy contracts
--   - deploy: can deploy contracts via this group
CREATE TABLE IF NOT EXISTS contract_grants (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    contract_id UUID NOT NULL REFERENCES contracts(id) ON DELETE CASCADE,
    group_id UUID NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    claims TEXT[] NOT NULL DEFAULT '{}', -- Array of claims: admin, upgrade, deploy
    functions TEXT[], -- NULL = all functions, or specific selectors ['0x12345678']
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(contract_id, group_id)
);

-- Group access: RPC method permissions and rate limits per group
-- Replaces roles.allow_methods and group_permissions rate limits
CREATE TABLE IF NOT EXISTS group_access (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    group_id UUID NOT NULL REFERENCES groups(id) ON DELETE CASCADE UNIQUE,
    allowed_methods TEXT[] NOT NULL DEFAULT '{}', -- Allowed JSON-RPC methods
    default_claims TEXT[] DEFAULT '{}', -- Claims for unregistered contracts
    rate_limit_rps INTEGER, -- Requests per second limit (NULL = unlimited)
    rate_limit_daily INTEGER, -- Daily request limit (NULL = unlimited)
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Users: Extended user model for RBAC
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    external_id VARCHAR(255) UNIQUE NOT NULL, -- User's DID
    kyc BOOLEAN NOT NULL DEFAULT false,
    banned BOOLEAN NOT NULL DEFAULT false,
    note TEXT,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Add FK constraint for contracts.deployed_by_user_id now that users table exists
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'fk_contracts_deployed_by_user'
    ) THEN
        ALTER TABLE contracts ADD CONSTRAINT fk_contracts_deployed_by_user
            FOREIGN KEY (deployed_by_user_id) REFERENCES users(id) ON DELETE SET NULL;
    END IF;
END $$;

-- User memberships: Links users to groups (simplified - no role_id override)
CREATE TABLE IF NOT EXISTS user_memberships (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    group_id UUID NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    source VARCHAR(50) NOT NULL DEFAULT 'admin', -- 'admin' or 'zk_attested'
    zk_credential_ref TEXT, -- Reference to ZK credential if source is zk_attested
    expires_at TIMESTAMP, -- Optional membership expiration
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(user_id, group_id)
);

-- Effective permissions cache: Materialized permissions for performance
-- Updated to reflect new contract-centric model
CREATE TABLE IF NOT EXISTS effective_permissions_cache (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    allowed_methods TEXT[] NOT NULL DEFAULT '{}',
    contract_access JSONB NOT NULL DEFAULT '{}'::jsonb, -- {address: {claims: [], functions: []}}
    default_claims TEXT[] DEFAULT '{}', -- Claims for unregistered contracts
    rate_limit_rps INTEGER,
    rate_limit_daily INTEGER,
    computed_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NOT NULL,
    UNIQUE(user_id, org_id)
);

-- RBAC audit log: Audit trail for all RBAC changes
CREATE TABLE IF NOT EXISTS rbac_audit_log (
    id BIGSERIAL PRIMARY KEY,
    actor_id UUID, -- User who performed the action (NULL for system actions)
    actor_external_id VARCHAR(255), -- External ID of actor for reference
    action VARCHAR(50) NOT NULL, -- create, update, delete, assign, revoke
    resource_type VARCHAR(50) NOT NULL, -- organization, group, user, membership, contract, grant, access
    resource_id UUID, -- ID of the affected resource
    resource_name VARCHAR(255), -- Human-readable name for reference
    old_value JSONB, -- Previous value (for updates)
    new_value JSONB, -- New value
    ip_address VARCHAR(45),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- =============================================================================
-- Indexes
-- =============================================================================

-- Legacy table indexes
CREATE INDEX IF NOT EXISTS idx_logs_external_id ON access_logs(external_id);
CREATE INDEX IF NOT EXISTS idx_logs_created_at ON access_logs(created_at);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_subject ON refresh_tokens(subject);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_expires ON refresh_tokens(expires_at);
CREATE INDEX IF NOT EXISTS idx_revoked_tokens_subject ON revoked_tokens(subject);
CREATE INDEX IF NOT EXISTS idx_revoked_tokens_expires ON revoked_tokens(expires_at);

-- ETH address linking indexes
CREATE INDEX IF NOT EXISTS idx_eth_address_links_did ON eth_address_links(did);
CREATE INDEX IF NOT EXISTS idx_eth_address_links_eth_address ON eth_address_links(eth_address);
CREATE INDEX IF NOT EXISTS idx_eth_address_links_active ON eth_address_links(did) WHERE revoked = false;

-- RBAC indexes
CREATE INDEX IF NOT EXISTS idx_groups_org_id ON groups(org_id);
CREATE INDEX IF NOT EXISTS idx_groups_parent_id ON groups(parent_id);
CREATE INDEX IF NOT EXISTS idx_groups_path ON groups(path);
CREATE INDEX IF NOT EXISTS idx_contracts_org_id ON contracts(org_id);
CREATE INDEX IF NOT EXISTS idx_contracts_address ON contracts(address);
CREATE INDEX IF NOT EXISTS idx_contract_grants_contract_id ON contract_grants(contract_id);
CREATE INDEX IF NOT EXISTS idx_contract_grants_group_id ON contract_grants(group_id);
CREATE INDEX IF NOT EXISTS idx_group_access_group_id ON group_access(group_id);
CREATE INDEX IF NOT EXISTS idx_users_external_id ON users(external_id);
CREATE INDEX IF NOT EXISTS idx_user_memberships_user_id ON user_memberships(user_id);
CREATE INDEX IF NOT EXISTS idx_user_memberships_group_id ON user_memberships(group_id);
CREATE INDEX IF NOT EXISTS idx_effective_permissions_user_org ON effective_permissions_cache(user_id, org_id);
CREATE INDEX IF NOT EXISTS idx_effective_permissions_expires ON effective_permissions_cache(expires_at);
CREATE INDEX IF NOT EXISTS idx_rbac_audit_log_actor ON rbac_audit_log(actor_id);
CREATE INDEX IF NOT EXISTS idx_rbac_audit_log_resource ON rbac_audit_log(resource_type, resource_id);
CREATE INDEX IF NOT EXISTS idx_rbac_audit_log_created ON rbac_audit_log(created_at);

-- =============================================================================
-- Default data
-- =============================================================================

-- Create default organization
INSERT INTO organizations (id, slug, name, settings)
VALUES (
    '00000000-0000-0000-0000-000000000001',
    'default',
    'Default Organization',
    '{}'::jsonb
)
ON CONFLICT (slug) DO NOTHING;

-- Create default root group
INSERT INTO groups (id, org_id, parent_id, slug, name, description, depth, path)
VALUES (
    '00000000-0000-0000-0000-000000000001',
    '00000000-0000-0000-0000-000000000001',
    NULL,
    'default',
    'Default Group',
    'Default group for all users',
    0,
    'default'
)
ON CONFLICT (org_id, slug) DO NOTHING;

-- Create default group access (allow common JSON-RPC methods)
INSERT INTO group_access (id, group_id, allowed_methods, default_claims)
VALUES (
    '00000000-0000-0000-0000-000000000001',
    '00000000-0000-0000-0000-000000000001',
    ARRAY['eth_blockNumber', 'eth_chainId', 'eth_gasPrice', 'net_version', 'net_listening', 'web3_clientVersion'],
    ARRAY[]::TEXT[] -- Default claims for unregistered contracts (none — legacy read/write removed)
)
ON CONFLICT (group_id) DO NOTHING;

---- create above / drop below ----

-- Drop all indexes
DROP INDEX IF EXISTS idx_rbac_audit_log_created;
DROP INDEX IF EXISTS idx_rbac_audit_log_resource;
DROP INDEX IF EXISTS idx_rbac_audit_log_actor;
DROP INDEX IF EXISTS idx_effective_permissions_expires;
DROP INDEX IF EXISTS idx_effective_permissions_user_org;
DROP INDEX IF EXISTS idx_user_memberships_group_id;
DROP INDEX IF EXISTS idx_user_memberships_user_id;
DROP INDEX IF EXISTS idx_users_external_id;
DROP INDEX IF EXISTS idx_group_access_group_id;
DROP INDEX IF EXISTS idx_contract_grants_group_id;
DROP INDEX IF EXISTS idx_contract_grants_contract_id;
DROP INDEX IF EXISTS idx_contracts_address;
DROP INDEX IF EXISTS idx_contracts_org_id;
DROP INDEX IF EXISTS idx_groups_path;
DROP INDEX IF EXISTS idx_groups_parent_id;
DROP INDEX IF EXISTS idx_groups_org_id;
DROP INDEX IF EXISTS idx_eth_address_links_active;
DROP INDEX IF EXISTS idx_eth_address_links_eth_address;
DROP INDEX IF EXISTS idx_eth_address_links_did;
DROP INDEX IF EXISTS idx_revoked_tokens_expires;
DROP INDEX IF EXISTS idx_revoked_tokens_subject;
DROP INDEX IF EXISTS idx_refresh_tokens_expires;
DROP INDEX IF EXISTS idx_refresh_tokens_subject;
DROP INDEX IF EXISTS idx_logs_created_at;
DROP INDEX IF EXISTS idx_logs_external_id;

-- Drop all tables (in reverse dependency order)
DROP TABLE IF EXISTS rbac_audit_log;
DROP TABLE IF EXISTS effective_permissions_cache;
DROP TABLE IF EXISTS user_memberships;
DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS group_access;
DROP TABLE IF EXISTS contract_grants;
DROP TABLE IF EXISTS contracts;
DROP TABLE IF EXISTS groups;
DROP TABLE IF EXISTS organizations;
DROP TABLE IF EXISTS eth_address_links;
DROP TABLE IF EXISTS revoked_tokens;
DROP TABLE IF EXISTS refresh_tokens;
DROP TABLE IF EXISTS access_logs;
DROP TABLE IF EXISTS access_policies;
