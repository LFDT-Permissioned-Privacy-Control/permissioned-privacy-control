-- Travel Rule Compliance tables for threshold-based transfer enforcement,
-- IVMS101 travel rule records, sanctioned address blocklists, and audit logging.

-- Per-org compliance configuration
CREATE TABLE IF NOT EXISTS compliance_config (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE UNIQUE,
    enabled BOOLEAN NOT NULL DEFAULT false,
    threshold_usd NUMERIC(20, 2) NOT NULL DEFAULT 1000.00,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Admin-configured token pricing (private network has no external oracles)
CREATE TABLE IF NOT EXISTS token_prices (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    token_address VARCHAR(42) NOT NULL, -- lowercase 0x-prefixed, or "native" for ETH
    symbol VARCHAR(20) NOT NULL,
    decimals INTEGER NOT NULL DEFAULT 18,
    price_usd NUMERIC(20, 8) NOT NULL,
    updated_by_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(org_id, token_address)
);

-- IVMS101 travel rule records submitted before transfer
CREATE TABLE IF NOT EXISTS travel_rule_records (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    originator_user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    originator_data JSONB NOT NULL,
    beneficiary_data JSONB NOT NULL,
    transfer_type VARCHAR(20) NOT NULL,
    token_address VARCHAR(42), -- NULL for native ETH
    beneficiary_address VARCHAR(42) NOT NULL,
    amount_wei VARCHAR(78) NOT NULL,
    amount_usd NUMERIC(20, 2) NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    used_at TIMESTAMPTZ,
    used_tx_hash VARCHAR(66),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT valid_transfer_type CHECK (transfer_type IN ('eth', 'erc20'))
);

-- Sanctioned address blocklist (global + per-org)
CREATE TABLE IF NOT EXISTS sanctioned_addresses (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    address VARCHAR(42) NOT NULL,
    reason TEXT NOT NULL,
    source VARCHAR(100),
    added_by_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Unique constraints for sanctioned_addresses (NULL-safe with partial indexes)
CREATE UNIQUE INDEX idx_sanctioned_addr_global ON sanctioned_addresses(address) WHERE org_id IS NULL;
CREATE UNIQUE INDEX idx_sanctioned_addr_org ON sanctioned_addresses(org_id, address) WHERE org_id IS NOT NULL;

-- Immutable compliance decision audit trail
CREATE TABLE IF NOT EXISTS compliance_logs (
    id BIGSERIAL PRIMARY KEY,
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    transfer_type VARCHAR(20) NOT NULL,
    token_address VARCHAR(42),
    from_address VARCHAR(42) NOT NULL,
    to_address VARCHAR(42) NOT NULL,
    amount_wei VARCHAR(78) NOT NULL,
    amount_usd NUMERIC(20, 2),
    threshold_usd NUMERIC(20, 2),
    decision VARCHAR(20) NOT NULL,
    denial_reason TEXT,
    travel_rule_record_id UUID REFERENCES travel_rule_records(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT valid_decision CHECK (decision IN ('allowed', 'denied'))
);

-- Indexes
CREATE INDEX idx_token_prices_org_token ON token_prices(org_id, token_address);
CREATE INDEX idx_travel_records_org_user ON travel_rule_records(org_id, originator_user_id);
CREATE INDEX idx_travel_records_lookup ON travel_rule_records(org_id, originator_user_id, beneficiary_address, token_address)
    WHERE used_at IS NULL;
CREATE INDEX idx_travel_records_expires ON travel_rule_records(expires_at) WHERE used_at IS NULL;
CREATE INDEX idx_sanctioned_lookup ON sanctioned_addresses(address);
CREATE INDEX idx_compliance_logs_org ON compliance_logs(org_id, created_at);
CREATE INDEX idx_compliance_logs_user ON compliance_logs(user_id, created_at);
CREATE INDEX idx_compliance_logs_decision ON compliance_logs(decision, created_at);

---- create above / drop below ----

DROP INDEX IF EXISTS idx_compliance_logs_decision;
DROP INDEX IF EXISTS idx_compliance_logs_user;
DROP INDEX IF EXISTS idx_compliance_logs_org;
DROP INDEX IF EXISTS idx_sanctioned_lookup;
DROP INDEX IF EXISTS idx_travel_records_expires;
DROP INDEX IF EXISTS idx_travel_records_lookup;
DROP INDEX IF EXISTS idx_travel_records_org_user;
DROP INDEX IF EXISTS idx_token_prices_org_token;
DROP INDEX IF EXISTS idx_sanctioned_addr_org;
DROP INDEX IF EXISTS idx_sanctioned_addr_global;
DROP TABLE IF EXISTS compliance_logs;
DROP TABLE IF EXISTS sanctioned_addresses;
DROP TABLE IF EXISTS travel_rule_records;
DROP TABLE IF EXISTS token_prices;
DROP TABLE IF EXISTS compliance_config;
