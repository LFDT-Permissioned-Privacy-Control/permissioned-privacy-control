-- Managed proxies table for tracking proxy contracts that can be upgraded
-- This enables the upgrade validator to intercept and validate proxy upgrade calls

CREATE TABLE IF NOT EXISTS managed_proxies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    proxy_address VARCHAR(42) NOT NULL,
    proxy_type VARCHAR(50) NOT NULL,
    current_impl VARCHAR(42),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(proxy_address)
);

CREATE INDEX IF NOT EXISTS idx_managed_proxies_org ON managed_proxies(org_id);
CREATE INDEX IF NOT EXISTS idx_managed_proxies_address ON managed_proxies(lower(proxy_address));

---- create above / drop below ----

DROP INDEX IF EXISTS idx_managed_proxies_address;
DROP INDEX IF EXISTS idx_managed_proxies_org;
DROP TABLE IF EXISTS managed_proxies;
