-- Pre-registered addresses for CREATE3 deployments
-- Allows organizations to whitelist future deployment addresses before bytecode is known

CREATE TABLE IF NOT EXISTS preregistered_addresses (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    address VARCHAR(42) NOT NULL,
    factory VARCHAR(42) NOT NULL,
    salt BYTEA NOT NULL,
    note TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    used_at TIMESTAMP,
    UNIQUE(address)
);

CREATE INDEX IF NOT EXISTS idx_preregistered_addresses_org ON preregistered_addresses(org_id);
CREATE INDEX IF NOT EXISTS idx_preregistered_addresses_address ON preregistered_addresses(lower(address));

---- create above / drop below ----

DROP INDEX IF EXISTS idx_preregistered_addresses_address;
DROP INDEX IF EXISTS idx_preregistered_addresses_org;
DROP TABLE IF EXISTS preregistered_addresses;
