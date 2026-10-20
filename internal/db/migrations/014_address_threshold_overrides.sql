-- Per-address threshold overrides for risk-based compliance.
-- Allows orgs to set lower travel rule thresholds for specific addresses.

CREATE TABLE IF NOT EXISTS address_threshold_overrides (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    address VARCHAR(42) NOT NULL,
    threshold_usd NUMERIC(20, 2) NOT NULL DEFAULT 0,
    note TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(org_id, address),
    CHECK (threshold_usd >= 0)
);

---- create above / drop below ----

DROP TABLE IF EXISTS address_threshold_overrides;
