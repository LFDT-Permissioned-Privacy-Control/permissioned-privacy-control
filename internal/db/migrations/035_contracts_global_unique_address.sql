-- Add global unique constraint on contract address (case-insensitive).
-- Previously unique per org only — two orgs could register the same address.
-- Now only one org can own a contract address.
CREATE UNIQUE INDEX IF NOT EXISTS idx_contracts_address_global_unique ON contracts(LOWER(address));

---- create above / drop below ----

DROP INDEX IF EXISTS idx_contracts_address_global_unique;
