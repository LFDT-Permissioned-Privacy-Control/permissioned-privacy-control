-- 023: Add prices_by_currency JSONB to token_prices for multi-currency support.
-- Manual per-org token prices can now be set per currency, matching the system_token_prices pattern.

ALTER TABLE token_prices ADD COLUMN IF NOT EXISTS prices_by_currency JSONB NOT NULL DEFAULT '{}';

---- create above / drop below ----

-- down (dev only)
ALTER TABLE token_prices DROP COLUMN IF EXISTS prices_by_currency;
