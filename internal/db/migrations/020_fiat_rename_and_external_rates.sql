-- 018_fiat_rename_and_external_rates.sql
-- Part A: Rename _usd → _fiat across all tables
-- Part B: Add currency snapshot to audit tables
-- Part C: Extend system_token_prices for external rates

-- Part A: Rename _usd → _fiat

-- compliance_config
ALTER TABLE compliance_config RENAME COLUMN threshold_usd TO threshold_fiat;
ALTER TABLE compliance_config DROP CONSTRAINT chk_compliance_threshold_non_negative;
ALTER TABLE compliance_config ADD CONSTRAINT chk_compliance_threshold_non_negative CHECK (threshold_fiat >= 0);

-- token_prices
ALTER TABLE token_prices RENAME COLUMN price_usd TO price_fiat;
ALTER TABLE token_prices DROP CONSTRAINT chk_token_price_usd_positive;
ALTER TABLE token_prices ADD CONSTRAINT chk_token_price_fiat_positive CHECK (price_fiat > 0 OR coingecko_id IS NOT NULL);

-- travel_rule_records
ALTER TABLE travel_rule_records RENAME COLUMN amount_usd TO amount_fiat;
ALTER TABLE travel_rule_records DROP CONSTRAINT chk_travel_rule_amount_usd_positive;
ALTER TABLE travel_rule_records ADD CONSTRAINT chk_travel_rule_amount_fiat_positive CHECK (amount_fiat > 0);

-- compliance_logs
ALTER TABLE compliance_logs RENAME COLUMN amount_usd TO amount_fiat;
ALTER TABLE compliance_logs RENAME COLUMN threshold_usd TO threshold_fiat;

-- address_threshold_overrides
ALTER TABLE address_threshold_overrides RENAME COLUMN threshold_usd TO threshold_fiat;

-- system_token_prices
ALTER TABLE system_token_prices RENAME COLUMN price_usd TO price_fiat;

-- Part B: Add currency snapshot to audit tables
ALTER TABLE compliance_logs ADD COLUMN currency VARCHAR(10) NOT NULL DEFAULT 'usd';
ALTER TABLE travel_rule_records ADD COLUMN currency VARCHAR(10) NOT NULL DEFAULT 'usd';

-- Part C: Extend system_token_prices for external rates

-- New columns
ALTER TABLE system_token_prices ADD COLUMN source VARCHAR(20) NOT NULL DEFAULT 'coingecko';
ALTER TABLE system_token_prices ADD COLUMN token_address VARCHAR(42);
ALTER TABLE system_token_prices ADD CONSTRAINT chk_stp_source CHECK (source IN ('coingecko', 'external'));

-- Seed token_address for ETH
UPDATE system_token_prices SET token_address = 'native' WHERE coingecko_id = 'ethereum';

-- Change PK: coingecko_id → serial id (external tokens have no coingecko_id)
ALTER TABLE system_token_prices DROP CONSTRAINT system_token_prices_pkey;
ALTER TABLE system_token_prices ALTER COLUMN coingecko_id DROP NOT NULL;
ALTER TABLE system_token_prices ADD COLUMN id SERIAL PRIMARY KEY;

-- Unique partial indexes replace old PK
CREATE UNIQUE INDEX idx_stp_coingecko_id ON system_token_prices(coingecko_id) WHERE coingecko_id IS NOT NULL;
CREATE UNIQUE INDEX idx_stp_token_address ON system_token_prices(token_address) WHERE token_address IS NOT NULL;

---- create above / drop below ----
