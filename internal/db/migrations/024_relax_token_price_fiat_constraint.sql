-- Allow price_fiat = 0 for manual tokens when the active currency has no price
-- in prices_by_currency (fail-closed: 0 price blocks transactions).
-- The old constraint required price_fiat > 0 for manual tokens, which prevented
-- currency switching from setting price_fiat = 0 for unconfigured currencies.

ALTER TABLE token_prices DROP CONSTRAINT IF EXISTS chk_token_price_fiat_positive;
ALTER TABLE token_prices ADD CONSTRAINT chk_token_price_fiat_non_negative CHECK (price_fiat >= 0);

---- create above / drop below ----

ALTER TABLE token_prices DROP CONSTRAINT IF EXISTS chk_token_price_fiat_non_negative;
ALTER TABLE token_prices ADD CONSTRAINT chk_token_price_fiat_positive CHECK (price_fiat > 0 OR coingecko_id IS NOT NULL);
