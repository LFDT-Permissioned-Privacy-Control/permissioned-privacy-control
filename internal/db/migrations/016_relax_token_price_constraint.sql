-- 016_relax_token_price_constraint.sql
-- Relax token price constraint to allow zero prices for CoinGecko-mapped tokens.
-- Manual token prices must be positive, but CoinGecko-mapped tokens are resolved
-- at runtime from system_token_prices, so their price_usd is initially 0.

ALTER TABLE token_prices DROP CONSTRAINT chk_token_price_usd_positive;
ALTER TABLE token_prices ADD CONSTRAINT chk_token_price_usd_positive CHECK (price_usd > 0 OR coingecko_id IS NOT NULL);

---- create above / drop below ----

ALTER TABLE token_prices DROP CONSTRAINT chk_token_price_usd_positive;
ALTER TABLE token_prices ADD CONSTRAINT chk_token_price_usd_positive CHECK (price_usd > 0);
