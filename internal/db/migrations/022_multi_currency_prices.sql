-- 022_multi_currency_prices.sql
-- Store CoinGecko prices for all supported currencies so currency switching is instant.

ALTER TABLE system_token_prices ADD COLUMN prices_by_currency JSONB NOT NULL DEFAULT '{}';

---- create above / drop below ----

ALTER TABLE system_token_prices DROP COLUMN prices_by_currency;
