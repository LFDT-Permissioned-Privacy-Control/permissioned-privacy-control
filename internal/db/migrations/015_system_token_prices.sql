-- 015_system_token_prices.sql
-- System-wide token price cache populated by CoinGecko background fetcher.
-- Per-org token_prices can reference system prices via coingecko_id.

CREATE TABLE IF NOT EXISTS system_token_prices (
    coingecko_id VARCHAR(100) PRIMARY KEY,
    symbol       VARCHAR(20) NOT NULL,
    decimals     INTEGER NOT NULL DEFAULT 18,
    price_usd    DOUBLE PRECISION NOT NULL DEFAULT 0,
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Seed with common tokens (price starts at 0 until first CoinGecko fetch)
INSERT INTO system_token_prices (coingecko_id, symbol, decimals, price_usd)
VALUES
    ('ethereum', 'ETH', 18, 0),
    ('tether', 'USDT', 6, 0),
    ('usd-coin', 'USDC', 6, 0)
ON CONFLICT (coingecko_id) DO NOTHING;

-- Add coingecko_id to per-org token_prices for price source mapping
ALTER TABLE token_prices ADD COLUMN IF NOT EXISTS coingecko_id VARCHAR(100);

---- create above / drop below ----

ALTER TABLE token_prices DROP COLUMN IF EXISTS coingecko_id;
DROP TABLE IF EXISTS system_token_prices;
