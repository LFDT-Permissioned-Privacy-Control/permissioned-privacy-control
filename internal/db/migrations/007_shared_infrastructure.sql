-- Create shared_infrastructure table for globally accessible contracts
-- This table stores contracts that are allowed for all organizations during runtime tracing.
-- Examples include Uniswap router, WETH, and other common DeFi infrastructure.
-- Used for cross-org isolation validation - these addresses bypass org-specific checks.

CREATE TABLE shared_infrastructure (
    address TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Index for efficient listing by creation time
CREATE INDEX idx_shared_infrastructure_created_at ON shared_infrastructure(created_at);

---- create above / drop below ----

DROP INDEX IF EXISTS idx_shared_infrastructure_created_at;
DROP TABLE IF EXISTS shared_infrastructure;
