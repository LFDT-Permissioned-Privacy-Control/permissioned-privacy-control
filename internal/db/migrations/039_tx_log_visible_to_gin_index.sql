-- Add GIN index on visible_to_dids to support efficient lookups by viewer DID.
-- Required by the shared-logs endpoint which queries for all txs where a given
-- DID appears in the visible_to_dids array.

CREATE INDEX idx_tx_log_visible_to_dids ON tx_log_visible_to USING GIN (visible_to_dids);

---- create above / drop below ----

DROP INDEX IF EXISTS idx_tx_log_visible_to_dids;
