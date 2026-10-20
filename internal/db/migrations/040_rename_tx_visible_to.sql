-- Rename tx_log_visible_to -> tx_visible_to (expand-only: create new table, keep old).
-- The "logVisibleTo" param is renamed to "visibleTo" to reflect that it grants
-- full tx + log visibility, not just log visibility.

CREATE TABLE tx_visible_to (
    tx_hash         TEXT NOT NULL,
    visible_to_dids TEXT[] NOT NULL,
    sender_did      TEXT NOT NULL,
    org_id          TEXT NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_tx_visible_to_tx ON tx_visible_to (tx_hash);
CREATE INDEX idx_tx_visible_to_sender ON tx_visible_to (sender_did);
CREATE INDEX idx_tx_visible_to_dids ON tx_visible_to USING GIN (visible_to_dids);

-- Migrate existing data
INSERT INTO tx_visible_to SELECT * FROM tx_log_visible_to;

---- create above / drop below ----

DROP TABLE IF EXISTS tx_visible_to;
