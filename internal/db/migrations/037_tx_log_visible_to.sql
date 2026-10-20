-- Per-transaction log visibility extension: allows tx senders to specify
-- additional DIDs that can see event logs for that specific transaction.
-- Purely additive — never restricts existing access from event rules.

CREATE TABLE tx_log_visible_to (
    tx_hash         TEXT NOT NULL,
    visible_to_dids TEXT[] NOT NULL,
    sender_did      TEXT NOT NULL,
    org_id          TEXT NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_tx_log_visible_to_tx ON tx_log_visible_to (tx_hash);
CREATE INDEX idx_tx_log_visible_to_sender ON tx_log_visible_to (sender_did);

---- create above / drop below ----

DROP TABLE IF EXISTS tx_log_visible_to;
