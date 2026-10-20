-- 042_audit_chain_anchor.sql
-- Persist the last-pruned entry hash per audit chain so that the chain stays
-- verifiable across pruning cuts. Every prune (FIFO row cap or time-based TTL)
-- writes the anchor before deleting rows. On startup the hash chain seeder
-- falls back to this table when no surviving rows are present.

CREATE TABLE IF NOT EXISTS audit_chain_anchor (
    chain_name             TEXT PRIMARY KEY,
    last_pruned_id         BIGINT NOT NULL,
    last_pruned_entry_hash TEXT NOT NULL,
    last_pruned_at         TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

---- create above / drop below ----

DROP TABLE IF EXISTS audit_chain_anchor;
