-- audit/004_access_logs_buffer_ranges.sql
--
-- ── WHAT ─────────────────────────────────────────────────────────
-- 1. access_logs_buffer_range_seq: every start of an instance with an async
--    audit buffer (AUDIT_BUFFER_DIR) draws one value n from it and numbers its
--    new buffer entries in the range n·2^40 + 1 .. (n+1)·2^40 − 1. Its first
--    value is set above every buffer_seq already stored. The runtime role may
--    only draw from it (USAGE: nextval, no setval).
-- 2. access_logs_chain_head_idx on (chain_name, id) for rows with a hash: the
--    sealer reads its chain's head before every batch it writes.
--
-- ── WHY (ticket: RD-1410) ────────────────────────────────────────
-- buffer_seq is unique across the whole table (access_logs_buffer_seq_uniq,
-- audit/002), but every instance used to number its entries from its chain's
-- high-water: two instances with different AUDIT_CHAIN_NAME values both
-- allocated 1, 2, 3 …, and the second one's seals failed on that index for
-- good. Two instances with the same name resumed from each other's
-- high-water and deleted unsealed records. With ranges every allocated
-- sequence is unique by construction (the index stays: expand-only), each
-- range is written by one buffer only, in order, so its high-water is that
-- buffer's exact resume point. The sealer now links each batch to the head it
-- reads under a per-chain transaction lock; without the index that read scans
-- every other instance's rows written since this chain's last batch.
--
-- ── ARITHMETIC ───────────────────────────────────────────────────
-- One range holds 2^40 − 1 ≈ 1.1·10^12 sequences: about 3.3 years of one
-- instance at 10,500 records/s without a restart (2^32 would last 4.7 days).
-- buffer_seq is a signed bigint, so the sequence ends at 2^23 − 1 = 8,388,607
-- starts (NO CYCLE), one start a minute for 15 years; the last range ends at
-- 2^63 − 1.
--
-- ── AFFECTED ROWS ────────────────────────────────────────────────
-- No access_logs row is changed; the index build reads every row. Detection
-- query (expect true: the next range to be drawn starts above every stored
-- entry):
--   SELECT (last_value + CASE WHEN is_called THEN 1 ELSE 0 END) << 40
--        > COALESCE((SELECT MAX(buffer_seq) FROM access_logs), 0)
--     FROM access_logs_buffer_range_seq;
--
-- ── OPERATIONAL IMPACT ───────────────────────────────────────────
-- CREATE INDEX blocks writes to access_logs (not reads) while it builds; on a
-- large table run it in the same maintenance window as audit/003, instances
-- stopped (`privacy-proxy migrate -audit`). lock_timeout makes it fail fast
-- instead of queueing every access_logs write behind a lock it cannot get.
-- Instances of an earlier release must be stopped before this release's first
-- instance starts: they number their entries the old way.
--
-- ── AUTHORITATIVE-RECORD note ────────────────────────────────────
-- Traceable record = this migration file (git) + PR review + tern
-- schema_version_audit. Writes nothing to a hash-chained table.
--
-- ── EXPAND-ONLY / ROLE-SEPARATION status ─────────────────────────
-- Expand-only: COMPLIANT (CREATE SEQUENCE, CREATE INDEX, GRANT). Role
-- separation: privacy_proxy_app gains USAGE on the new sequence only (draw,
-- not set). Runs ONLY against the audit database.

SET LOCAL lock_timeout = '10s';

CREATE SEQUENCE IF NOT EXISTS access_logs_buffer_range_seq
    AS bigint START WITH 1 INCREMENT BY 1 MINVALUE 1 MAXVALUE 8388607 NO CYCLE CACHE 1;

-- The first range starts above every buffer sequence already stored, so old
-- entries (numbered per chain from 1) never share a sequence with new ones.
SELECT setval('access_logs_buffer_range_seq',
              (COALESCE((SELECT MAX(buffer_seq) FROM access_logs), 0) >> 40) + 1,
              false);

GRANT USAGE ON SEQUENCE access_logs_buffer_range_seq TO privacy_proxy_app;

CREATE INDEX IF NOT EXISTS access_logs_chain_head_idx
    ON access_logs USING btree (chain_name, id) WHERE (entry_hash IS NOT NULL);
