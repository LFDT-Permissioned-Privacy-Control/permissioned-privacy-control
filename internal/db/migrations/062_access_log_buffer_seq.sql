-- 062_access_log_buffer_seq.sql
-- RD-1112 (#6/#7): the access-log write moves OFF the request hot path. The
-- proxy now appends each entry to a durable embedded buffer and returns; a
-- single background sealer drains the buffer in order and writes the chained
-- rows here. This column records the buffer sequence each row was sealed from.
--
-- ── WHAT ──────────────────────────────────────────────────────────────────
--   Add access_logs.buffer_seq (nullable) + a partial UNIQUE index on it.
--
-- ── WHY ───────────────────────────────────────────────────────────────────
--   1. Idempotency key — a UNIQUE buffer_seq makes a double-seal a loud
--      constraint error, never a silent duplicate.
--   2. Crash-safe resume — the sealer reads MAX(buffer_seq) as its high-water;
--      entries at or below it are already sealed and skipped on the next drain
--      (so a crash between the chain commit and the buffer delete cannot
--      double-seal).
--   buffer_seq is OPERATIONAL metadata only — it is NOT part of the hashed
--   chain content (AccessLogChainContent), so the verifier and all existing
--   rows are unaffected.
--
-- ── AFFECTED ROWS ─────────────────────────────────────────────────────────
--   None rewritten. Legacy rows and any synchronous (non-buffered) writes have
--   buffer_seq = NULL; the partial unique index excludes NULLs.
--
-- ── EXPAND-ONLY ───────────────────────────────────────────────────────────
--   Yes — ADD COLUMN + CREATE INDEX only. No DROP, no constraint removal.
--
-- ── GRANTS ────────────────────────────────────────────────────────────────
--   None needed — access_logs is already granted to privacy_proxy_app
--   (migration 058); PostgreSQL column grants are automatic.
--
-- ── AUTHORITATIVE RECORD ──────────────────────────────────────────────────
--   This migration file (git) + PR review + tern schema_version applied-at
--   timestamp. No write to any hash-chained audit table from this migration
--   (per CLAUDE.md) — buffer_seq is populated only at runtime by the sealer.

ALTER TABLE access_logs
    ADD COLUMN IF NOT EXISTS buffer_seq BIGINT;

CREATE UNIQUE INDEX IF NOT EXISTS access_logs_buffer_seq_uniq
    ON access_logs (buffer_seq)
    WHERE buffer_seq IS NOT NULL;

---- create above / drop below ----

-- Down migration is development-only; production is expand-only (CLAUDE.md).
-- DROP INDEX IF EXISTS access_logs_buffer_seq_uniq;
-- ALTER TABLE access_logs DROP COLUMN IF EXISTS buffer_seq;
