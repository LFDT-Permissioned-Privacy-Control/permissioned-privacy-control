-- 063_audit_chain_checkpoint.sql
-- RD-1112 (#8): signed truncation-detection checkpoints for the tamper-evident
-- audit chains, plus a chain_name column on access_logs for future per-instance
-- chain partitioning (multi-instance scale-out without a chain fork).
--
-- ── WHAT ──────────────────────────────────────────────────────────────────
--   1. audit_chain_checkpoint — append-only signed roll-ups. Per chain_name,
--      {head_id, head_hash, row_count} signed by a key held OUTSIDE the app DB
--      credential's blast radius. Lets the verifier detect TAIL TRUNCATION:
--      deleting recent rows breaks no downstream hash, but it drops row_count
--      and moves the head below the last signed checkpoint.
--   2. access_logs.chain_name (default 'access_logs') — the single global chain
--      today; per-instance sealers will tag their own chain later for scale-out.
--
-- ── WHY ───────────────────────────────────────────────────────────────────
--   Security review findings #1 (count/presence check) + #2 (signed,
--   key-separated checkpoint).
--
-- ── AFFECTED ROWS ─────────────────────────────────────────────────────────
--   None rewritten; existing access_logs rows default to chain_name='access_logs'.
--
-- ── EXPAND-ONLY ───────────────────────────────────────────────────────────
--   Yes — CREATE TABLE + ADD COLUMN + CREATE INDEX + GRANT only.
--
-- ── GRANTS ────────────────────────────────────────────────────────────────
--   New append-only table → SELECT, INSERT for privacy_proxy_app + the sequence
--   grant (per the 058 new-table checklist). access_logs column grant is
--   automatic. Nobody at runtime gets UPDATE/DELETE on the checkpoint table.
--
-- ── AUTHORITATIVE RECORD ──────────────────────────────────────────────────
--   This migration file (git) + PR review + tern schema_version. Checkpoint
--   ROWS are written only at runtime (signed by the checkpoint worker) — never
--   from this migration (per CLAUDE.md).

CREATE TABLE IF NOT EXISTS audit_chain_checkpoint (
    id          BIGSERIAL PRIMARY KEY,
    chain_name  TEXT        NOT NULL,
    head_id     BIGINT      NOT NULL,
    head_hash   TEXT        NOT NULL,
    row_count   BIGINT      NOT NULL,
    key_id      TEXT        NOT NULL,
    signature   TEXT        NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS audit_chain_checkpoint_chain_idx
    ON audit_chain_checkpoint (chain_name, id DESC);

ALTER TABLE access_logs
    ADD COLUMN IF NOT EXISTS chain_name TEXT NOT NULL DEFAULT 'access_logs';

GRANT SELECT, INSERT ON audit_chain_checkpoint TO privacy_proxy_app;
GRANT USAGE, UPDATE ON SEQUENCE audit_chain_checkpoint_id_seq TO privacy_proxy_app;

---- create above / drop below ----

-- Down migration is development-only; production is expand-only (CLAUDE.md).
-- ALTER TABLE access_logs DROP COLUMN IF EXISTS chain_name;
-- DROP TABLE IF EXISTS audit_chain_checkpoint;
