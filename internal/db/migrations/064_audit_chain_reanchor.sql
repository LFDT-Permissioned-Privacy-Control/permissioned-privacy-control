-- 064_audit_chain_reanchor.sql
-- RD-1112 (#8): signed break-glass re-anchor records — the authorized,
-- attributable, tamper-evident trail of a DELIBERATE audit-chain discontinuity
-- (recovery after data loss, a migration, a chain reset).
--
-- ── WHAT ──────────────────────────────────────────────────────────────────
--   audit_chain_reanchor — append-only. Each row records {chain_name, reason,
--   actor, from→to head} and is SIGNED by the checkpoint key. The break-glass
--   operation also moves audit_chain_anchor + writes a fresh checkpoint so the
--   verifier resumes cleanly from the recovery point.
--
-- ── WHY ───────────────────────────────────────────────────────────────────
--   Security review #3: a chain that can never be re-anchored after a
--   legitimate incident is operationally unusable; but the re-anchor is the one
--   operation that could mask tampering, so it must be signed (by a key outside
--   the DB credential), attributed (actor + reason), and permanently recorded.
--   Writing one requires the checkpoint key → gated to the PR-approved,
--   dual-control break-glass runbook. This is visibility, not suppression: the
--   row is the forever record of the break.
--
-- ── EXPAND-ONLY ───────────────────────────────────────────────────────────
--   Yes — CREATE TABLE + CREATE INDEX + GRANT only.
--
-- ── GRANTS ────────────────────────────────────────────────────────────────
--   New append-only table → SELECT, INSERT for privacy_proxy_app + sequence
--   grant (058 new-table checklist). Nobody at runtime gets UPDATE/DELETE.
--
-- ── AUTHORITATIVE RECORD ──────────────────────────────────────────────────
--   This migration file (git) + PR review + tern schema_version. Re-anchor
--   ROWS are written only at runtime (signed) — never from this migration.

CREATE TABLE IF NOT EXISTS audit_chain_reanchor (
    id           BIGSERIAL PRIMARY KEY,
    chain_name   TEXT        NOT NULL,
    reason       TEXT        NOT NULL,
    actor        TEXT        NOT NULL,
    from_head_id BIGINT      NOT NULL,
    from_hash    TEXT        NOT NULL DEFAULT '',
    to_head_id   BIGINT      NOT NULL,
    to_hash      TEXT        NOT NULL DEFAULT '',
    key_id       TEXT        NOT NULL,
    signature    TEXT        NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS audit_chain_reanchor_chain_idx
    ON audit_chain_reanchor (chain_name, id DESC);

GRANT SELECT, INSERT ON audit_chain_reanchor TO privacy_proxy_app;
GRANT USAGE, UPDATE ON SEQUENCE audit_chain_reanchor_id_seq TO privacy_proxy_app;

---- create above / drop below ----

-- Down migration is development-only; production is expand-only (CLAUDE.md).
-- DROP TABLE IF EXISTS audit_chain_reanchor;
