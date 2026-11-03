-- exec/002_tracking_meta.sql
--
-- ── WHAT ─────────────────────────────────────────────────────────
-- tracking_meta: one row naming the network (chain id, deployment id) this
-- tracking database belongs to, and a random incarnation created with it.
--
-- ── WHY (ticket: RD-1410; plan §4.10, §4.8.4) ────────────────────
-- OPS refuses to start against a tracking database recorded for another
-- network. The incarnation fences asynchronous work: every batch asserts the
-- incarnation it was issued under, so after the database is dropped and
-- recreated (new incarnation) no outstanding acknowledgement, transition or
-- finalization from before can touch a new row.
--
-- ── AFFECTED ROWS ────────────────────────────────────────────────
-- None at migration time. The owner pool inserts the single row at the first
-- start (INSERT … ON CONFLICT DO NOTHING); later starts only compare it.
--
-- ── AUTHORITATIVE-RECORD note ────────────────────────────────────
-- Operational, lossable state; not evidence. Traceable record = this file
-- (git) + PR review + tern schema_version_exec. No audit-table write.
--
-- ── EXPAND-ONLY / ROLE-SEPARATION status ─────────────────────────
-- Expand-only: COMPLIANT (CREATE TABLE + GRANT). The runtime role may only
-- read the row; the owner writes it.

CREATE TABLE IF NOT EXISTS tracking_meta (
    singleton     BOOLEAN PRIMARY KEY DEFAULT true CHECK (singleton),
    chain_id      BIGINT NOT NULL CHECK (chain_id > 0),
    deployment_id TEXT NOT NULL CHECK (deployment_id <> ''),
    incarnation   UUID NOT NULL DEFAULT gen_random_uuid(),
    created_at    TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

GRANT SELECT ON tracking_meta TO privacy_proxy_app;
