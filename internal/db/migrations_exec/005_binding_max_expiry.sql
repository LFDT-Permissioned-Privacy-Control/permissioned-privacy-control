-- exec/005_binding_max_expiry.sql
--
-- ── WHAT ─────────────────────────────────────────────────────────
-- node_tx_binding.max_expires_at: the longest lease of any execution identity
-- recorded for the binding. expires_at stays the current envelope's.
--
-- ── WHY (ticket: RD-1410, independent review finding 2) ──────────
-- A revival may sign a shorter lease than one the node already holds (a
-- database clock step, or a shorter identity lifetime on another instance).
-- The node keeps the longer identity, so retain the longest recorded expiry
-- as an operational envelope fence. Every writer keeps
-- greatest(max_expires_at, the identity it records).
-- Lease expiry alone never finalizes a stopped binding: an unused nonce can
-- execute under a fresh identity, so the immutable owner binding survives
-- until finalized nonce consumption. The earlier lease-expiry finality
-- design was removed after independent review.
--
-- ── AFFECTED ROWS ────────────────────────────────────────────────
-- Existing bindings get max_expires_at = expires_at (in-flight work only;
-- the tracking database holds no history before this release). Stop every
-- OPS instance of an earlier release before this migration runs: an earlier
-- release does not maintain the column (its inserts fail on NOT NULL, which
-- refuses its admissions; fail closed). Detection query (must return 0):
--   SELECT count(*) FROM node_tx_binding WHERE max_expires_at < expires_at;
--
-- ── AUTHORITATIVE-RECORD note ────────────────────────────────────
-- Operational, lossable state; not evidence. The dropped decision itself is
-- audited (ops.system.dropped, with its evidence) before it commits.
-- Traceable record = this file (git) + PR review + tern schema_version_exec.
-- No audit-table write.
--
-- ── EXPAND-ONLY / ROLE-SEPARATION status ─────────────────────────
-- Expand-only: COMPLIANT (ADD COLUMN, backfill, SET NOT NULL, column GRANT).
-- The runtime role may update the new lifecycle column; identity columns stay
-- non-updatable. Unindexed, so binding updates stay HOT-eligible.

ALTER TABLE node_tx_binding ADD COLUMN IF NOT EXISTS max_expires_at TIMESTAMPTZ;
UPDATE node_tx_binding SET max_expires_at = expires_at WHERE max_expires_at IS NULL;
ALTER TABLE node_tx_binding ALTER COLUMN max_expires_at SET NOT NULL;
ALTER TABLE node_tx_binding ADD CONSTRAINT node_tx_binding_max_expiry CHECK (max_expires_at >= expires_at);

GRANT UPDATE (max_expires_at) ON node_tx_binding TO privacy_proxy_app;
