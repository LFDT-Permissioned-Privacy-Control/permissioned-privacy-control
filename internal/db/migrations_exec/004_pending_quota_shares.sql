-- exec/004_pending_quota_shares.sql
--
-- ── WHAT ─────────────────────────────────────────────────────────
-- pending_quota_principal and pending_quota_org: the count of bindings each
-- submitting principal and each organization holds — pending, or
-- renewal_stopped and not yet final — next to the global pending_quota row
-- (pending only), so admission can bound one principal's and one
-- organization's work as well as the total renewable work.
--
-- ── WHY (ticket: RD-1410; plan §4.8.2) ───────────────────────────
-- The global pending-work limit protects the lease keeper's renewal budget,
-- but on its own one principal (or a few principals of one organization)
-- could hold the whole limit, for example with transactions that never get
-- included before their maximum age, and every other tenant would be refused.
-- Stopped bindings count too (independent review, finding 2), so no principal
-- accumulates them without bound until they are final. Every writer applies
-- the per-row delta is_held(after) − is_held(before) (held: state 1 or 3),
-- grouped by the binding's principal and organization (identity columns that
-- are never updated), in the same transaction as the global row's
-- is_pending delta: after the binding rows, principals then organizations,
-- and the global row last.
--
-- ── AFFECTED ROWS ────────────────────────────────────────────────
-- One row per principal and per organization with held bindings, seeded
-- here from node_tx_binding (state 1 or 3) while the global quota row is locked,
-- so no admission or transition can change the counts during the seed.
-- Stop every OPS instance of an earlier release before this migration runs:
-- an earlier release updates only the global row. OPS recounts a share that
-- would go below zero at once and repairs any other drift in its periodic
-- maintenance pass (logged as an error). Detection query (must return 0):
--   SELECT
--    (SELECT count(*) FROM pending_quota_principal q
--      FULL JOIN (SELECT principal_id, count(*) AS pending FROM node_tx_binding
--                 WHERE state IN (1, 3) GROUP BY principal_id) b USING (principal_id)
--      WHERE coalesce(q.used, 0) <> coalesce(b.pending, 0))
--   +(SELECT count(*) FROM pending_quota_org q
--      FULL JOIN (SELECT org_id, count(*) AS pending FROM node_tx_binding
--                 WHERE state IN (1, 3) GROUP BY org_id) b USING (org_id)
--      WHERE coalesce(q.used, 0) <> coalesce(b.pending, 0));
--
-- ── AUTHORITATIVE-RECORD note ────────────────────────────────────
-- Operational, lossable state; not evidence. Traceable record = this file
-- (git) + PR review + tern schema_version_exec. No audit-table write. Rows
-- whose count is 0 are deleted by the maintenance pass (owner role), so no
-- principal or organization id is kept after its last held transaction.
--
-- ── EXPAND-ONLY / ROLE-SEPARATION status ─────────────────────────
-- Expand-only: COMPLIANT (CREATE TABLE + seed INSERT + GRANT). The runtime
-- role may read, insert and update counters; it has no DELETE and no DDL.

LOCK TABLE pending_quota IN SHARE ROW EXCLUSIVE MODE;

-- used has no CHECK (used >= 0): writers apply signed deltas with one
-- INSERT … ON CONFLICT DO UPDATE in key order, and PostgreSQL checks a CHECK
-- constraint on the proposed row (a −1) before it resolves the conflict. A
-- writer that would leave a count below zero recounts that key under its row
-- lock instead (and logs an error).
-- fillfactor 50: counters are updated once per batch per key; room on the
-- page keeps those updates HOT (only the primary key is indexed, and it never
-- changes).
CREATE TABLE IF NOT EXISTS pending_quota_principal (
    principal_id UUID PRIMARY KEY,
    used         BIGINT NOT NULL DEFAULT 0
) WITH (fillfactor = 50, autovacuum_vacuum_scale_factor = 0, autovacuum_vacuum_threshold = 1000, autovacuum_vacuum_cost_delay = 0);

CREATE TABLE IF NOT EXISTS pending_quota_org (
    org_id UUID PRIMARY KEY,
    used   BIGINT NOT NULL DEFAULT 0
) WITH (fillfactor = 50, autovacuum_vacuum_scale_factor = 0, autovacuum_vacuum_threshold = 1000, autovacuum_vacuum_cost_delay = 0);

INSERT INTO pending_quota_principal (principal_id, used)
SELECT principal_id, count(*) FROM node_tx_binding WHERE state IN (1, 3) GROUP BY principal_id
ON CONFLICT (principal_id) DO UPDATE SET used = EXCLUDED.used;

INSERT INTO pending_quota_org (org_id, used)
SELECT org_id, count(*) FROM node_tx_binding WHERE state IN (1, 3) GROUP BY org_id
ON CONFLICT (org_id) DO UPDATE SET used = EXCLUDED.used;

GRANT SELECT, INSERT, UPDATE ON pending_quota_principal TO privacy_proxy_app;
GRANT SELECT, INSERT, UPDATE ON pending_quota_org TO privacy_proxy_app;
