-- exec/003_tracking_schema.sql
--
-- ── WHAT ─────────────────────────────────────────────────────────
-- The compact per-transaction schema of the Reth execution path (plan §4.10):
--   * node_tx_binding   — one row per transaction hash H from admission until a
--                         final status: who submitted it (principal, org,
--                         signer), its current identity generation, delivery,
--                         and inclusion state. The single serialization point
--                         for anti-rebinding: every admission, transition and
--                         finalization of H acts on this row under its lock.
--   * node_tx_payload   — the raw signed transaction, written once at admission.
--                         Kept in a ring of 16 fifteen-minute buckets; a bucket
--                         is truncated by the owner once no identity created in
--                         it can still be valid (maximum age + finality bound +
--                         margin). Never updated or deleted per row.
--   * node_tx_status    — insert-once final status (included, reverted, dropped),
--                         daily partitions on final_at, dropped after
--                         RETENTION_NODE_SUBMISSIONS.
--   * node_tx_identities— operational history: generations ≥ 2, refusals and
--                         stops; daily partitions on created_at, same retention.
--   * pending_quota     — the count of renewable (pending) bindings, so admission
--                         can be bounded across instances.
-- Daily partitions are created ahead (CREATE + ATTACH) and expired ones
-- detached and dropped by the owner pool, never by the runtime role.
--
-- ── WHY (ticket: RD-1410) ────────────────────────────────────────
-- The main-database node_submissions row (2.2 KB, never deleted, three
-- non-HOT updates per transaction) moves out of the main database into this
-- lossable tracking database. Updates touch only unindexed columns of the
-- binding row (HOT); final rows leave it; history and status are pruned by
-- partition, not by DELETE and vacuum.
--
-- ── AFFECTED ROWS ────────────────────────────────────────────────
-- None: new tables in a new database. V2 is not deployed, so there is no
-- node_submissions data to move.
--
-- ── AUTHORITATIVE-RECORD note ────────────────────────────────────
-- Operational state, not evidence: the executed identity lives in the node's
-- block manifests; system decisions are audited in the access-log chain before
-- they commit here. Traceable record = this file (git) + PR review + tern
-- schema_version_exec. No audit-table write.
--
-- ── EXPAND-ONLY / ROLE-SEPARATION status ─────────────────────────
-- Expand-only: COMPLIANT (CREATE TABLE / INDEX / FUNCTION + GRANT). The runtime
-- role gets SELECT, INSERT, UPDATE, DELETE on the operational tables, SELECT
-- and INSERT on the insert-once tables, and no DDL; partition maintenance runs
-- as the owner.

CREATE TABLE IF NOT EXISTS node_tx_binding (
    tx_hash              BYTEA PRIMARY KEY CHECK (octet_length(tx_hash) = 32),
    principal_id         UUID NOT NULL,
    org_id               UUID NOT NULL,
    signer               BYTEA NOT NULL CHECK (octet_length(signer) = 20),
    nonce                BIGINT NOT NULL CHECK (nonce >= 0),
    -- 1 pending, 2 provisional, 3 renewal_stopped.
    state                SMALLINT NOT NULL CHECK (state BETWEEN 1 AND 3),
    -- The state before the last admission upsert (NULL after an insert), so
    -- the upsert's quota delta is computed under the row lock.
    prev_state           SMALLINT,
    reason               SMALLINT NOT NULL DEFAULT 0,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    generation           INTEGER NOT NULL CHECK (generation > 0),
    context_id           UUID NOT NULL,
    envelope_hash        BYTEA NOT NULL CHECK (octet_length(envelope_hash) = 32),
    expires_at           TIMESTAMPTZ NOT NULL,
    min_version          BIGINT NOT NULL CHECK (min_version > 0),
    delivered_boot       UUID,
    delivered_generation INTEGER,
    claim_owner          UUID,
    claim_boot           UUID,
    claim_expires        TIMESTAMPTZ,
    incarnation          UUID NOT NULL,
    issued_contexts      UUID[] NOT NULL,
    visible_to           TEXT[] NOT NULL DEFAULT '{}',
    -- The sender DID, stored only for transactions with visibleTo, so the
    -- visibility rule survives a principal deleted before finality (K24).
    visible_sender       TEXT,
    block_number         BIGINT,
    -- The node_tx_payload bucket holding raw_tx (set with the payload row).
    payload_bucket       SMALLINT NOT NULL CHECK (payload_bucket BETWEEN 0 AND 15),
    -- The inserting transaction, never updated: the reconciler discovers rows
    -- other instances admitted by it, reading only xids below the snapshot
    -- xmin, so a row whose transaction commits late is never skipped. An
    -- index on a never-updated column keeps every update HOT-eligible.
    admit_xid            XID8 NOT NULL DEFAULT pg_current_xact_id(),
    CHECK ((visible_sender IS NULL) = (cardinality(visible_to) = 0))
) WITH (fillfactor = 50, autovacuum_vacuum_scale_factor = 0, autovacuum_vacuum_threshold = 10000, autovacuum_vacuum_cost_delay = 0);
-- fillfactor 50: rows admitted together share a page and are made provisional
-- together, in one transaction, so a page needs room for a second version of
-- every row it holds; at 70 only about 45% of those updates stay HOT (G45).
-- Rows leave the table at finality, so it holds only in-flight work; vacuum
-- runs by row count (not table fraction) to return deleted space promptly.
CREATE INDEX IF NOT EXISTS node_tx_binding_admit_xid ON node_tx_binding (admit_xid);

CREATE TABLE IF NOT EXISTS node_tx_payload (
    bucket  SMALLINT NOT NULL CHECK (bucket BETWEEN 0 AND 15),
    tx_hash BYTEA NOT NULL CHECK (octet_length(tx_hash) = 32),
    raw_tx  BYTEA NOT NULL,
    PRIMARY KEY (bucket, tx_hash)
) PARTITION BY LIST (bucket);
DO $$
BEGIN
    FOR b IN 0..15 LOOP
        EXECUTE format('CREATE TABLE IF NOT EXISTS node_tx_payload_%s PARTITION OF node_tx_payload FOR VALUES IN (%s)', b, b);
    END LOOP;
END$$;

CREATE TABLE IF NOT EXISTS node_tx_status (
    tx_hash      BYTEA NOT NULL CHECK (octet_length(tx_hash) = 32),
    principal_id UUID NOT NULL,
    org_id       UUID NOT NULL,
    -- 10 included, 11 reverted, 12 dropped.
    state        SMALLINT NOT NULL CHECK (state BETWEEN 10 AND 12),
    reason       SMALLINT NOT NULL DEFAULT 0,
    final_at     TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    block_number BIGINT
) PARTITION BY RANGE (final_at);
CREATE INDEX IF NOT EXISTS node_tx_status_tx_hash ON node_tx_status (tx_hash);

CREATE TABLE IF NOT EXISTS node_tx_identities (
    tx_hash            BYTEA NOT NULL CHECK (octet_length(tx_hash) = 32),
    generation         INTEGER NOT NULL,
    context_id         UUID NOT NULL,
    envelope_hash      BYTEA,
    expires_at         TIMESTAMPTZ,
    min_version        BIGINT,
    reason             SMALLINT NOT NULL DEFAULT 0,
    actor              SMALLINT NOT NULL DEFAULT 0,
    travel_rule_record UUID,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    seq                BIGSERIAL
) PARTITION BY RANGE (created_at);
CREATE INDEX IF NOT EXISTS node_tx_identities_seq ON node_tx_identities (seq);

CREATE TABLE IF NOT EXISTS pending_quota (
    singleton BOOLEAN PRIMARY KEY DEFAULT true CHECK (singleton),
    used      BIGINT NOT NULL DEFAULT 0 CHECK (used >= 0)
);
INSERT INTO pending_quota (singleton, used) VALUES (true, 0) ON CONFLICT DO NOTHING;

-- The binding's identity (hash, principal, organisation, signer, nonce,
-- visibility, incarnation, admission xid) is never updated: the runtime role
-- may update only the lifecycle columns.
GRANT SELECT, INSERT, DELETE ON node_tx_binding TO privacy_proxy_app;
GRANT UPDATE (state, prev_state, reason, created_at, generation, context_id, envelope_hash, expires_at, min_version,
              delivered_boot, delivered_generation, claim_owner, claim_boot, claim_expires, issued_contexts,
              block_number, payload_bucket) ON node_tx_binding TO privacy_proxy_app;
GRANT SELECT, INSERT ON node_tx_payload TO privacy_proxy_app;
GRANT SELECT, INSERT ON node_tx_status TO privacy_proxy_app;
GRANT SELECT, INSERT ON node_tx_identities TO privacy_proxy_app;
GRANT USAGE ON SEQUENCE node_tx_identities_seq_seq TO privacy_proxy_app;
GRANT SELECT, UPDATE ON pending_quota TO privacy_proxy_app;
