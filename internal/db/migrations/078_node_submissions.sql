-- 078_node_submissions.sql — main-database side of transaction execution
-- (rewritten in place by RD-1410; V2 has not been deployed).
--
-- CHANGE MANAGEMENT: the earlier version of this migration created
-- node_submissions, the per-transaction intent table, in the main database.
-- RD-1410 moves per-transaction tracking to the separate execution-tracking
-- database (internal/db/migrations_exec), so this file no longer creates it.
-- A development database migrated with the earlier version must be recreated:
-- OPS refuses to start in Reth mode against it (CheckNodePolicySchema). Once
-- V2 ships, the expand-only policy applies to this file again.

-- ── Cross-database effects of the execution-tracking database (RD-1410) ──
-- WHAT: three main-database tables for the per-transaction tracking that now
-- lives in the separate execution-tracking database (plan §4.11):
--   * node_tx_effects_floor — per network, the durable replay floor: no
--     finalized transaction at or below this block may apply effects again.
--     Never deleted, never lowered (trigger), so pruning markers and raising
--     retention can never re-enable expired work.
--   * node_tx_effects_applied — one marker per finalized transaction WITH
--     side effects (created contracts, visibleTo), with one bit per effect,
--     so a re-run after a crash between this database and the tracking
--     database applies each effect at most once and never re-applies one an
--     administrator has since revoked.
--   * node_tx_compliance_claims — the one travel-rule record claimed by each
--     transaction, so a same-transaction retry or renewal re-uses its own
--     record instead of consuming another.
-- WHY: idempotency instead of cross-database atomicity; one claim per tx.
-- AFFECTED ROWS: none (new tables). The floor row is created by OPS for its
-- configured network at startup, not here (a migration cannot know it).
-- AUTHORITATIVE RECORD: markers and claims are bookkeeping; the actor-
-- attributed records stay rbac_audit_log, compliance_logs and the access-log
-- chain. No audit-chain write.
-- EXPAND-ONLY / ROLE SEPARATION: new tables; the runtime role may not delete
-- or lower the floor.
CREATE TABLE node_tx_effects_floor (
    chain_id BIGINT NOT NULL CHECK (chain_id > 0),
    deployment_id TEXT NOT NULL CHECK (deployment_id <> ''),
    floor_block BIGINT NOT NULL DEFAULT 0 CHECK (floor_block >= 0),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (chain_id, deployment_id)
);
CREATE FUNCTION node_tx_effects_floor_monotone() RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP IN ('DELETE', 'TRUNCATE') THEN
        RAISE EXCEPTION 'the node effects replay floor is never deleted' USING ERRCODE = '55000';
    END IF;
    IF NEW.chain_id <> OLD.chain_id OR NEW.deployment_id <> OLD.deployment_id OR NEW.floor_block < OLD.floor_block THEN
        RAISE EXCEPTION 'the node effects replay floor only rises' USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER node_tx_effects_floor_guard BEFORE UPDATE OR DELETE ON node_tx_effects_floor
FOR EACH ROW EXECUTE FUNCTION node_tx_effects_floor_monotone();
CREATE TRIGGER node_tx_effects_floor_no_truncate BEFORE TRUNCATE ON node_tx_effects_floor
FOR EACH STATEMENT EXECUTE FUNCTION node_tx_effects_floor_monotone();

CREATE TABLE node_tx_effects_applied (
    chain_id BIGINT NOT NULL,
    deployment_id TEXT NOT NULL,
    tx_hash BYTEA NOT NULL CHECK (octet_length(tx_hash) = 32),
    block_number BIGINT NOT NULL CHECK (block_number >= 0),
    ownership BOOLEAN NOT NULL DEFAULT false,
    visibility BOOLEAN NOT NULL DEFAULT false,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (chain_id, deployment_id, tx_hash),
    FOREIGN KEY (chain_id, deployment_id) REFERENCES node_tx_effects_floor (chain_id, deployment_id)
);
CREATE INDEX node_tx_effects_applied_age ON node_tx_effects_applied (chain_id, deployment_id, applied_at);

CREATE TABLE node_tx_compliance_claims (
    chain_id BIGINT NOT NULL CHECK (chain_id > 0),
    deployment_id TEXT NOT NULL CHECK (deployment_id <> ''),
    tx_hash BYTEA NOT NULL CHECK (octet_length(tx_hash) = 32),
    travel_rule_record_id UUID NOT NULL UNIQUE REFERENCES travel_rule_records (id) ON DELETE CASCADE,
    claimed_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (chain_id, deployment_id, tx_hash)
);
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='privacy_proxy_app') THEN
        GRANT SELECT, INSERT, UPDATE ON node_tx_effects_floor TO privacy_proxy_app;
        GRANT SELECT, INSERT, UPDATE, DELETE ON node_tx_effects_applied TO privacy_proxy_app;
        GRANT SELECT, INSERT ON node_tx_compliance_claims TO privacy_proxy_app;
    END IF;
END $$;
