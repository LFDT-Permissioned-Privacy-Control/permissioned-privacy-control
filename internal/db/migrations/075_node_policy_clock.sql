-- WHAT: the commit-ordered fact clock of the private execution node, the
-- change log its incremental export reads, and the node's acknowledgement
-- cursor (RD-1411).
--   * node_policy_clock: one version, bumped ONCE per transaction that changes
--     a column the fact export reads (internal/db/node_policy_export.go,
--     nodePolicyFactDependencies). The row lock orders fact writers, so a
--     consumer can never see version 2 before version 1 commits.
--   * node_policy_changes: the keys each version changed. The elected
--     publisher reads it to export only what changed since the generation the
--     node holds, and prunes it through every version the node acknowledged;
--     node_policy_change_floor says everything above it is still present.
--   * node_policy_cursors: the generation the node acknowledged.
--   * Row triggers on every table the export reads: insert and delete always;
--     update only WHEN one of the export's dependency columns changed (a WHEN
--     clause rather than UPDATE OF, so a value set by a BEFORE trigger counts).
--     A statement trigger on truncate forces a full export.
--   * pg_notify('node_policy_changed', version) once per transaction, delivered
--     at commit, so the publisher publishes on change instead of on its timer.
-- WHY (RD-1411): every update of a fact table bumped the clock (no column
-- filter: logins, notes, deployment metadata), each bump made requests wait for
-- a publication the publisher only noticed on its 1 s timer, and every
-- publication exported every fact.
-- AFFECTED ROWS: none. Version 1 denotes the initial full export.
-- AUTHORITATIVE RECORD: the fact rows themselves. The clock and the change log
-- project them (keys only: no actor, no values) and are pruned; they are not a
-- compliance record. Actor-attributed evidence of fact changes stays in
-- rbac_audit_log and configuration_revisions. No audit-chain table is written.
-- REWRITTEN IN PLACE: V2 (073-083) is not deployed. This replaces the earlier
-- 075_node_policy_outbox (a JSONB outbox written per change and read by
-- nothing). A development database that applied the earlier file must be
-- recreated. execution_policy_revisions' triggers are created in 083, after
-- its artifact_set column exists.
-- NOTES: a fact write NOTIFYs, so it cannot run in a prepared (two-phase)
-- transaction; the publisher LISTENs on a direct session, not through a
-- transaction-pooling proxy.
-- EXPAND-ONLY / ROLE SEPARATION: new tables, functions and triggers only. The
-- runtime role reads the clock, the log and the floor and changes them only
-- through the SECURITY DEFINER functions below.
-- Detection: SELECT version FROM node_policy_clock;
--   SELECT version, entity, resource_key FROM node_policy_changes ORDER BY version;

CREATE TABLE node_policy_clock (
    singleton BOOLEAN PRIMARY KEY DEFAULT true CHECK (singleton),
    version BIGINT NOT NULL CHECK (version > 0)
);
INSERT INTO node_policy_clock(singleton, version) VALUES (true, 1);

CREATE TABLE node_policy_changes (
    version BIGINT NOT NULL CHECK (version > 0),
    entity TEXT NOT NULL CHECK (entity IN ('principal','did','group','contract','contract_id','policy','sanctions','full')),
    resource_key TEXT NOT NULL CHECK (resource_key <> ''),
    PRIMARY KEY (version, entity, resource_key)
);

CREATE TABLE node_policy_change_floor (
    singleton BOOLEAN PRIMARY KEY DEFAULT true CHECK (singleton),
    version BIGINT NOT NULL CHECK (version > 0)
);
INSERT INTO node_policy_change_floor(singleton, version) VALUES (true, 1);

CREATE TABLE node_policy_cursors (
    consumer_id TEXT PRIMARY KEY,
    version BIGINT NOT NULL CHECK (version > 0),
    payload_digest TEXT NOT NULL CHECK (payload_digest ~ '^[0-9a-f]{64}$'),
    expires_at BIGINT NOT NULL CHECK (expires_at > 0),
    acknowledged_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

-- One version per transaction. The marker is transaction-local and carries
-- the transaction id, so neither a later transaction on the same session nor
-- a session-level value can reuse it; a rolled-back savepoint reverts the
-- clock update, the marker and the pending notification together.
-- The clock, the log and the floor are written only through these SECURITY
-- DEFINER functions: the runtime role can add keys and prune through a
-- version (which raises the floor with it), but can neither delete a change
-- nor lower the floor, so it cannot hide a gap from the reader.
CREATE FUNCTION node_policy_bump() RETURNS BIGINT LANGUAGE plpgsql
SECURITY DEFINER SET search_path = pg_catalog, public, pg_temp AS $$
DECLARE
    marker TEXT := current_setting('ops.node_policy_tx', true);
    tx TEXT := txid_current()::text;
    v BIGINT;
BEGIN
    IF marker IS NOT NULL AND split_part(marker, ':', 1) = tx THEN
        RETURN split_part(marker, ':', 2)::bigint;
    END IF;
    -- The row lock lasts until commit and orders every later fact writer.
    UPDATE node_policy_clock SET version = version + 1 WHERE singleton
    RETURNING version INTO v;
    PERFORM set_config('ops.node_policy_tx', tx || ':' || v, true);
    PERFORM pg_notify('node_policy_changed', v::text);
    -- Bound the log when no publisher acknowledges (legacy mode, no node):
    -- every 1,024 versions drop what is more than 8,192 versions old. A
    -- publisher whose generation is older reads in full.
    IF v % 1024 = 0 AND v > 8192 THEN
        PERFORM node_policy_prune(v - 8192);
    END IF;
    RETURN v;
END
$$;

CREATE FUNCTION node_policy_record(p_entity TEXT, p_keys TEXT[]) RETURNS VOID LANGUAGE plpgsql
SECURITY DEFINER SET search_path = pg_catalog, public, pg_temp AS $$
DECLARE
    v BIGINT := node_policy_bump();
BEGIN
    INSERT INTO node_policy_changes(version, entity, resource_key)
    SELECT DISTINCT v, p_entity, k FROM unnest(p_keys) AS k WHERE k IS NOT NULL AND k <> ''
    ON CONFLICT DO NOTHING;
END
$$;

-- Pruning through an acknowledged version raises the floor in the same
-- statement; the floor never moves down.
CREATE FUNCTION node_policy_prune(through BIGINT) RETURNS VOID LANGUAGE plpgsql
SECURITY DEFINER SET search_path = pg_catalog, public, pg_temp AS $$
DECLARE
    bound BIGINT;
BEGIN
    IF through IS NULL OR through < 1 THEN RETURN; END IF;
    -- Never past the committed clock: a floor above it would describe
    -- changes that do not exist yet.
    SELECT LEAST(through, version) INTO bound FROM node_policy_clock WHERE singleton;
    UPDATE node_policy_change_floor SET version = GREATEST(version, bound) WHERE singleton;
    DELETE FROM node_policy_changes WHERE version <= bound;
END
$$;

-- Manual marking (operators, tests): bump and record one key.
CREATE FUNCTION node_policy_mark_dirty(entity TEXT, resource_key TEXT)
RETURNS VOID LANGUAGE plpgsql AS $$
BEGIN
    IF resource_key IS NULL OR resource_key = '' THEN RETURN; END IF;
    IF entity NOT IN ('principal','did','group','contract','contract_id','policy','sanctions','full') THEN
        RAISE EXCEPTION 'unsupported node policy entity';
    END IF;
    -- Keys are canonical: lower case, except DIDs, which are case-sensitive.
    PERFORM node_policy_record(entity, ARRAY[CASE WHEN entity = 'did' THEN resource_key ELSE lower(resource_key) END]);
END
$$;

-- Records the key of each row image (both on update, so a key move marks the
-- old and the new key). Keys are what the export keys facts by: user ids,
-- DIDs (resolved to users by the reader), group ids, lower-case contract
-- addresses, organisation ids for policies, org:address for sanctions. A
-- policy row counts only while an image is active; the export reads nothing
-- else, so a draft does not bump the clock.
CREATE FUNCTION node_policy_capture_change() RETURNS TRIGGER LANGUAGE plpgsql AS $$
DECLARE
    entity TEXT := TG_ARGV[0];
    key_column TEXT := TG_ARGV[1];
    image JSONB;
    keys TEXT[] := '{}';
BEGIN
    FOREACH image IN ARRAY CASE TG_OP
            WHEN 'INSERT' THEN ARRAY[to_jsonb(NEW)]
            WHEN 'DELETE' THEN ARRAY[to_jsonb(OLD)]
            ELSE ARRAY[to_jsonb(OLD), to_jsonb(NEW)]
        END
    LOOP
        IF entity = 'policy' AND image->>'status' IS DISTINCT FROM 'active' THEN
            CONTINUE;
        END IF;
        keys := keys || CASE entity
            WHEN 'sanctions' THEN COALESCE(image->>'org_id', '') || ':' || lower(image->>'address')
            WHEN 'contract' THEN lower(image->>key_column)
            ELSE image->>key_column
        END;
    END LOOP;
    IF entity = 'policy' AND cardinality(keys) = 0 THEN
        RETURN NULL;
    END IF;
    PERFORM node_policy_record(entity, keys);
    RETURN NULL;
END
$$;

-- Contracts also record the contract id when its id or address moves: a
-- group's contract claims embed the granted address. The reader resolves the
-- ids to the groups holding grants in its own snapshot, never here, so a
-- grant committed concurrently with the move cannot be missed.
CREATE FUNCTION node_policy_capture_contract() RETURNS TRIGGER LANGUAGE plpgsql AS $$
DECLARE
    keys TEXT[] := '{}';
BEGIN
    IF TG_OP <> 'INSERT' THEN keys := keys || lower(OLD.address); END IF;
    IF TG_OP <> 'DELETE' THEN keys := keys || lower(NEW.address); END IF;
    PERFORM node_policy_record('contract', keys);
    IF TG_OP = 'UPDATE' AND (OLD.id IS DISTINCT FROM NEW.id OR lower(OLD.address) IS DISTINCT FROM lower(NEW.address)) THEN
        PERFORM node_policy_record('contract_id', ARRAY[OLD.id::text, NEW.id::text]);
    END IF;
    RETURN NULL;
END
$$;

-- A truncation records no keys: the reader falls back to the full export.
CREATE FUNCTION node_policy_capture_truncate() RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    PERFORM node_policy_record('full', ARRAY['*']);
    RETURN NULL;
END
$$;

-- Dependency columns per table (plan RD-1411 §5.1; nodePolicyFactDependencies
-- in node_policy_export.go must list exactly these).
CREATE TRIGGER node_policy_users_rows AFTER INSERT OR DELETE ON users
FOR EACH ROW EXECUTE FUNCTION node_policy_capture_change('principal','id');
CREATE TRIGGER node_policy_users_update AFTER UPDATE ON users
FOR EACH ROW WHEN ((OLD.id, OLD.external_id, OLD.kyc, OLD.banned) IS DISTINCT FROM (NEW.id, NEW.external_id, NEW.kyc, NEW.banned))
EXECUTE FUNCTION node_policy_capture_change('principal','id');

CREATE TRIGGER node_policy_user_memberships_rows AFTER INSERT OR DELETE ON user_memberships
FOR EACH ROW EXECUTE FUNCTION node_policy_capture_change('principal','user_id');
CREATE TRIGGER node_policy_user_memberships_update AFTER UPDATE ON user_memberships
FOR EACH ROW WHEN ((OLD.user_id, OLD.group_id, OLD.expires_at) IS DISTINCT FROM (NEW.user_id, NEW.group_id, NEW.expires_at))
EXECUTE FUNCTION node_policy_capture_change('principal','user_id');

CREATE TRIGGER node_policy_eth_address_links_rows AFTER INSERT OR DELETE ON eth_address_links
FOR EACH ROW EXECUTE FUNCTION node_policy_capture_change('did','did');
CREATE TRIGGER node_policy_eth_address_links_update AFTER UPDATE ON eth_address_links
FOR EACH ROW WHEN ((OLD.did, OLD.eth_address, OLD.revoked) IS DISTINCT FROM (NEW.did, NEW.eth_address, NEW.revoked))
EXECUTE FUNCTION node_policy_capture_change('did','did');

CREATE TRIGGER node_policy_access_policies_rows AFTER INSERT OR DELETE ON access_policies
FOR EACH ROW EXECUTE FUNCTION node_policy_capture_change('did','external_id');
CREATE TRIGGER node_policy_access_policies_update AFTER UPDATE ON access_policies
FOR EACH ROW WHEN ((OLD.external_id, OLD.banned) IS DISTINCT FROM (NEW.external_id, NEW.banned))
EXECUTE FUNCTION node_policy_capture_change('did','external_id');

CREATE TRIGGER node_policy_groups_rows AFTER INSERT OR DELETE ON groups
FOR EACH ROW EXECUTE FUNCTION node_policy_capture_change('group','id');
CREATE TRIGGER node_policy_groups_update AFTER UPDATE ON groups
FOR EACH ROW WHEN ((OLD.id, OLD.org_id, OLD.is_org_admin) IS DISTINCT FROM (NEW.id, NEW.org_id, NEW.is_org_admin))
EXECUTE FUNCTION node_policy_capture_change('group','id');

CREATE TRIGGER node_policy_group_access_rows AFTER INSERT OR DELETE ON group_access
FOR EACH ROW EXECUTE FUNCTION node_policy_capture_change('group','group_id');
CREATE TRIGGER node_policy_group_access_update AFTER UPDATE ON group_access
FOR EACH ROW WHEN ((OLD.group_id, OLD.claims) IS DISTINCT FROM (NEW.group_id, NEW.claims))
EXECUTE FUNCTION node_policy_capture_change('group','group_id');

CREATE TRIGGER node_policy_contract_grants_rows AFTER INSERT OR DELETE ON contract_grants
FOR EACH ROW EXECUTE FUNCTION node_policy_capture_change('group','group_id');
CREATE TRIGGER node_policy_contract_grants_update AFTER UPDATE ON contract_grants
FOR EACH ROW WHEN ((OLD.group_id, OLD.contract_id) IS DISTINCT FROM (NEW.group_id, NEW.contract_id))
EXECUTE FUNCTION node_policy_capture_change('group','group_id');

CREATE TRIGGER node_policy_contracts_rows AFTER INSERT OR DELETE ON contracts
FOR EACH ROW EXECUTE FUNCTION node_policy_capture_contract();
CREATE TRIGGER node_policy_contracts_update AFTER UPDATE ON contracts
FOR EACH ROW WHEN ((OLD.id, OLD.address, OLD.org_id, OLD.deployed_by_user_id) IS DISTINCT FROM (NEW.id, NEW.address, NEW.org_id, NEW.deployed_by_user_id))
EXECUTE FUNCTION node_policy_capture_contract();

CREATE TRIGGER node_policy_shared_infrastructure_rows AFTER INSERT OR DELETE ON shared_infrastructure
FOR EACH ROW EXECUTE FUNCTION node_policy_capture_change('contract','address');
CREATE TRIGGER node_policy_shared_infrastructure_update AFTER UPDATE ON shared_infrastructure
FOR EACH ROW WHEN ((OLD.address, OLD.codehash) IS DISTINCT FROM (NEW.address, NEW.codehash))
EXECUTE FUNCTION node_policy_capture_change('contract','address');

CREATE TRIGGER node_policy_preregistered_addresses_rows AFTER INSERT OR DELETE ON preregistered_addresses
FOR EACH ROW EXECUTE FUNCTION node_policy_capture_change('contract','address');
CREATE TRIGGER node_policy_preregistered_addresses_update AFTER UPDATE ON preregistered_addresses
FOR EACH ROW WHEN ((OLD.address, OLD.org_id) IS DISTINCT FROM (NEW.address, NEW.org_id))
EXECUTE FUNCTION node_policy_capture_change('contract','address');

CREATE TRIGGER node_policy_sanctioned_addresses_rows AFTER INSERT OR DELETE ON sanctioned_addresses
FOR EACH ROW EXECUTE FUNCTION node_policy_capture_change('sanctions','address');
CREATE TRIGGER node_policy_sanctioned_addresses_update AFTER UPDATE ON sanctioned_addresses
FOR EACH ROW WHEN ((OLD.org_id, OLD.address) IS DISTINCT FROM (NEW.org_id, NEW.address))
EXECUTE FUNCTION node_policy_capture_change('sanctions','address');

CREATE TRIGGER node_policy_users_truncate AFTER TRUNCATE ON users
FOR EACH STATEMENT EXECUTE FUNCTION node_policy_capture_truncate();
CREATE TRIGGER node_policy_user_memberships_truncate AFTER TRUNCATE ON user_memberships
FOR EACH STATEMENT EXECUTE FUNCTION node_policy_capture_truncate();
CREATE TRIGGER node_policy_eth_address_links_truncate AFTER TRUNCATE ON eth_address_links
FOR EACH STATEMENT EXECUTE FUNCTION node_policy_capture_truncate();
CREATE TRIGGER node_policy_access_policies_truncate AFTER TRUNCATE ON access_policies
FOR EACH STATEMENT EXECUTE FUNCTION node_policy_capture_truncate();
CREATE TRIGGER node_policy_groups_truncate AFTER TRUNCATE ON groups
FOR EACH STATEMENT EXECUTE FUNCTION node_policy_capture_truncate();
CREATE TRIGGER node_policy_group_access_truncate AFTER TRUNCATE ON group_access
FOR EACH STATEMENT EXECUTE FUNCTION node_policy_capture_truncate();
CREATE TRIGGER node_policy_contract_grants_truncate AFTER TRUNCATE ON contract_grants
FOR EACH STATEMENT EXECUTE FUNCTION node_policy_capture_truncate();
CREATE TRIGGER node_policy_contracts_truncate AFTER TRUNCATE ON contracts
FOR EACH STATEMENT EXECUTE FUNCTION node_policy_capture_truncate();
CREATE TRIGGER node_policy_shared_infrastructure_truncate AFTER TRUNCATE ON shared_infrastructure
FOR EACH STATEMENT EXECUTE FUNCTION node_policy_capture_truncate();
CREATE TRIGGER node_policy_preregistered_addresses_truncate AFTER TRUNCATE ON preregistered_addresses
FOR EACH STATEMENT EXECUTE FUNCTION node_policy_capture_truncate();
CREATE TRIGGER node_policy_sanctioned_addresses_truncate AFTER TRUNCATE ON sanctioned_addresses
FOR EACH STATEMENT EXECUTE FUNCTION node_policy_capture_truncate();

REVOKE EXECUTE ON FUNCTION node_policy_bump(), node_policy_record(TEXT, TEXT[]), node_policy_prune(BIGINT) FROM PUBLIC;
DO $$
BEGIN
    -- Both roles write fact tables (the admin role is the incident-response
    -- identity, 058), so both fire the triggers that record changes. Only the
    -- runtime role publishes, so only it prunes.
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'privacy_proxy_app') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE ON node_policy_cursors TO privacy_proxy_app;
        GRANT SELECT ON node_policy_clock, node_policy_changes, node_policy_change_floor TO privacy_proxy_app;
        GRANT EXECUTE ON FUNCTION node_policy_record(TEXT, TEXT[]), node_policy_prune(BIGINT),
            node_policy_mark_dirty(TEXT, TEXT), node_policy_capture_change(),
            node_policy_capture_contract(), node_policy_capture_truncate() TO privacy_proxy_app;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'privacy_proxy_admin') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE ON node_policy_cursors TO privacy_proxy_admin;
        GRANT SELECT ON node_policy_clock, node_policy_changes, node_policy_change_floor TO privacy_proxy_admin;
        GRANT EXECUTE ON FUNCTION node_policy_record(TEXT, TEXT[]), node_policy_prune(BIGINT),
            node_policy_mark_dirty(TEXT, TEXT), node_policy_capture_change(),
            node_policy_capture_contract(), node_policy_capture_truncate() TO privacy_proxy_admin;
    END IF;
END
$$;

---- create above / drop below ----

-- Forward-only: facts and checkpoints must remain reproducible.
