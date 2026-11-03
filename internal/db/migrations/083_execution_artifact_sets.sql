-- WHAT: retain the complete per-group compiler output on an execution revision.
-- WHY: one organization document is reviewed and activated atomically, while
-- each group's bytecode must fit independently within the runtime size limit.
-- AFFECTED ROWS: no policies are rebuilt or changed. NULL identifies an existing
-- approved organization-wide artifact. New grouped projections store the whole
-- set, including every digest, in the same transaction as activation and audit.
-- AUTHORITATIVE RECORD: immutable configuration revision, reviewed artifact set,
-- actor-attributed activation audit, this migration and tern schema_version.
-- EXPAND-ONLY / ROLE SEPARATION: additive column; existing table grants and the
-- configuration projection writer guard apply. No audit-table writes here.
-- FACT CLOCK (RD-1411, rewritten in place: V2 is not deployed): the node fact
-- triggers on execution_policy_revisions are created here, once artifact_set
-- exists, because the export reads it (075 creates the clock and the other
-- tables' triggers). Only active images count: a draft bumps nothing.
-- Detection: SELECT org_id,revision FROM execution_policy_revisions
-- WHERE status='active' AND artifact_set IS NULL;

ALTER TABLE execution_policy_revisions ADD COLUMN artifact_set JSONB
    CHECK (artifact_set IS NULL OR jsonb_typeof(artifact_set) = 'object');

CREATE TRIGGER node_policy_execution_policy_revisions_rows AFTER INSERT OR DELETE ON execution_policy_revisions
FOR EACH ROW EXECUTE FUNCTION node_policy_capture_change('policy','org_id');
CREATE TRIGGER node_policy_execution_policy_revisions_update AFTER UPDATE ON execution_policy_revisions
FOR EACH ROW WHEN ((OLD.org_id, OLD.revision, OLD.policy_digest, OLD.runtime_digest, OLD.runtime_bytecode, OLD.artifact_set, OLD.status)
    IS DISTINCT FROM (NEW.org_id, NEW.revision, NEW.policy_digest, NEW.runtime_digest, NEW.runtime_bytecode, NEW.artifact_set, NEW.status))
EXECUTE FUNCTION node_policy_capture_change('policy','org_id');
CREATE TRIGGER node_policy_execution_policy_revisions_truncate AFTER TRUNCATE ON execution_policy_revisions
FOR EACH STATEMENT EXECUTE FUNCTION node_policy_capture_truncate();

---- create above / drop below ----

-- Forward-only: preserve approved artifact evidence.
