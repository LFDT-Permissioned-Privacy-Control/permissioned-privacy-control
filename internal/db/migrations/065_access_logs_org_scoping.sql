-- Cross-org scoping for the access log (RD-1135).
--
-- WHAT: add a nullable org_id column (+ supporting indexes) to access_logs
-- so the admin /api/v1/admin/logs handler can filter rows to the caller's
-- own organization(s).
--
-- WHY (RD-1135): pre-fix, getLogs returned the FLEET-WIDE access log to any
-- authenticated admin, including tier-2 org admins (Bearer JWT with the
-- admin claim). access_logs had no org column, so an org-A admin could read
-- org-B's request history (external_id/method/status/ip/timestamp). This is
-- the same cross-org-isolation gap that migration 051 closed for
-- rbac_audit_log; this migration applies the identical pattern to
-- access_logs. The application's request processor now stamps the org the
-- entry-point access decision resolved against (AccessCheckResult.OrgID)
-- onto each new row.
--
-- AFFECTED: pre-existing rows have NULL org_id. They are NOT back-filled
-- (forward-only, by product decision) and are therefore visible only to
-- super-admin (X-Admin-Token) callers — tenant org admins see rows from
-- this migration forward. Historical rows that remain unattributed:
--     SELECT count(*) FROM access_logs WHERE org_id IS NULL;
--
-- AUTHORITATIVE RECORD: this migration file (git) + PR review + tern
-- schema_version (applied-at) is the traceable record. No backfill, and
-- crucially NO write to the access_logs hash chain from this migration:
-- access_logs is a tamper-evident, hash-chained audit table and a
-- migration-issued INSERT/UPDATE with a wrong/absent entry_hash would trip
-- the integrity verifier. ADD COLUMN does not touch existing rows' content
-- or their entry_hash.
--
-- HASH CHAIN: org_id is intentionally NOT part of the entry_hash. The chain
-- content (AccessLogChainContentV2) and the verifier's SELECT list are
-- unchanged, so hash_format_version stays 2 and existing rows continue to
-- verify byte-for-byte. org_id is a confidentiality-scoping attribute for
-- reads, not an integrity-protected field (a DB-write attacker who could
-- alter it can already read every row directly). If org_id ever needs to be
-- tamper-evident, that is a separate V3 format bump (see rbac_audit_log,
-- which does hash its org_id).
--
-- GRANTS: no GRANT change. The privacy_proxy_app grant on access_logs is
-- table-level (migration 058), which covers new columns automatically.
--
-- EXPAND-ONLY: additive (ADD COLUMN + CREATE INDEX). Role-separation
-- unchanged.
--
-- INDEXES: created here to match migration 051. On a very large existing
-- access_logs table a non-concurrent build briefly locks writes; operators
-- of such deployments may prefer to pre-build these CONCURRENTLY out-of-band
-- before applying. New/PoC deployments are unaffected.

ALTER TABLE access_logs
ADD COLUMN IF NOT EXISTS org_id TEXT NULL;

CREATE INDEX IF NOT EXISTS idx_access_logs_org_id
ON access_logs (org_id);

CREATE INDEX IF NOT EXISTS idx_access_logs_org_created
ON access_logs (org_id, created_at DESC);

---- create above / drop below ----

DROP INDEX IF EXISTS idx_access_logs_org_created;
DROP INDEX IF EXISTS idx_access_logs_org_id;
ALTER TABLE access_logs DROP COLUMN IF EXISTS org_id;
