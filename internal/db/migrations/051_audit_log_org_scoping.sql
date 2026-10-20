-- Cross-org scoping for the RBAC audit log (security audit H1).
--
-- Pre-fix, listAuditLogs returned every entry across every org for a
-- given resource_type / actor_id query. A tier-2 admin could read
-- mutations from any tenant. Add org_id so the list handler can
-- filter at the SQL level.
--
-- Pre-existing rows have NULL org_id — they are visible only to
-- super-admin (X-Admin-Token) callers. New writes will populate the
-- column; the application's recordAuditAction helper passes the
-- resource's parent org.

ALTER TABLE rbac_audit_log
ADD COLUMN org_id TEXT NULL;

CREATE INDEX IF NOT EXISTS idx_rbac_audit_log_org_id
ON rbac_audit_log (org_id);

CREATE INDEX IF NOT EXISTS idx_rbac_audit_log_org_created
ON rbac_audit_log (org_id, created_at DESC);
