-- Denial-reason attribution for the access log (RD-1137, Part B).
--
-- WHAT: add a nullable denial_reason column to access_logs holding a curated,
-- stable reason code for denied requests (e.g. sender_not_linked, cross_org,
-- method_not_allowed). NULL for successful or unclassified requests.
--
-- WHY (RD-1137): today the access log records only the status code, and the
-- real reason a request was denied lives in slog/stdout (operator-only). Org
-- admins viewing the Access Logs panel (RD-1135) can see THAT a request was
-- denied but not WHY — so they cannot self-diagnose tenant issues (the worked
-- example: "call denied: invalid request shape" was really "sender address not
-- linked"). This column surfaces a tenant-safe reason in the admin panel. The
-- companion status-code fix (logging the real status instead of a hardcoded
-- 403 for trace denials) ships in the same change.
--
-- AFTER (RD-1137 Part A, separate change): the same curated reason is what an
-- opt-in (group-flagged) caller may receive on the wire. The wire path applies
-- an oracle-collapse step; this column always stores the precise reason for the
-- org-scoped admin view.
--
-- AFFECTED: pre-existing rows have NULL denial_reason (no backfill — the reason
-- was never captured). New denials populate it.
--
-- HASH CHAIN: denial_reason is NOT part of the entry_hash (chain content
-- AccessLogChainContentV2 + verifier SELECT unchanged), so hash_format_version
-- stays 2 and existing rows verify byte-for-byte. Same posture as org_id
-- (migration 065): a read-side attribute, not an integrity field. No write to
-- the hash chain from this migration.
--
-- GRANTS: none needed — the privacy_proxy_app grant on access_logs is
-- table-level (migration 058) and covers new columns.
--
-- EXPAND-ONLY: additive (ADD COLUMN).

ALTER TABLE access_logs
ADD COLUMN IF NOT EXISTS denial_reason TEXT NULL;

---- create above / drop below ----

ALTER TABLE access_logs DROP COLUMN IF EXISTS denial_reason;
