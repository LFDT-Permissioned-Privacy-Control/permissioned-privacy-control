-- Opt-in verbose RPC errors per group (RD-1137, Part A).
--
-- WHAT: add a boolean verbose_errors flag to group_access (default false).
--
-- WHY (RD-1137 Part A): client automations can't branch on the proxy's opaque
-- denial messages. When a caller's group has this flag set, processor-
-- originated denials carry a curated, stable machine-readable reason code
-- (the same taxonomy stored in access_logs.denial_reason — RD-1137 Part B) as
-- a `reason` field alongside the (unchanged) opaque `error` message. Default
-- OFF: every caller stays fully opaque exactly as today.
--
-- SECURITY: this re-opens, for opted-in callers only, the opaque-error surface
-- hardened in RD-934. The wire layer applies an oracle-collapse: cross-org /
-- trace-reachability reason codes are reduced to a single generic value even
-- when verbose, so the feature never reveals another tenant's state. Toggling
-- this flag is an RBAC-relevant change and is recorded in rbac_audit_log by the
-- application (NOT from this migration).
--
-- AFFECTED: all existing group_access rows get verbose_errors = false (NOT
-- NULL DEFAULT false) — i.e. no behavior change until an admin opts a group in.
--
-- GRANTS: none needed — the privacy_proxy_app grant on group_access is
-- table-level and covers new columns.
--
-- EXPAND-ONLY: additive (ADD COLUMN). Not a hash-chained table; no chain
-- considerations.

ALTER TABLE group_access
ADD COLUMN IF NOT EXISTS verbose_errors BOOLEAN NOT NULL DEFAULT false;

---- create above / drop below ----

ALTER TABLE group_access DROP COLUMN IF EXISTS verbose_errors;
