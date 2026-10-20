-- 060_org_admin_group_invariants.sql
-- RD-968: enforce the org-admin group invariants that were previously only
-- implied by UI conventions, and normalize existing rows that violate them.
--
-- Three coupled footguns shared one root cause: the "org admin" abstraction maps
-- to three independent fields (groups.is_org_admin, groups.is_org_readonly_admin,
-- group_access.claims) and nothing enforced their coupling. This migration closes
-- the data-model half; the API layer (internal/server/admin_rbac_group.go) enforces
-- the same invariants on every write going forward.
--
-- ── WHAT THIS MIGRATION DOES ─────────────────────────────────────────────────
--   1. Clears is_org_readonly_admin on any group that ALSO has is_org_admin.
--      A group cannot be both "full org admin" and "read-only org admin".
--      Full-admin dominates: is_org_readonly_admin only gates admin-dashboard read
--      access, never the RBAC engine, so clearing it changes no effective permission.
--      (Required BEFORE the CHECK constraint below, or the ALTER would fail to validate.)
--   2. Clears group_access.claims on org-admin groups. Claims are dead data there:
--      computeOrgAdminPermissions (internal/rbac/resolver.go) hard-codes AllClaims()
--      for org-admin members regardless of this field, and explorer visibility
--      (GetBatchVisibility) keys off the is_org_admin flag / contract_grants.claims,
--      NEVER group_access.claims. Clearing removes a misleading stored value with
--      zero functional effect (see REDACTION_SPEC.md "VisibilityFull" paths).
--   3. Adds CHECK (NOT (is_org_admin AND is_org_readonly_admin)) as a DB-level
--      backstop to the API-level 400. Defense in depth: no code path (or direct
--      SQL) can reintroduce the contradictory state.
--
-- ── WHAT IT DELIBERATELY DOES NOT DO ─────────────────────────────────────────
--   It does NOT touch group_access.allowed_methods. An org-admin group with an
--   empty method list is non-functional (Gap 3), but the fix is forward enforcement
--   (admin_rbac_group.go rejects an empty allowed_methods save for org-admin groups,
--   400) plus the UI requiring a method preset -- NOT a silent backfill here. The
--   RBAC spec (site/src/app/docs/rbac) makes the method allowlist the source of truth
--   even for org admins (they receive all CLAIMS on all CONTRACTS, not all METHODS),
--   so auto-granting methods would over-grant. Existing offenders are left
--   fail-closed (members can call nothing) until an admin sets methods explicitly.
--
--   Detection query for existing offenders (run post-migration; fix via the dashboard):
--     SELECT g.org_id, g.id, g.slug
--     FROM groups g
--     JOIN group_access ga ON ga.group_id = g.id
--     WHERE g.is_org_admin
--       AND (ga.allowed_methods IS NULL OR array_length(ga.allowed_methods, 1) IS NULL);
--
-- ── AUTHORITATIVE RECORD / AUDIT ─────────────────────────────────────────────
--   This migration rewrites security-relevant rows. Per the audit model
--   (site/src/app/docs/security/audit-integrity), rbac_audit_log is the runtime,
--   actor-attributed, hash-chained trail and is deliberately NOT written from
--   migrations: a SQL INSERT with a wrong/absent entry_hash would trip the integrity
--   Verifier's tamper alarm. The authoritative change-management record for this
--   data normalization is THIS file (git history) + the PR (RD-968, code review) +
--   tern's schema_version table (applied-at timestamp). Self-explanatory, no magic.
--
-- ── ROLE-SEPARATION (RD-858) CHECK ───────────────────────────────────────────
--   No new table is created here, so no privacy_proxy_app GRANT block is required
--   (see migration 058's new-table checklist). Migrations run as privacy_proxy_admin.
--
-- ── EXPAND-ONLY ──────────────────────────────────────────────────────────────
--   ADD CONSTRAINT is additive (allowed). The UPDATEs are data normalization, not
--   schema drops. The DOWN section drops only the constraint -- the data cleanups
--   are forward-only (prior per-row flag/claims state is not recoverable and is
--   intentionally not restored).

UPDATE groups
SET is_org_readonly_admin = false
WHERE is_org_admin = true
  AND is_org_readonly_admin = true;

UPDATE group_access ga
SET claims = '{}'
FROM groups g
WHERE ga.group_id = g.id
  AND g.is_org_admin = true
  AND array_length(ga.claims, 1) IS NOT NULL;

ALTER TABLE groups
    ADD CONSTRAINT groups_admin_role_exclusive
    CHECK (NOT (is_org_admin AND is_org_readonly_admin));

---- create above / drop below ----

ALTER TABLE groups DROP CONSTRAINT IF EXISTS groups_admin_role_exclusive;
