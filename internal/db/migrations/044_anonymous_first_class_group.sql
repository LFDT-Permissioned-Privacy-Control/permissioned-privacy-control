-- RD-870: promote anonymous (no-JWT) access from a hardcoded code branch to a
-- first-class RBAC group whose `allowed_methods` and `claims` are configurable
-- in the DB. The access path no longer carries an implicit metadata-only
-- allowlist; instead it loads the anonymous group's group_access row.
--
-- This migration:
--   1. Adds `is_system BOOLEAN NOT NULL DEFAULT false` to organizations and
--      groups. System rows are immutable identity-wise (slug/rename/delete
--      blocked); their group_access permissions are editable by super admins
--      (X-Admin-Token) only.
--   2. Inserts an `anonymous` org and `anonymous` group, both is_system=true,
--      with deterministic UUIDs distinct from the existing default org/group
--      (which use ...-0000-0001).
--   3. Inserts the anonymous group's group_access row with the same six
--      claim-free metadata methods that were hardcoded in
--      internal/rbac/access.go's `req.UserExternalID == ""` branch, and an
--      empty `claims` array. Behavior is preserved exactly; the rules just
--      live in a configurable row now.

-- 1. Schema: is_system flag.
ALTER TABLE organizations ADD COLUMN is_system BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE groups        ADD COLUMN is_system BOOLEAN NOT NULL DEFAULT false;

-- 2. Anonymous org and group.
INSERT INTO organizations (id, slug, name, settings, is_system)
VALUES (
    '00000000-0000-0000-0000-000000000002',
    'anonymous',
    'Anonymous',
    '{}'::jsonb,
    true
)
ON CONFLICT (slug) DO NOTHING;

INSERT INTO groups (id, org_id, parent_id, slug, name, description, depth, path, is_system)
VALUES (
    '00000000-0000-0000-0000-000000000002',
    '00000000-0000-0000-0000-000000000002',
    NULL,
    'anonymous',
    'Anonymous',
    'Permissions for unauthenticated (no-JWT) requests. Edits restricted to super admin (X-Admin-Token).',
    0,
    'anonymous',
    true
)
ON CONFLICT (org_id, slug) DO NOTHING;

-- 3. Anonymous group's access config — pinned to the historical hardcoded
-- behavior (the six claim-free metadata methods). Empty claims means no
-- admin/upgrade/deploy gate-bearing claims, so writes/deploys against
-- registered or unregistered contracts remain denied.
INSERT INTO group_access (id, group_id, allowed_methods, claims)
VALUES (
    '00000000-0000-0000-0000-000000000002',
    '00000000-0000-0000-0000-000000000002',
    ARRAY[
        'eth_blockNumber',
        'eth_chainId',
        'eth_gasPrice',
        'net_version',
        'net_listening',
        'web3_clientVersion'
    ],
    ARRAY[]::TEXT[]
)
ON CONFLICT (group_id) DO NOTHING;

---- create above / drop below ----

-- Down migration is dev-only (per CLAUDE.md expand-only policy). Provided so
-- local iteration can rewind cleanly.
DELETE FROM group_access  WHERE group_id = '00000000-0000-0000-0000-000000000002';
DELETE FROM groups        WHERE id       = '00000000-0000-0000-0000-000000000002';
DELETE FROM organizations WHERE id       = '00000000-0000-0000-0000-000000000002';

ALTER TABLE groups        DROP COLUMN IF EXISTS is_system;
ALTER TABLE organizations DROP COLUMN IF EXISTS is_system;
