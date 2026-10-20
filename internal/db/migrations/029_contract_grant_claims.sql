-- Migration 029: Re-add claims column to contract_grants
-- The claims column was dropped in migration 010 when claims moved to group_access.
-- However, explorer visibility filtering (GetBatchVisibility) needs per-grant claims
-- to distinguish admin-level grants from read-only grants. Only groups with
-- is_org_admin=true OR 'admin' in their contract_grant claims should see VisibilityFull.

ALTER TABLE contract_grants ADD COLUMN claims TEXT[] NOT NULL DEFAULT '{}';

---- create above / drop below ----

ALTER TABLE contract_grants DROP COLUMN IF EXISTS claims;
