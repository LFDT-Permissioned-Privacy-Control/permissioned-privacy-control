-- Rename default_claims to claims in group_access and effective_permissions_cache
-- This reflects the simplified RBAC model where groups have claims (capabilities)
-- that apply to both registered contracts (via grants) and public contracts.

-- Rename in group_access table
ALTER TABLE group_access RENAME COLUMN default_claims TO claims;

-- Rename in effective_permissions_cache table
ALTER TABLE effective_permissions_cache RENAME COLUMN default_claims TO claims;

---- create above / drop below ----

-- Revert: rename back to default_claims
ALTER TABLE group_access RENAME COLUMN claims TO default_claims;
ALTER TABLE effective_permissions_cache RENAME COLUMN claims TO default_claims;
