-- Drop the deprecated claims column from contract_grants.
-- Claims are now inherited from the group's GroupAccess.claims.

ALTER TABLE contract_grants DROP COLUMN IF EXISTS claims;

---- create above / drop below ----

-- DOWN: Re-add claims column (for development rollback only)
ALTER TABLE contract_grants ADD COLUMN claims TEXT[] NOT NULL DEFAULT '{}';
