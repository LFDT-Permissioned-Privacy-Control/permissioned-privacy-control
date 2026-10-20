-- Add auth_tenant_id to users so we can revoke sessions when an Azure AD tenant is removed.
-- NULL for Privado users (no tenant concept).

ALTER TABLE users ADD COLUMN IF NOT EXISTS auth_tenant_id TEXT;
CREATE INDEX IF NOT EXISTS idx_users_auth_tenant_id ON users (auth_tenant_id) WHERE auth_tenant_id IS NOT NULL;

---- create above / drop below ----

ALTER TABLE users DROP COLUMN IF EXISTS auth_tenant_id;
