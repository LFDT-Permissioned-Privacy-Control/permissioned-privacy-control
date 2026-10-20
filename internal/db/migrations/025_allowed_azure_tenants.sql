-- Allowed Azure AD tenants: controls which Azure AD tenants can authenticate.
-- Authentication (who are you?) is separate from authorization (what can you access?).
-- Tenant -> default org/group mapping provides initial placement, not hard binding.
CREATE TABLE IF NOT EXISTS allowed_azure_tenants (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id TEXT NOT NULL UNIQUE,
    label TEXT NOT NULL DEFAULT '',
    default_org_id UUID REFERENCES organizations(id) ON DELETE SET NULL,
    default_group_id UUID REFERENCES groups(id) ON DELETE SET NULL,
    auto_provision BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

---- create above / drop below ----

DROP TABLE IF EXISTS allowed_azure_tenants;
