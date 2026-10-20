-- Governance approver groups: designate which groups can approve governance requests.
-- When no approver groups are configured, any org admin can approve (backward compatible).
CREATE TABLE governance_approver_groups (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    group_id UUID NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(org_id, group_id)
);

CREATE INDEX idx_governance_approver_groups_org ON governance_approver_groups(org_id);

---- create above / drop below ----

DROP TABLE governance_approver_groups;
