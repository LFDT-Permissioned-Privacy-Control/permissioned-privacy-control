-- Add event_rules JSONB column to contract_grants for ABI-based log filtering.
-- Analogous to the existing functions JSONB column.
-- When NULL: all events visible (backward compat).
-- When set: allowlist of events by topic0, with optional param_rules for "self" constraints.

ALTER TABLE contract_grants ADD COLUMN event_rules JSONB;

-- Flush effective_permissions_cache since ContractAccess now includes event_rules
DELETE FROM effective_permissions_cache;

---- create above / drop below ----

ALTER TABLE contract_grants DROP COLUMN IF EXISTS event_rules;
