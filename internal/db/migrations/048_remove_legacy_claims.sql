-- RD-853: remove legacy 'read' and 'write' claim values.
--
-- These claims are no longer enforced anywhere in the backend (see
-- internal/rbac/models.go) — the only gating claims are 'admin',
-- 'upgrade', and 'deploy'. Strip the dead values from any rows that
-- still carry them so DB content matches code intent.
--
-- The columns themselves stay (TEXT[]); we only filter the values.
-- Idempotent: array_remove on a value that isn't present is a no-op.

UPDATE group_access
SET claims = array_remove(array_remove(claims, 'read'), 'write')
WHERE 'read' = ANY(claims) OR 'write' = ANY(claims);

UPDATE contract_grants
SET claims = array_remove(array_remove(claims, 'read'), 'write')
WHERE 'read' = ANY(claims) OR 'write' = ANY(claims);

UPDATE effective_permissions_cache
SET claims = array_remove(array_remove(claims, 'read'), 'write')
WHERE 'read' = ANY(claims) OR 'write' = ANY(claims);

---- create above / drop below ----

-- No-op: legacy values are dead. DOWN is dev-only and we cannot
-- reconstruct which rows previously carried 'read'/'write'.
SELECT 1;
