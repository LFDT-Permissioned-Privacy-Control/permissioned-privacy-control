-- readonly_admin
ALTER TABLE groups ADD COLUMN is_org_readonly_admin BOOLEAN NOT NULL DEFAULT FALSE;

---- create above / drop below ----

-- Optional: down migration
-- ALTER TABLE groups DROP COLUMN is_org_readonly_admin;
