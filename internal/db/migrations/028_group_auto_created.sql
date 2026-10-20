-- Migration 028: Add auto_created flag to groups
-- Tracks groups that were automatically created by deployer auto-grants,
-- enabling batch management operations (move contracts, delete empty groups).

ALTER TABLE groups ADD COLUMN auto_created BOOLEAN NOT NULL DEFAULT false;

-- Backfill: groups with slugs matching the deployer auto-grant pattern (deploy-<uuid>)
UPDATE groups SET auto_created = true WHERE slug LIKE 'deploy-%';

-- Index for filtering by auto_created within an org
CREATE INDEX idx_groups_auto_created ON groups (org_id, auto_created);

---- create above / drop below ----

DROP INDEX IF EXISTS idx_groups_auto_created;
ALTER TABLE groups DROP COLUMN IF EXISTS auto_created;
