-- Enforce that group display names are unique within an organization
-- (case-insensitive). Two groups in the same org with the same name made
-- the Users tab ambiguous — group chips show only the name, so members
-- of "Auditors" #1 vs "Auditors" #2 looked identical.
--
-- Step 1 dedupes any pre-existing duplicates by appending the slug to the
-- non-canonical rows ("Auditors" + slug "rd866-auditors-1778085638"
-- becomes "Auditors (rd866-auditors-1778085638)"). The lexicographically
-- smallest slug per (org_id, lower(name)) cluster keeps its original
-- name; the rest get disambiguated.
--
-- Step 2 creates the unique index. With duplicates resolved in step 1,
-- this is safe to run on populated databases.

UPDATE groups g
SET name = g.name || ' (' || g.slug || ')',
    updated_at = CURRENT_TIMESTAMP
WHERE EXISTS (
    SELECT 1 FROM groups g2
    WHERE g2.org_id = g.org_id
      AND lower(g2.name) = lower(g.name)
      AND g2.slug < g.slug
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_groups_org_name_unique
    ON groups(org_id, lower(name));

---- create above / drop below ----

DROP INDEX IF EXISTS idx_groups_org_name_unique;

-- Note: we do NOT undo the slug-suffix renames in DOWN. Recovering the
-- original names would require remembering which row was the canonical
-- one before step 1 ran. DOWN migrations are dev-only per CLAUDE.md;
-- production rollback is via a new forward migration.
