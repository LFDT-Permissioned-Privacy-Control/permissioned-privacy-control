-- KD-1 self-review hardening: shared_infrastructure.address is the
-- table's natural key and was never declared UNIQUE.
--
-- Pre-fix, two concurrent admin POSTs racing for the same address
-- could both pass the "does it already exist?" check in
-- createSharedInfrastructure and both INSERT, leaving two rows for
-- the same address. The trace validator's IsSharedInfrastructure
-- read returns the first hit (or whatever the planner happens to
-- pick) — both rows have the same trust meaning so it's not a
-- security gap, but it's an operational footgun (which of the two
-- gets PUT/DELETE'd? whoever the planner picks). The audit-log
-- entry for the second create is also confusing.
--
-- Defense in depth: making the column UNIQUE closes the race and
-- relies on Postgres to enforce the invariant the application
-- already assumes. Pre-existing duplicates are collapsed: keep the
-- earliest-created row (the original trust attestation) and drop
-- the rest. The earliest row's codehash, name, description survive.
--
-- The existing dev-mode addresses (none seeded by default) and any
-- prod entries are unaffected unless duplicates exist.

DELETE FROM shared_infrastructure a
USING shared_infrastructure b
WHERE a.created_at > b.created_at
  AND LOWER(a.address) = LOWER(b.address);

ALTER TABLE shared_infrastructure
ADD CONSTRAINT shared_infrastructure_address_key UNIQUE (address);
