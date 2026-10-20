-- Change request_params from JSONB to TEXT so the exact bytes used in
-- the hash chain entry are preserved on round-trip. JSONB does not
-- guarantee key ordering or whitespace preservation, which makes hash
-- chain verification from DB state non-deterministic.
ALTER TABLE access_logs ALTER COLUMN request_params TYPE TEXT;

---- create above / drop below ----

ALTER TABLE access_logs ALTER COLUMN request_params TYPE JSONB USING request_params::jsonb;
