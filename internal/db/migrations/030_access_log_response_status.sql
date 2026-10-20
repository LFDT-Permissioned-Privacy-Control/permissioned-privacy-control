-- Add response_status column to access_logs for opaque denial tracking.
-- decision status (status_code) records what happened internally (401/403/500).
-- response_status records what the client was told (e.g., 404 for opaque denials).
-- NULL when response matches decision (non-opaque requests).
--
-- hash_format_version tracks the hash chain entry content format so that
-- chain verification can deterministically reconstruct entries across
-- format changes. Version 1 = original format, version 2 = includes response_status.
ALTER TABLE access_logs ADD COLUMN IF NOT EXISTS response_status INTEGER;
ALTER TABLE access_logs ADD COLUMN IF NOT EXISTS hash_format_version SMALLINT;
UPDATE access_logs SET hash_format_version = 1 WHERE hash_format_version IS NULL;
ALTER TABLE access_logs ALTER COLUMN hash_format_version SET NOT NULL;
ALTER TABLE access_logs ALTER COLUMN hash_format_version SET DEFAULT 2;

---- create above / drop below ----

ALTER TABLE access_logs DROP COLUMN IF EXISTS hash_format_version;
ALTER TABLE access_logs DROP COLUMN IF EXISTS response_status;
