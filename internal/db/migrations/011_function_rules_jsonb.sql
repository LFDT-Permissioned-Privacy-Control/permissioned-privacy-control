-- Convert contract_grants.functions from TEXT[] to JSONB for structured function rules
-- with optional parameter constraints.

-- Step 1: Add new JSONB column
ALTER TABLE contract_grants ADD COLUMN functions_jsonb JSONB;

-- Step 2: Migrate existing TEXT[] data to JSONB format
-- Converts {'0x70a08231','0xa9059cbb'} to [{"selector":"0x70a08231"},{"selector":"0xa9059cbb"}]
UPDATE contract_grants
SET functions_jsonb = (
    SELECT jsonb_agg(jsonb_build_object('selector', elem))
    FROM unnest(functions) AS elem
)
WHERE functions IS NOT NULL AND array_length(functions, 1) > 0;

-- Step 3: Drop old column and rename
ALTER TABLE contract_grants DROP COLUMN functions;
ALTER TABLE contract_grants RENAME COLUMN functions_jsonb TO functions;

-- Flush effective_permissions_cache since ContractAccess.Functions format changed
DELETE FROM effective_permissions_cache;

---- create above / drop below ----

-- DOWN: Convert JSONB back to TEXT[]
ALTER TABLE contract_grants ADD COLUMN functions_old TEXT[];
UPDATE contract_grants
SET functions_old = (
    SELECT array_agg(elem->>'selector')
    FROM jsonb_array_elements(functions) AS elem
)
WHERE functions IS NOT NULL;
ALTER TABLE contract_grants DROP COLUMN functions;
ALTER TABLE contract_grants RENAME COLUMN functions_old TO functions;
