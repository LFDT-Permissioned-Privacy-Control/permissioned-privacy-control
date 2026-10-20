-- Add per-group override for the HTTP header name used to send the upstream
-- RPC API key. Default "Authorization" preserves the existing Bearer behaviour;
-- any other value (e.g. "X-API-Key") sends the API key raw under that header.
-- Header name only — the actual key value continues to live in rpc_api_key
-- (which is encrypted at rest when RPC_API_KEY_ENCRYPTION_KEY is configured).
ALTER TABLE group_access ADD COLUMN rpc_api_key_header VARCHAR(64) NOT NULL DEFAULT 'Authorization';

---- create above / drop below ----

ALTER TABLE group_access DROP COLUMN IF EXISTS rpc_api_key_header;
