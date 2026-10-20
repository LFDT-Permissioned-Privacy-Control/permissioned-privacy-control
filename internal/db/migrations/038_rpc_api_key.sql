-- Add RPC API key to group_access for upstream RPC proxy authentication.
-- When set, this key is attached as a Bearer token to requests forwarded
-- to the RPC proxy, enabling per-group rate limiting on the proxy side.
ALTER TABLE group_access ADD COLUMN rpc_api_key TEXT;

---- create above / drop below ----

ALTER TABLE group_access DROP COLUMN IF EXISTS rpc_api_key;
