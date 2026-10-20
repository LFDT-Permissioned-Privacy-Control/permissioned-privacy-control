-- Add constructor_abi column to preregistered_addresses
-- This stores the contract ABI (JSON) for constructor argument validation.
-- When a deployment targets a preregistered address, the ABI is used to decode
-- and validate constructor arguments (e.g., immutable address variables).

ALTER TABLE preregistered_addresses ADD COLUMN constructor_abi TEXT;

---- create above / drop below ----

ALTER TABLE preregistered_addresses DROP COLUMN IF EXISTS constructor_abi;
