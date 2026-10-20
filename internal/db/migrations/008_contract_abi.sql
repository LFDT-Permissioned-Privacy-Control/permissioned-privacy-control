-- Add ABI column to contracts table
-- This stores the contract's ABI JSON for function-level access control

ALTER TABLE contracts ADD COLUMN abi TEXT;

---- create above / drop below ----

ALTER TABLE contracts DROP COLUMN IF EXISTS abi;
