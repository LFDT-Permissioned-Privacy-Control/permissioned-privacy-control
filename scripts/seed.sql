-- Seed data for Open Privacy Suite development
-- Run with: make seed

-- Clear existing policies (for clean re-seeding)
TRUNCATE TABLE access_policies CASCADE;

-- Dashboard test identity (used by the test request panel)
INSERT INTO access_policies (external_id, kyc, allow_methods, banned, note)
VALUES (
    'test:dashboard',
    true,
    '["eth_blockNumber", "eth_chainId", "eth_gasPrice", "eth_getBalance", "eth_getBlockByNumber", "eth_getBlockByHash", "eth_getTransactionByHash", "eth_getTransactionReceipt", "eth_call", "eth_estimateGas", "eth_getLogs", "net_version"]'::jsonb,
    false,
    'Dashboard test identity - full read access'
);

-- Example DID identities for development/testing
INSERT INTO access_policies (external_id, kyc, allow_methods, banned, note)
VALUES (
    'did:privado:example:alice',
    true,
    '["eth_blockNumber", "eth_chainId", "eth_gasPrice", "eth_getBalance", "eth_call"]'::jsonb,
    false,
    'Example user Alice - basic read access'
);

INSERT INTO access_policies (external_id, kyc, allow_methods, banned, note)
VALUES (
    'did:privado:example:bob',
    true,
    '["eth_blockNumber", "eth_chainId"]'::jsonb,
    false,
    'Example user Bob - minimal access'
);

-- Example banned user
INSERT INTO access_policies (external_id, kyc, allow_methods, banned, note)
VALUES (
    'did:privado:example:banned',
    true,
    '["eth_blockNumber"]'::jsonb,
    true,
    'Example banned user'
);

-- Example user without KYC (will be denied)
INSERT INTO access_policies (external_id, kyc, allow_methods, banned, note)
VALUES (
    'did:privado:example:no-kyc',
    false,
    '["eth_blockNumber", "eth_chainId"]'::jsonb,
    false,
    'Example user without KYC verification'
);

-- Confirm seeded data
SELECT external_id, kyc, banned, note FROM access_policies ORDER BY created_at;
