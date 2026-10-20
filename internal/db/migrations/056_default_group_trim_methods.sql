-- RD-877: trim default group allowed_methods to metadata-only and remove the
-- implicit "default org" fallback from the access layer.
--
-- The default group is a limbo state: any authenticated user who has not yet
-- been assigned to a real org group lands here (Privado/ZK login, Azure AD
-- login when the tenant has no DefaultGroupID configured). Granting it 27
-- broad RPC methods (eth_getBalance, eth_call, eth_sendTransaction, etc.) was
-- unintentional — it allowed default-group users to query unregistered EOA
-- balances and send EOA-to-EOA value transfers without ever being assigned to
-- an org. Access-layer checks (CheckDefaultClaimsAllowed, isBasicAddressQuery)
-- kept registered contracts safe, but the implicit latitude was wider than
-- necessary for a holding state.
--
-- Trimmed to the same six claim-free metadata methods as the anonymous group:
-- enough to verify the chain is reachable, nothing that touches user state.
-- Access to any real resource requires an explicit org group assignment.
UPDATE group_access
SET allowed_methods = ARRAY[
    'eth_blockNumber',
    'eth_chainId',
    'eth_gasPrice',
    'net_version',
    'net_listening',
    'web3_clientVersion'
]
WHERE group_id = '00000000-0000-0000-0000-000000000001';

---- create above / drop below ----

UPDATE group_access
SET allowed_methods = ARRAY[
    'eth_blockNumber', 'eth_chainId', 'eth_gasPrice',
    'eth_getBalance', 'eth_getBlockByHash', 'eth_getBlockByNumber',
    'eth_getCode', 'eth_getStorageAt', 'eth_getTransactionByHash',
    'eth_getTransactionCount', 'eth_getTransactionReceipt',
    'eth_call', 'eth_estimateGas', 'eth_sendRawTransaction',
    'eth_sendTransaction', 'eth_getLogs',
    'eth_getBlockTransactionCountByHash', 'eth_getBlockTransactionCountByNumber',
    'eth_getUncleCountByBlockHash', 'eth_getUncleCountByBlockNumber',
    'eth_protocolVersion', 'eth_syncing',
    'net_version', 'net_listening', 'net_peerCount',
    'web3_clientVersion', 'web3_sha3'
]
WHERE group_id = '00000000-0000-0000-0000-000000000001';
