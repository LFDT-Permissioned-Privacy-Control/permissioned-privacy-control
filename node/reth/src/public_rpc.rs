//! The public JSON-RPC server's guard. A public method that would replay a
//! block or transaction through the guarded executor (and so re-verify a
//! block's whole evidence for an anonymous caller), or build blocks, is
//! refused by name with one fixed error before any work.
//!
//! Applied as Reth's RPC middleware, which wraps the public HTTP and WS
//! servers (not the authenticated engine API, and not IPC, which the node
//! forces off). The refused methods are also removed from every configured
//! transport, and the node refuses to start when any public transport would
//! serve a method nobody reviewed (`guard_configured`), so a Reth upgrade that
//! adds a method fails closed. The modules that replay, trace, validate or
//! build blocks as a whole (`debug`, `trace`, `ots`, `flashbots`, `mev`,
//! `testing`) are refused at startup instead.

use jsonrpsee::{
    MethodResponse,
    core::middleware::{
        Batch, BatchEntry, BatchEntryErr, Notification, ResponseFuture, RpcServiceT,
    },
    types::{ErrorObject, Request},
};
use reth_ethereum::rpc::builder::TransportRpcModules;
use std::{collections::BTreeSet, future::Future};

/// Every public method of the modules the node still serves (`eth`, `net`,
/// `web3`, `txpool`, `admin`, `rpc`, `reth`, `miner`) that reaches the block
/// executor or block building, in Reth v2.5.2 (`5a6940e`). Re-check this
/// list whenever the Reth pin changes.
/// - `eth_callMany`: with a `transactionIndex` inside the block, replays the
///   block's earlier transactions through the block executor.
/// - `eth_getBlockAccessList*`: re-executes the whole block through it.
/// - `eth_simulateV1`: builds candidate blocks (also off: its block limit is
///   forced to 0).
/// - `reth_getBlockExecutionOutcome`: re-executes up to 128 blocks.
pub const REFUSED_METHODS: [&str; 7] = [
    "eth_callMany",
    "eth_getBlockAccessList",
    "eth_getBlockAccessListByBlockHash",
    "eth_getBlockAccessListByBlockNumber",
    "eth_getBlockAccessListRaw",
    "eth_simulateV1",
    "reth_getBlockExecutionOutcome",
];

/// The refusal: JSON-RPC "method not found / not available".
pub const REFUSED_CODE: i32 = -32601;
pub const REFUSED_MESSAGE: &str = "method not available on the guarded node";

/// Every other public method the pinned Reth registers for the modules the
/// node serves, each reviewed to never reach the block executor or block
/// building: calls (`eth_call`, `eth_estimateGas`, `eth_createAccessList`,
/// `eth_fillTransaction`, `eth_callBundle`) run on the unauthenticated policy
/// context, which cannot execute guarded code. Some change node settings or
/// the pool (`admin_*`, `miner_*`, `reth_jit`, transaction submission); which
/// modules to expose publicly is the operator's choice. A new method must be
/// reviewed before it is added here.
pub const REVIEWED_METHODS: [&str; 98] = [
    "admin_addPeer",
    "admin_addTrustedPeer",
    "admin_banPeer",
    "admin_clearTxpool",
    "admin_nodeInfo",
    "admin_peerEvents",
    "admin_peerEvents_unsubscribe",
    "admin_peers",
    "admin_removePeer",
    "admin_removeTrustedPeer",
    "admin_unbanPeer",
    "eth_accounts",
    "eth_baseFee",
    "eth_blobBaseFee",
    "eth_blockNumber",
    "eth_call",
    "eth_callBundle",
    "eth_capabilities",
    "eth_chainId",
    "eth_coinbase",
    "eth_createAccessList",
    "eth_estimateGas",
    "eth_feeHistory",
    "eth_fillTransaction",
    "eth_gasPrice",
    "eth_getAccount",
    "eth_getAccountInfo",
    "eth_getBalance",
    "eth_getBlockByHash",
    "eth_getBlockByNumber",
    "eth_getBlockReceipts",
    "eth_getBlockTransactionCountByHash",
    "eth_getBlockTransactionCountByNumber",
    "eth_getCode",
    "eth_getFilterChanges",
    "eth_getFilterLogs",
    "eth_getHeaderByHash",
    "eth_getHeaderByNumber",
    "eth_getLogs",
    "eth_getMultiProof",
    "eth_getProof",
    "eth_getRawTransactionByBlockHashAndIndex",
    "eth_getRawTransactionByBlockNumberAndIndex",
    "eth_getRawTransactionByHash",
    "eth_getStorageAt",
    "eth_getStorageValues",
    "eth_getTransactionByBlockHashAndIndex",
    "eth_getTransactionByBlockNumberAndIndex",
    "eth_getTransactionByHash",
    "eth_getTransactionBySenderAndNonce",
    "eth_getTransactionCount",
    "eth_getTransactionReceipt",
    "eth_getUncleByBlockHashAndIndex",
    "eth_getUncleByBlockNumberAndIndex",
    "eth_getUncleCountByBlockHash",
    "eth_getUncleCountByBlockNumber",
    "eth_getWork",
    "eth_hashrate",
    "eth_maxPriorityFeePerGas",
    "eth_mining",
    "eth_newBlockFilter",
    "eth_newFilter",
    "eth_newPendingTransactionFilter",
    "eth_pendingTransactions",
    "eth_protocolVersion",
    "eth_sendRawTransaction",
    "eth_sendRawTransactionSync",
    "eth_sendTransaction",
    "eth_sign",
    "eth_signTransaction",
    "eth_signTypedData",
    "eth_submitHashrate",
    "eth_submitWork",
    "eth_subscribe",
    "eth_syncing",
    "eth_uninstallFilter",
    "eth_unsubscribe",
    "miner_setExtra",
    "miner_setGasLimit",
    "miner_setGasPrice",
    "net_listening",
    "net_peerCount",
    "net_version",
    "reth_getBalanceChangesInBlock",
    "reth_jit",
    "reth_subscribeChainNotifications",
    "reth_subscribeFinalizedChainNotifications",
    "reth_subscribePersistedBlock",
    "reth_unsubscribeChainNotifications",
    "reth_unsubscribeFinalizedChainNotifications",
    "reth_unsubscribePersistedBlock",
    "rpc_modules",
    "txpool_content",
    "txpool_contentFrom",
    "txpool_inspect",
    "txpool_status",
    "web3_clientVersion",
    "web3_sha3",
];

/// Whether a public method is refused.
pub fn refused(method: &str) -> bool {
    REFUSED_METHODS.contains(&method)
}

/// Refuse to start when a configured public transport would serve a method
/// that is neither reviewed nor refused, then remove the refused methods from
/// every transport (the middleware answers them on HTTP and WS first).
pub fn guard_configured(modules: &mut TransportRpcModules) -> Result<(), String> {
    let served: BTreeSet<&'static str> = [
        modules.http_methods(|_| true),
        modules.ws_methods(|_| true),
        modules.ipc_methods(|_| true),
    ]
    .into_iter()
    .flatten()
    .flat_map(|methods| methods.method_names().collect::<Vec<_>>())
    .collect();
    let unreviewed: Vec<&str> = served
        .into_iter()
        .filter(|method| !refused(method) && !REVIEWED_METHODS.contains(method))
        .collect();
    if !unreviewed.is_empty() {
        return Err(format!(
            "public RPC methods not reviewed for the guarded node: {}",
            unreviewed.join(" ")
        ));
    }
    for method in REFUSED_METHODS {
        modules.remove_method_from_configured(method);
    }
    Ok(())
}

fn refusal<'a>() -> ErrorObject<'a> {
    ErrorObject::borrowed(REFUSED_CODE, REFUSED_MESSAGE, None)
}

/// Reth RPC middleware that refuses `REFUSED_METHODS`.
#[derive(Clone, Copy, Debug, Default)]
pub struct RefuseReplayLayer;

impl<S> tower::Layer<S> for RefuseReplayLayer {
    type Service = RefuseReplay<S>;

    fn layer(&self, inner: S) -> Self::Service {
        RefuseReplay { inner }
    }
}

#[derive(Clone, Debug)]
pub struct RefuseReplay<S> {
    inner: S,
}

impl<S> RpcServiceT for RefuseReplay<S>
where
    S: RpcServiceT<
            MethodResponse = MethodResponse,
            BatchResponse = MethodResponse,
            NotificationResponse = MethodResponse,
        > + Send
        + Sync
        + Clone
        + 'static,
{
    type MethodResponse = MethodResponse;
    type NotificationResponse = MethodResponse;
    type BatchResponse = MethodResponse;

    fn call<'a>(&self, request: Request<'a>) -> impl Future<Output = MethodResponse> + Send + 'a {
        if refused(request.method_name()) {
            ResponseFuture::ready(
                MethodResponse::error(request.id(), refusal())
                    .with_extensions(request.extensions().clone()),
            )
        } else {
            ResponseFuture::future(self.inner.call(request))
        }
    }

    /// The server hands a batch to the inner service whole, so each refused
    /// call is replaced by its error entry here (the inner service answers an
    /// error entry without dispatching anything), and each refused
    /// notification is dropped.
    fn batch<'a>(&self, mut batch: Batch<'a>) -> impl Future<Output = MethodResponse> + Send + 'a {
        let refused_notification = |entry: &Result<BatchEntry<'a>, BatchEntryErr<'a>>| matches!(entry, Ok(BatchEntry::Notification(notification)) if refused(notification.method_name()));
        if batch.iter().any(refused_notification) {
            let extensions = batch.extensions().clone();
            let entries: Vec<_> = batch
                .into_iter()
                .filter(|entry| !refused_notification(entry))
                .collect();
            if entries.is_empty() {
                // Only notifications: nothing to answer.
                return ResponseFuture::ready(
                    MethodResponse::notification().with_extensions(extensions),
                );
            }
            batch = Batch::from(entries);
            *batch.extensions_mut() = extensions;
        }
        for entry in batch.iter_mut() {
            if let Ok(BatchEntry::Call(request)) = entry
                && refused(request.method_name())
            {
                let id = request.id();
                *entry = Err(BatchEntryErr::new(id, refusal()));
            }
        }
        ResponseFuture::future(self.inner.batch(batch))
    }

    fn notification<'a>(
        &self,
        notification: Notification<'a>,
    ) -> impl Future<Output = MethodResponse> + Send + 'a {
        if refused(notification.method_name()) {
            ResponseFuture::ready(
                MethodResponse::notification().with_extensions(notification.extensions().clone()),
            )
        } else {
            ResponseFuture::future(self.inner.notification(notification))
        }
    }
}
