use alloy_eips::eip2718::Decodable2718;
use alloy_primitives::{Address, B256, Bytes};
use alloy_rpc_types_trace::geth::GethDebugTracingCallOptions;
use async_trait::async_trait;
use base64::{Engine, engine::general_purpose::STANDARD};
use ops_reth_policy::{
    api::{ExecutionBackend, PoolRejection, PoolSubmission, PrivateApi, serve},
    archive::{ArtifactStore, Retention},
    context::ExecutionBinding,
    runtime::PolicyRuntime,
    sdk::{OpsExecutorBuilder, ProviderChain},
    simulation,
    transaction::PolicyTx,
    wire::{Identity, Network, SimulationRequest, Verifier},
};
use reth_ethereum::{
    PooledTransactionVariant,
    cli::interface::Cli,
    node::core::args::{DatabaseArgs, DebugArgs, RpcServerArgs},
    node::{
        EthereumNode,
        builder::rpc::{BasicEngineApiBuilder, BasicEngineValidatorBuilder, RpcAddOns},
        node::{EthereumEngineValidatorBuilder, EthereumEthApiBuilder},
    },
    pool::TransactionOrigin,
    primitives::{Recovered, WithEncoded},
    provider::db::mdbx::SyncMode,
    rpc::{
        api::eth::helpers::{Call, EthTransactions},
        builder::RethRpcModule,
        eth::{
            EthApiError, RpcInvalidTransactionError,
            error::RpcPoolError,
            primitives::{BlockId, TransactionRequest, state::EvmOverrides},
        },
    },
};
use serde_json::Value;
use std::{
    collections::BTreeMap,
    future::Future,
    pin::Pin,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

type BackendFuture<T> = Pin<Box<dyn Future<Output = Result<T, String>> + Send>>;
type SubmitFn =
    Arc<dyn Fn(Identity, Bytes, Address) -> BackendFuture<PoolSubmission> + Send + Sync>;
type StatusFn = Arc<dyn Fn(B256) -> BackendFuture<Value> + Send + Sync>;
type SimulateFn =
    Arc<dyn Fn(Identity, SimulationRequest, Bytes) -> BackendFuture<Value> + Send + Sync>;

struct Backend {
    submit: SubmitFn,
    simulate: SimulateFn,
    status: StatusFn,
}
#[async_trait]
impl ExecutionBackend for Backend {
    fn capabilities(&self) -> Vec<String> {
        [
            "per_frame_a5",
            "signed_identity_v1",
            "fact_stream_v1",
            "simulation_v1",
            "archive_v1",
            "candidate_simulation_v1",
            "scoped_diagnostics_v1",
            "finalized_status_v1",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect()
    }
    async fn submit(
        &self,
        identity: Identity,
        raw: Bytes,
        signer: Address,
    ) -> Result<PoolSubmission, String> {
        (self.submit)(identity, raw, signer).await
    }
    async fn transaction_status(&self, hash: B256) -> Result<Value, String> {
        (self.status)(hash).await
    }
    async fn simulate(
        &self,
        identity: Identity,
        request: SimulationRequest,
        exact: Bytes,
    ) -> Result<Value, String> {
        (self.simulate)(identity, request, exact).await
    }
}
fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|v| v.as_secs() as i64)
        .unwrap_or_default()
}
fn required(name: &str) -> eyre::Result<String> {
    std::env::var(name).map_err(|_| eyre::eyre!("{name} is required"))
}

/// The pool's answer to a submission, from its typed error only (never an
/// error's text). "Already known" means the pool holds a transaction with the
/// submitted hash, for example one restored from its backup after a restart.
/// "Nonce too low" (the nonce is used) and an underpriced replacement are
/// definitive answers for these bytes at the current head (not finality).
/// Every other error is transient or ambiguous and reported opaquely.
fn pool_submission(result: Result<B256, EthApiError>) -> Result<PoolSubmission, String> {
    match result {
        Ok(hash) => Ok(PoolSubmission::Inserted(hash)),
        Err(EthApiError::PoolError(RpcPoolError::AlreadyKnown)) => Ok(PoolSubmission::AlreadyKnown),
        Err(EthApiError::PoolError(RpcPoolError::Invalid(
            RpcInvalidTransactionError::NonceTooLow { .. },
        ))) => Ok(PoolSubmission::Rejected(PoolRejection::NonceUsed)),
        Err(EthApiError::PoolError(RpcPoolError::ReplaceUnderpriced)) => {
            Ok(PoolSubmission::Rejected(PoolRejection::Replaced))
        }
        Err(_) => Err("transaction pool rejected submission".into()),
    }
}

/// Public RPC modules that replay, simulate or build blocks through the guarded
/// executor: historical debug/trace and Otterscan replay (forensic replay is
/// authenticated), bundle simulation and block validation, and test block
/// building. `all` includes them.
const REFUSED_RPC_MODULES: [RethRpcModule; 6] = [
    RethRpcModule::Debug,
    RethRpcModule::Trace,
    RethRpcModule::Ots,
    RethRpcModule::Flashbots,
    RethRpcModule::Mev,
    RethRpcModule::Testing,
];

/// Public RPC settings the guarded node refuses to start with: the modules
/// above, and a transaction forwarder, which would send guarded transactions
/// to a node that does not enforce policy.
fn refuse_unsafe_rpc(rpc: &RpcServerArgs) -> eyre::Result<()> {
    for selection in [&rpc.http_api, &rpc.ws_api].into_iter().flatten() {
        if let Some(module) = REFUSED_RPC_MODULES
            .iter()
            .find(|module| selection.contains(module))
        {
            eyre::bail!(
                "public RPC module {module} executes through the guarded node and is not supported; use ops_simulate for calls"
            );
        }
    }
    // With a forwarder, Reth answers with the remote node's hash and drops the
    // local pool result, so a locally rejected transaction would be reported
    // accepted, and the remote node does not enforce policy.
    if rpc.rpc_forwarder.is_some() {
        eyre::bail!(
            "--rpc.forwarder is not supported: it sends guarded transactions to a node without policy and hides local pool rejections"
        );
    }
    Ok(())
}

/// Debug settings the guarded node refuses: the reorg stream builds, replays
/// and persists synthetic blocks through the guarded executor.
fn refuse_unsafe_debug(debug: &DebugArgs) -> eyre::Result<()> {
    if debug.reorg_frequency.is_some() {
        eyre::bail!("--debug.reorg-frequency is not supported by the guarded node");
    }
    Ok(())
}

/// The node reports finality, and releases identities, only for blocks Reth
/// has written; a database sync mode that can lose committed blocks on a
/// host crash would break that.
fn refuse_unsafe_database(database: &DatabaseArgs) -> eyre::Result<()> {
    if database
        .sync_mode
        .is_some_and(|mode| mode != SyncMode::Durable)
    {
        eyre::bail!("--db.sync-mode must be durable on the guarded node");
    }
    Ok(())
}

/// "Nonce too low" for a transaction whose own canonical receipt exists is an
/// inclusion, not a rejection (Reth validates the nonce before it looks for a
/// duplicate). A failed receipt lookup is transient: the registration stays.
fn settle_nonce_rejection(
    submission: PoolSubmission,
    own_receipt: impl FnOnce() -> Result<bool, String>,
) -> Result<PoolSubmission, String> {
    match submission {
        PoolSubmission::Rejected(PoolRejection::NonceUsed) => Ok(if own_receipt()? {
            PoolSubmission::Included
        } else {
            submission
        }),
        other => Ok(other),
    }
}

/// Settings the guarded node forces on public RPC. A public `pending` query or
/// `eth_simulateV1` would build candidate blocks through the guarded executor
/// and publish their manifests; OPS needs neither.
fn force_rpc_settings(rpc: &mut RpcServerArgs) -> eyre::Result<()> {
    rpc.ipcdisable = true;
    rpc.rpc_pending_block = "none".parse().map_err(eyre::Report::msg)?;
    rpc.rpc_max_simulate_blocks = 0;
    Ok(())
}

/// The pooled form of `raw`, whose signer the private API already recovered
/// from these exact bytes: no second recovery on the way into the pool.
fn recovered_pooled(
    raw: &Bytes,
    signer: Address,
) -> Result<Recovered<PooledTransactionVariant>, String> {
    let mut remaining = raw.as_ref();
    let pooled = PooledTransactionVariant::decode_2718(&mut remaining)
        .map_err(|_| "invalid signed transaction")?;
    if !remaining.is_empty() {
        return Err("invalid signed transaction".into());
    }
    Ok(Recovered::new_unchecked(pooled, signer))
}

fn main() -> eyre::Result<()> {
    Cli::parse_args().run(move |mut builder, _| async move {
        let network = Network {
            chain_id: required("OPS_NODE_POLICY_CHAIN_ID")?.parse()?,
            deployment_id: required("OPS_NODE_POLICY_DEPLOYMENT_ID")?,
        };
        let encoded: BTreeMap<String, String> =
            serde_json::from_str(&required("OPS_NODE_POLICY_PUBLIC_KEYS")?)?;
        if encoded.is_empty() || network.chain_id == 0 || network.deployment_id.is_empty() {
            eyre::bail!("invalid OPS policy trust configuration");
        }
        let mut keys = BTreeMap::new();
        for (id, encoded) in encoded {
            let bytes: [u8; 32] = STANDARD
                .decode(encoded)?
                .try_into()
                .map_err(|_| eyre::eyre!("invalid Ed25519 public key length"))?;
            keys.insert(id, ed25519_dalek::VerifyingKey::from_bytes(&bytes)?);
        }
        let archive = Arc::new(
            ArtifactStore::open(required("OPS_NODE_POLICY_STATE_DIR")?)
                .map_err(eyre::Report::msg)?,
        );
        let setting = |name: &str, default: &str| -> eyre::Result<u64> {
            std::env::var(name)
                .unwrap_or_else(|_| default.into())
                .parse::<u64>()
                .map_err(|error| eyre::eyre!("{name}: {error}"))
        };
        let capacity = usize::try_from(setting("OPS_NODE_POLICY_CAPACITY", "262144")?)?;
        // Slots are held until the transaction's block is final and written:
        // size them for the expected load.
        ops_reth_policy::identity::validate_capacity(
            capacity,
            setting("OPS_NODE_POLICY_EXPECTED_TPS", "2000")?,
            setting("OPS_NODE_POLICY_FINALITY_BOUND", "64")?,
            setting("OPS_NODE_POLICY_PENDING_LIMIT", "37500")?,
        )
        .map_err(eyre::Report::msg)?;
        // How long block evidence is kept after its block (`forever` for an
        // archive node); pruned on the maintenance thread.
        let retention = Retention::parse(
            &std::env::var("OPS_NODE_POLICY_MANIFEST_RETENTION").unwrap_or_else(|_| "7d".into()),
        )
        .map_err(eyre::Report::msg)?;
        let runtime = Arc::new(
            PolicyRuntime::open(Verifier::new(network, keys), archive, capacity, now())
                .map_err(eyre::Report::msg)?
                .with_retention(retention),
        );
        refuse_unsafe_rpc(&builder.config().rpc)?;
        refuse_unsafe_debug(&builder.config().debug)?;
        refuse_unsafe_database(&builder.config().db)?;
        force_rpc_settings(&mut builder.config_mut().rpc)?;
        let listener = tokio::net::TcpListener::bind(required("OPS_NODE_POLICY_LISTEN")?).await?;
        let token = required("OPS_NODE_POLICY_TOKEN")?;
        let eth_builder: EthereumEthApiBuilder = Default::default();
        let engine_builder: BasicEngineApiBuilder<EthereumEngineValidatorBuilder> =
            Default::default();
        let validator_builder: BasicEngineValidatorBuilder<EthereumEngineValidatorBuilder> =
            Default::default();
        let addons = RpcAddOns::new(
            eth_builder,
            EthereumEngineValidatorBuilder::default(),
            engine_builder,
            validator_builder,
            tower::layer::util::Identity::new(),
            tower::layer::util::Identity::new(),
        );
        let handle = builder
            .with_types::<EthereumNode>()
            .with_components(
                EthereumNode::components().executor(OpsExecutorBuilder(runtime.clone())),
            )
            .with_add_ons(addons)
            .launch_with_debug_capabilities()
            .await?;
        // The node's own canonical chain drives finality: status, and identity
        // release at finality on the maintenance thread, woken by Reth's
        // finalized and persisted notifications.
        let provider = handle.node.provider.clone();
        let memory = provider.canonical_in_memory_state();
        let written = memory.clone();
        runtime.attach_chain(Arc::new(ProviderChain::new(
            provider,
            move || written.get_persisted_num_hash(),
            runtime.persisted_at_start(),
        )));
        runtime.start_maintenance(Arc::new(now))?;
        let (mut finalized, mut persisted) = (
            memory.subscribe_finalized_block(),
            memory.subscribe_persisted_block(),
        );
        let maintenance = runtime.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    changed = finalized.changed() => if changed.is_err() { break },
                    changed = persisted.changed() => if changed.is_err() { break },
                }
                maintenance.wake_maintenance();
            }
        });
        let eth_submit = handle.node.rpc_registry.eth_api().clone();
        let eth_simulate = eth_submit.clone();
        let eth_status = eth_submit.clone();
        let status_runtime = runtime.clone();
        let status: StatusFn = Arc::new(move |hash| {
            let eth = eth_status.clone();
            let runtime = status_runtime.clone();
            Box::pin(async move {
                let status = if let Some(receipt) = eth
                    .transaction_receipt(hash)
                    .await
                    .map_err(|_| "receipt lookup failed")?
                {
                    let receipt =
                        serde_json::to_value(receipt).map_err(|_| "invalid canonical receipt")?;
                    let block: B256 = receipt
                        .get("blockHash")
                        .and_then(Value::as_str)
                        .ok_or("receipt block unavailable")?
                        .parse()
                        .map_err(|_| "invalid receipt block")?;
                    let included = u64::from_str_radix(
                        receipt
                            .get("blockNumber")
                            .and_then(Value::as_str)
                            .ok_or("receipt block unavailable")?
                            .trim_start_matches("0x"),
                        16,
                    )
                    .map_err(|_| "invalid receipt block")?;
                    let success = receipt.get("status").and_then(Value::as_str) == Some("0x1");
                    // Finality from the node's canonical chain, never above
                    // what Reth has written (a crash cannot lose a block
                    // reported final); deciding from it is the runtime's.
                    let lookup = runtime.clone();
                    tokio::task::spawn_blocking(move || {
                        let finality = lookup.finality_evidence(included);
                        lookup.canonical_status(hash, (included, block), success, finality)
                    })
                    .await
                    .map_err(|_| "status lookup failed")??
                } else {
                    // Not included: only a live (registered) identity has a status.
                    let identity = runtime
                        .live_identity(hash)
                        .ok_or("unknown execution identity")?;
                    if identity.header.expires_at <= now() {
                        // This describes the current ticket only. An already pinned
                        // candidate can still settle; OPS continues receipt polling.
                        ops_reth_policy::runtime::TransactionStatus {
                            status: "expired".into(),
                            facts_version: identity.min_snapshot_version,
                            block_hash: None,
                            block_number: None,
                            reason_code: "IDENTITY_EXPIRED".into(),
                            created: Vec::new(),
                            finalized: false,
                            finalized_block_hash: None,
                            finalized_block_number: None,
                        }
                    } else {
                        let lookup = runtime.clone();
                        tokio::task::spawn_blocking(move || lookup.transaction_status(hash, None))
                            .await
                            .map_err(|_| "status lookup failed")??
                            .unwrap_or(ops_reth_policy::runtime::TransactionStatus {
                                status: "pending".into(),
                                facts_version: identity.min_snapshot_version,
                                block_hash: None,
                                block_number: None,
                                reason_code: String::new(),
                                created: Vec::new(),
                                finalized: false,
                                finalized_block_hash: None,
                                finalized_block_number: None,
                            })
                    }
                };
                serde_json::to_value(status).map_err(|_| "invalid execution status".into())
            })
        });
        let submit: SubmitFn = Arc::new(move |identity: Identity, raw: Bytes, signer| {
            let eth = eth_submit.clone();
            Box::pin(async move {
                let recovered = recovered_pooled(&raw, signer)?;
                if format!("{:#x}", recovered.tx_hash()) != identity.binding_hash {
                    return Err("transaction identity mismatch".into());
                }
                let hash = *recovered.tx_hash();
                let submission = pool_submission(
                    eth.send_transaction(
                        TransactionOrigin::Local,
                        WithEncoded::new(raw, recovered),
                    )
                    .await,
                )?;
                let own_receipt =
                    if submission == PoolSubmission::Rejected(PoolRejection::NonceUsed) {
                        Some(
                            eth.transaction_receipt(hash)
                                .await
                                .map(|receipt| receipt.is_some())
                                .map_err(|_| "receipt lookup failed".to_owned()),
                        )
                    } else {
                        None
                    };
                settle_nonce_rejection(submission, || own_receipt.unwrap_or(Ok(false)))
            })
        });
        let simulation_runtime = runtime.clone();
        let simulate: SimulateFn = Arc::new(move |identity, request, _exact| {
            let eth = eth_simulate.clone();
            let org = identity.org_id.clone();
            let binding = ExecutionBinding::Simulation {
                digest: identity.binding_hash.parse().unwrap_or_default(),
                context_id: identity.context_id.clone(),
            };
            let runtime = simulation_runtime.clone();
            Box::pin(async move {
                // Pinning facts and building policy adapters scale with the
                // fact snapshot: prepared on a blocking thread, not an async worker.
                let (factory, candidate_report, transaction, request) =
                    tokio::task::spawn_blocking(move || -> Result<_, String> {
                        let pinned = runtime.pin_simulation(identity, now())?;
                        let (factory, candidate_report) = if let Some(candidates) =
                            &request.candidate_policies
                        {
                            let (factory, report) =
                                pinned.candidate_set_factory(candidates, &org)?;
                            (factory, Some(report))
                        } else if let Some(candidate) = &request.candidate_policy {
                            let (factory, report) = pinned.candidate_factory(candidate, &org)?;
                            (factory, Some(report))
                        } else {
                            (pinned.factory(), None)
                        };
                        let transaction: TransactionRequest =
                            serde_json::from_value(request.params[0].clone())
                                .map_err(|_| "invalid simulation transaction")?;
                        Ok((factory, candidate_report, transaction, request))
                    })
                    .await
                    .map_err(|_| "simulation preparation failed")??;
                let block: BlockId = request
                    .params
                    .get(1)
                    .filter(|v| !v.is_null())
                    .map(|v| serde_json::from_value(v.clone()))
                    .transpose()
                    .map_err(|_| "invalid simulation block")?
                    .unwrap_or_default();
                // A signed principal authorizes execution of existing code,
                // never replacement code/storage supplied by an RPC caller.
                let overrides = EvmOverrides::default();
                let mut trace = None;
                if request.method == "debug_traceCall" {
                    let options: GethDebugTracingCallOptions = serde_json::from_value(
                        request
                            .params
                            .get(2)
                            .cloned()
                            .unwrap_or_else(|| serde_json::json!({})),
                    )
                    .map_err(|_| "invalid tracing options")?;
                    if options.tx_index.is_some() {
                        return Err("transaction-index simulation is unsupported".into());
                    }
                    if options
                        .state_overrides
                        .as_ref()
                        .is_some_and(|state| !state.is_empty())
                    {
                        return Err("simulation state overrides are unsupported".into());
                    }
                    trace = Some(options.tracing_options);
                }
                eth.spawn_with_call_at(transaction, block, overrides, move |db, env, tx| {
                    let tx = PolicyTx::bound(tx.environment().clone(), binding);
                    let result = if let Some(report) = candidate_report {
                        let factory = if request.dry_run {
                            factory.diagnostic().0
                        } else {
                            factory
                        };
                        simulation::run(factory, db, env, tx, &request.method, trace).and_then(
                            |result| {
                                Ok(serde_json::json!({"result":result,"policy":report.value()?}))
                            },
                        )
                    } else if request.dry_run {
                        simulation::run_diagnostic(factory, db, env, tx, &request.method, trace)
                    } else {
                        simulation::run(factory, db, env, tx, &request.method, trace)
                    };
                    result.map_err(EthApiError::InvalidParams)
                })
                .await
                .map_err(|_| "simulation denied or failed".into())
            })
        });
        let workers = usize::try_from(setting(
            "OPS_NODE_POLICY_VERIFY_WORKERS",
            &ops_reth_policy::api::DEFAULT_CPU_WORKERS.to_string(),
        )?)?;
        if !(1..=64).contains(&workers) {
            eyre::bail!("OPS_NODE_POLICY_VERIFY_WORKERS must be between 1 and 64");
        }
        let api = Arc::new(
            PrivateApi::new(
                runtime,
                Arc::new(Backend {
                    submit,
                    simulate,
                    status,
                }),
                token,
                Arc::new(now),
            )
            .map_err(eyre::Report::msg)?
            .with_cpu_pool(ops_reth_policy::api::CpuPool::new(workers)),
        );
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let mut private = tokio::spawn(serve(listener, api, async move {
            let _ = stopped.await;
        }));
        tokio::select! {
            exit=handle.wait_for_node_exit()=> {let _=stop.send(());private.await??;exit},
            result=&mut private=> {result??;eyre::bail!("private OPS policy listener stopped")},
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use reth_ethereum::cli::{chainspec::EthereumChainSpecParser, interface::Cli};

    #[test]
    fn already_known_pool_error_is_an_already_pooled_transaction() {
        let hash = B256::repeat_byte(7);
        assert_eq!(
            pool_submission(Ok(hash)),
            Ok(PoolSubmission::Inserted(hash))
        );
        assert_eq!(
            pool_submission(Err(EthApiError::PoolError(RpcPoolError::AlreadyKnown))),
            Ok(PoolSubmission::AlreadyKnown)
        );
        assert_eq!(
            pool_submission(Err(EthApiError::PoolError(RpcPoolError::Invalid(
                RpcInvalidTransactionError::NonceTooLow { tx: 1, state: 2 },
            )))),
            Ok(PoolSubmission::Rejected(PoolRejection::NonceUsed))
        );
        assert_eq!(
            pool_submission(Err(EthApiError::PoolError(
                RpcPoolError::ReplaceUnderpriced
            ))),
            Ok(PoolSubmission::Rejected(PoolRejection::Replaced))
        );
        for rejected in [
            EthApiError::PoolError(RpcPoolError::TxPoolOverflow),
            EthApiError::PoolError(RpcPoolError::Underpriced),
            EthApiError::PoolError(RpcPoolError::Invalid(
                RpcInvalidTransactionError::NonceTooHigh,
            )),
            // Only the pool's typed answer counts, never an error's text.
            EthApiError::PoolError(RpcPoolError::Other("already known".into())),
            EthApiError::PoolError(RpcPoolError::Other("nonce too low".into())),
        ] {
            assert_eq!(
                pool_submission(Err(rejected)),
                Err("transaction pool rejected submission".into())
            );
        }
    }

    fn rpc(arguments: &[&str]) -> RpcServerArgs {
        let mut command = vec!["ops-reth", "node"];
        command.extend_from_slice(arguments);
        let cli = Cli::<EthereumChainSpecParser>::try_parse_args_from(command).unwrap();
        let reth_ethereum::cli::interface::Commands::Node(node) = cli.command else {
            panic!("not the node command");
        };
        node.rpc
    }

    #[test]
    fn unsafe_public_rpc_is_refused_at_startup() {
        assert!(refuse_unsafe_rpc(&rpc(&["--http", "--http.api", "eth,net,web3"])).is_ok());
        assert!(refuse_unsafe_rpc(&rpc(&["--http", "--http.api", "eth,txpool,admin"])).is_ok());
        for arguments in [
            &["--http", "--http.api", "eth,debug"][..],
            &["--http", "--http.api", "debug"],
            &["--ws", "--ws.api", "trace"],
            &["--ws", "--ws.api", "eth,ots"],
            &["--http", "--http.api", "eth,testing"],
            &["--http", "--http.api", "mev"],
            &["--http", "--http.api", "flashbots"],
            &["--http", "--http.api", "all"],
            &["--rpc.forwarder", "http://127.0.0.1:8545"],
        ] {
            assert!(
                refuse_unsafe_rpc(&rpc(arguments)).is_err(),
                "{arguments:?} was accepted"
            );
        }
    }

    #[test]
    fn public_rpc_never_builds_candidate_blocks() {
        let mut args = rpc(&["--rpc.max-simulate-blocks", "64"]);
        force_rpc_settings(&mut args).unwrap();
        assert_eq!(
            args.rpc_max_simulate_blocks, 0,
            "eth_simulateV1 would build blocks"
        );
        assert!(args.ipcdisable);
        assert_eq!(args.rpc_pending_block, "none".parse().unwrap());
    }

    #[test]
    fn pooled_form_keeps_the_recovered_signer_and_hash() {
        let gold: Value = serde_json::from_str(include_str!(
            "../../../internal/nodepolicy/testdata/envelopes-v1.json"
        ))
        .unwrap();
        let raw: Bytes = gold["raw_transaction"].as_str().unwrap().parse().unwrap();
        let signer = Address::repeat_byte(5);
        let recovered = recovered_pooled(&raw, signer).unwrap();
        assert_eq!(recovered.signer(), signer);
        let envelope = alloy_consensus::TxEnvelope::decode_2718(&mut raw.as_ref()).unwrap();
        assert_eq!(recovered.tx_hash(), envelope.tx_hash());
        let mut trailing = raw.to_vec();
        trailing.push(0);
        assert!(recovered_pooled(&trailing.into(), signer).is_err());
    }

    #[test]
    fn nonce_too_low_with_own_receipt_is_an_inclusion() {
        let used = PoolSubmission::Rejected(PoolRejection::NonceUsed);
        assert_eq!(
            settle_nonce_rejection(used, || Ok(true)),
            Ok(PoolSubmission::Included)
        );
        assert_eq!(settle_nonce_rejection(used, || Ok(false)), Ok(used));
        assert!(
            settle_nonce_rejection(used, || Err("lookup".into())).is_err(),
            "a failed lookup must keep the registration (transient)"
        );
        let replaced = PoolSubmission::Rejected(PoolRejection::Replaced);
        assert_eq!(
            settle_nonce_rejection(replaced, || panic!("no lookup for other answers")),
            Ok(replaced)
        );
    }

    #[test]
    fn debug_reorg_stream_is_refused_at_startup() {
        let debug = |arguments: &[&str]| {
            let mut command = vec!["ops-reth", "node"];
            command.extend_from_slice(arguments);
            let cli = Cli::<EthereumChainSpecParser>::try_parse_args_from(command).unwrap();
            let reth_ethereum::cli::interface::Commands::Node(node) = cli.command else {
                panic!("not the node command");
            };
            node.debug
        };
        assert!(refuse_unsafe_debug(&debug(&[])).is_ok());
        assert!(refuse_unsafe_debug(&debug(&["--debug.reorg-frequency", "5"])).is_err());
    }

    #[test]
    fn non_durable_database_is_refused_at_startup() {
        let database = |arguments: &[&str]| {
            let mut command = vec!["ops-reth", "node"];
            command.extend_from_slice(arguments);
            let cli = Cli::<EthereumChainSpecParser>::try_parse_args_from(command).unwrap();
            let reth_ethereum::cli::interface::Commands::Node(node) = cli.command else {
                panic!("not the node command");
            };
            node.db
        };
        assert!(refuse_unsafe_database(&database(&[])).is_ok());
        assert!(refuse_unsafe_database(&database(&["--db.sync-mode", "durable"])).is_ok());
        assert!(refuse_unsafe_database(&database(&["--db.sync-mode", "safe-no-sync"])).is_err());
    }
}
