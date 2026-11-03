//! Pinned Reth v2.5.2 integration. Context travels explicitly through block
//! execution and assembly; no mutable ambient signer or thread-local scope exists.

use crate::{
    archive::BlockDescriptor,
    chain::{ChainState, Inclusion},
    policy::{PolicyEvm, PolicyFactory},
    runtime::{
        ChainView, ExecutionHandle, FinalityView, ImportExecution, ImportOrigin, PolicyRuntime,
    },
};
use alloy_consensus::{BlockHeader, Header, TxReceipt};
use alloy_eips::BlockNumHash;
use alloy_evm::{
    EvmEnv,
    block::{BlockExecutorFactory, StateDB},
    eth::{EthBlockExecutionCtx, EthBlockExecutorFactory, EthEvmContext},
    revm::inspector::Inspector,
};
use alloy_primitives::{Address, B256, keccak256};
use reth_ethereum::{
    Block, EthPrimitives,
    chainspec::ChainSpec,
    evm::{
        EthBlockAssembler, EthEvmConfig, RethReceiptBuilder,
        primitives::{
            ConfigureEngineEvm, ConfigureEvm, ExecutableTxIterator, NextBlockEnvAttributes,
            execute::{BlockAssembler, BlockAssemblerInput, BlockExecutionError},
        },
    },
    node::{
        api::{FullNodeTypes, NodeTypes},
        builder::{BuilderContext, components::ExecutorBuilder},
    },
    primitives::{SealedBlock, SealedHeader},
    provider::{
        BlockHashReader, BlockIdReader, BlockNumReader, DatabaseProviderFactory, HeaderProvider,
        ReceiptProvider, StateProviderFactory, TransactionsProvider,
    },
    rpc::types::engine::ExecutionData,
};
use std::{fmt, io, sync::Arc};

type InnerFactory = EthBlockExecutorFactory<RethReceiptBuilder, Arc<ChainSpec>, PolicyFactory>;

/// What executes a block: a pinned candidate or replay handle, or trusted
/// finalized history.
#[derive(Clone, Debug)]
enum Execution {
    Handle(Arc<ExecutionHandle>),
    TrustedFinalized(PolicyFactory),
}

#[derive(Clone, Debug)]
pub struct ExecutionCtx<'a> {
    inner: EthBlockExecutionCtx<'a>,
    execution: Execution,
}

/// The node's canonical chain, read from its provider at each import, so a
/// stage re-run or restart re-derives finality from persisted state.
struct ProviderFinality<P>(P);

impl<P> fmt::Debug for ProviderFinality<P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ProviderFinality")
    }
}

impl<P: BlockIdReader + BlockNumReader + Send + Sync> FinalityView for ProviderFinality<P> {
    fn chain_view(&self, block_number: u64) -> Option<ChainView> {
        let finalized = self.0.finalized_block_num_hash().ok().flatten()?;
        Some(ChainView {
            finalized: (finalized.number, finalized.hash),
            best: self.0.best_block_number().ok()?,
            canonical_at_block: self.0.block_hash(block_number).ok().flatten(),
            canonical_at_finalized: self.0.block_hash(finalized.number).ok().flatten(),
        })
    }
}

/// The node's canonical chain for effective finality and release. The
/// persisted height comes from Reth's persisted-block notification, used
/// only while it names a canonical block, and until the first notification
/// from the height Reth had written at startup.
pub struct ProviderChain<P> {
    provider: P,
    persisted: Box<dyn Fn() -> Option<BlockNumHash> + Send + Sync>,
    at_start: Option<(u64, B256)>,
}

impl<P> ProviderChain<P> {
    pub fn new(
        provider: P,
        persisted: impl Fn() -> Option<BlockNumHash> + Send + Sync + 'static,
        at_start: Option<(u64, B256)>,
    ) -> Self {
        Self {
            provider,
            persisted: Box::new(persisted),
            at_start,
        }
    }
}

impl<P> fmt::Debug for ProviderChain<P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ProviderChain")
    }
}

impl<P> ChainState for ProviderChain<P>
where
    P: BlockIdReader
        + BlockHashReader
        + TransactionsProvider<Transaction = reth_ethereum::TransactionSigned>
        + ReceiptProvider<Receipt: TxReceipt>
        + HeaderProvider<Header: BlockHeader>
        + StateProviderFactory
        + Send
        + Sync,
{
    fn finalized(&self) -> Option<(u64, B256)> {
        let finalized = self.provider.finalized_block_num_hash().ok().flatten()?;
        Some((finalized.number, finalized.hash))
    }
    fn persisted(&self) -> Option<u64> {
        // Either way only while it is still the canonical block there.
        let (number, hash) = match (self.persisted)() {
            None => self.at_start?,
            Some(persisted) => (persisted.number, persisted.hash),
        };
        (self.canonical_hash(number) == Some(hash)).then_some(number)
    }
    fn canonical_hash(&self, number: u64) -> Option<B256> {
        let hash = self.provider.block_hash(number).ok().flatten()?;
        // Above the canonical head the provider falls back to the database,
        // which keeps blocks of an abandoned branch until Reth removes them
        // (after a forkchoice to an ancestor): those are not canonical. The
        // head is read after the hash, so a head that moves back meanwhile
        // refuses the hash.
        (number <= self.provider.best_block_number().ok()?).then_some(hash)
    }
    fn transactions(&self, number: u64) -> Option<Vec<B256>> {
        Some(
            self.provider
                .transactions_by_block(number.into())
                .ok()
                .flatten()?
                .iter()
                .map(|transaction| *transaction.tx_hash())
                .collect(),
        )
    }
    fn inclusion(&self, hash: B256) -> Result<Option<Inclusion>, String> {
        // Index lookups only: the transaction's block and its own receipt,
        // never the block's other receipts.
        let Some((_, meta)) = self
            .provider
            .transaction_by_hash_with_meta(hash)
            .map_err(|_| "transaction lookup failed")?
        else {
            return Ok(None);
        };
        let receipt = self
            .provider
            .receipt_by_hash(hash)
            .map_err(|_| "receipt lookup failed")?
            .ok_or("receipt unavailable")?;
        // Two lookups: only an inclusion still canonical after both is
        // evidence (a reorganization in between could pair them wrongly).
        if self.canonical_hash(meta.block_number) != Some(meta.block_hash) {
            return Err("canonical chain changed during the lookup".into());
        }
        Ok(Some(Inclusion {
            number: meta.block_number,
            hash: meta.block_hash,
            success: receipt.status(),
        }))
    }
    fn block_timestamp(&self, hash: B256) -> Option<u64> {
        Some(self.provider.header(hash).ok().flatten()?.timestamp())
    }
    fn nonces_at(&self, block: B256, accounts: &[Address]) -> Result<Vec<u64>, String> {
        // One state view at exactly this block, by hash.
        let state = self
            .provider
            .state_by_block_hash(block)
            .map_err(|_| "account state unavailable")?;
        accounts
            .iter()
            .map(|account| {
                state
                    .account_nonce(account)
                    .map(Option::unwrap_or_default)
                    .map_err(|_| "account state unavailable".to_owned())
            })
            .collect()
    }
}

#[derive(Clone, Debug)]
pub struct OpsBlockExecutorFactory {
    inner: InnerFactory,
}
impl BlockExecutorFactory for OpsBlockExecutorFactory {
    type EvmFactory = PolicyFactory;
    type TxExecutionResult = <InnerFactory as BlockExecutorFactory>::TxExecutionResult;
    type ExecutionCtx<'a> = ExecutionCtx<'a>;
    type Transaction = <InnerFactory as BlockExecutorFactory>::Transaction;
    type Receipt = <InnerFactory as BlockExecutorFactory>::Receipt;
    type Executor<'a, DB: StateDB, I: Inspector<EthEvmContext<DB>>> =
        <InnerFactory as BlockExecutorFactory>::Executor<'a, DB, I>;
    fn evm_factory(&self) -> &Self::EvmFactory {
        self.inner.evm_factory()
    }
    fn create_executor<'a, DB: StateDB, I: Inspector<EthEvmContext<DB>>>(
        &'a self,
        mut evm: PolicyEvm<DB, I>,
        ctx: Self::ExecutionCtx<'a>,
    ) -> Self::Executor<'a, DB, I> {
        evm.install_context(match &ctx.execution {
            Execution::Handle(handle) => handle.factory(),
            Execution::TrustedFinalized(factory) => factory.clone(),
        });
        self.inner.create_executor(evm, ctx.inner)
    }
}

#[derive(Clone, Debug)]
pub struct OpsBlockAssembler {
    inner: EthBlockAssembler<ChainSpec>,
    runtime: Arc<PolicyRuntime>,
}
impl BlockAssembler<OpsBlockExecutorFactory> for OpsBlockAssembler {
    type Block = Block;
    fn assemble_block(
        &self,
        input: BlockAssemblerInput<'_, '_, OpsBlockExecutorFactory>,
    ) -> Result<Block, BlockExecutionError> {
        let Execution::Handle(handle) = input.execution_ctx.execution else {
            return Err(BlockExecutionError::msg(
                "trusted finalized history is never assembled into a new block",
            ));
        };
        let inner = BlockAssemblerInput::<InnerFactory>::new(
            input.evm_env,
            input.execution_ctx.inner,
            input.parent,
            input.transactions,
            input.output,
            input.bundle_state,
            input.state_provider,
            input.state_root,
            input.block_access_list_hash,
        );
        let block = self.inner.assemble_block(inner, None, None, None)?;
        let descriptor = BlockDescriptor {
            network: self.runtime.network().clone(),
            hash: block.header.hash_slow(),
            parent_hash: block.header.parent_hash,
            number: block.header.number,
            timestamp: block.header.timestamp,
            transactions: block
                .body
                .transactions
                .iter()
                .map(|tx| *tx.tx_hash())
                .collect(),
        };
        self.runtime
            .persist(&handle, &descriptor)
            .map_err(BlockExecutionError::msg)?;
        Ok(block)
    }
}

#[derive(Clone, Debug)]
pub struct OpsEvmConfig {
    inner: EthEvmConfig<ChainSpec, PolicyFactory>,
    factory: OpsBlockExecutorFactory,
    assembler: OpsBlockAssembler,
    runtime: Arc<PolicyRuntime>,
    finality: Arc<dyn FinalityView>,
}
impl OpsEvmConfig {
    pub fn new(
        chain: Arc<ChainSpec>,
        runtime: Arc<PolicyRuntime>,
        finality: Arc<dyn FinalityView>,
    ) -> Self {
        let inner = EthEvmConfig::new_with_evm_factory(chain, PolicyFactory::unconfigured());
        Self {
            factory: OpsBlockExecutorFactory {
                inner: inner.executor_factory.clone(),
            },
            assembler: OpsBlockAssembler {
                inner: inner.block_assembler.clone(),
                runtime: runtime.clone(),
            },
            inner,
            runtime,
            finality,
        }
    }
}
impl ConfigureEvm for OpsEvmConfig {
    type Primitives = EthPrimitives;
    type Error = io::Error;
    type NextBlockEnvCtx = NextBlockEnvAttributes;
    type BlockExecutorFactory = OpsBlockExecutorFactory;
    type BlockAssembler = OpsBlockAssembler;
    fn block_executor_factory(&self) -> &Self::BlockExecutorFactory {
        &self.factory
    }
    fn block_assembler(&self) -> &Self::BlockAssembler {
        &self.assembler
    }
    fn evm_env(&self, header: &Header) -> Result<EvmEnv, Self::Error> {
        Ok(self
            .inner
            .evm_env(header)
            .expect("infallible Ethereum environment"))
    }
    fn next_evm_env(
        &self,
        parent: &Header,
        attributes: &Self::NextBlockEnvCtx,
    ) -> Result<EvmEnv, Self::Error> {
        Ok(self
            .inner
            .next_evm_env(parent, attributes)
            .expect("infallible Ethereum environment"))
    }
    fn context_for_block<'a>(
        &self,
        block: &'a SealedBlock<Block>,
    ) -> Result<ExecutionCtx<'a>, Self::Error> {
        let descriptor = BlockDescriptor {
            network: self.runtime.network().clone(),
            hash: block.hash(),
            parent_hash: block.header().parent_hash,
            number: block.header().number,
            timestamp: block.header().timestamp,
            transactions: block
                .body()
                .transactions
                .iter()
                .map(|tx| *tx.tx_hash())
                .collect(),
        };
        let execution = match self
            .runtime
            .import(&descriptor, ImportOrigin::Block, self.finality.as_ref())
            .map_err(io::Error::other)?
        {
            ImportExecution::Replay(handle) => Execution::Handle(handle),
            trusted @ ImportExecution::TrustedFinalized(_) => {
                Execution::TrustedFinalized(trusted.factory())
            }
        };
        Ok(ExecutionCtx {
            inner: self
                .inner
                .context_for_block(block)
                .expect("infallible Ethereum context"),
            execution,
        })
    }
    fn context_for_next_block(
        &self,
        parent: &SealedHeader,
        attributes: Self::NextBlockEnvCtx,
    ) -> Result<ExecutionCtx<'_>, Self::Error> {
        let at = i64::try_from(attributes.timestamp).map_err(io::Error::other)?;
        let handle = self.runtime.pin_candidate(at).map_err(io::Error::other)?;
        Ok(ExecutionCtx {
            inner: self
                .inner
                .context_for_next_block(parent, attributes)
                .expect("infallible Ethereum context"),
            execution: Execution::Handle(handle),
        })
    }
}
impl ConfigureEngineEvm<ExecutionData> for OpsEvmConfig {
    fn evm_env_for_payload(&self, payload: &ExecutionData) -> Result<EvmEnv, Self::Error> {
        Ok(self
            .inner
            .evm_env_for_payload(payload)
            .expect("infallible Ethereum environment"))
    }
    fn context_for_payload<'a>(
        &self,
        payload: &'a ExecutionData,
    ) -> Result<ExecutionCtx<'a>, Self::Error> {
        let descriptor = BlockDescriptor {
            network: self.runtime.network().clone(),
            hash: payload.payload.block_hash(),
            parent_hash: payload.parent_hash(),
            number: payload.payload.block_number(),
            timestamp: payload.payload.timestamp(),
            transactions: payload
                .payload
                .transactions()
                .iter()
                .map(keccak256)
                .collect(),
        };
        // An engine payload is never trusted here: it always replays its manifest.
        // (A payload buffered for an unknown parent later takes the block path,
        // where it is not canonical at its height and so replays as well.)
        Ok(ExecutionCtx {
            inner: self
                .inner
                .context_for_payload(payload)
                .expect("infallible Ethereum context"),
            execution: Execution::Handle(
                self.runtime
                    .self_import(&descriptor)
                    .map_err(io::Error::other)?,
            ),
        })
    }
    fn tx_iterator_for_payload(
        &self,
        payload: &ExecutionData,
    ) -> Result<impl ExecutableTxIterator<Self>, Self::Error> {
        Ok(self
            .inner
            .tx_iterator_for_payload(payload)
            .expect("infallible Ethereum transactions"))
    }
}

/// The `PrunedData` of Reth's prune modes (`PruneConfig::segments`, from the
/// command line or the config file), without naming Reth's prune types.
#[macro_export]
macro_rules! pruned_data {
    ($segments:expr) => {{
        let segments = &$segments;
        $crate::sdk::PrunedData {
            transaction_lookup: segments.transaction_lookup.is_some(),
            receipts: segments.receipts.is_some() || !segments.receipts_log_filter.is_empty(),
            bodies: segments.bodies_history.is_some(),
        }
    }};
}

/// Which transaction data a node's pruning settings remove.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PrunedData {
    pub transaction_lookup: bool,
    pub receipts: bool,
    pub bodies: bool,
}

impl PrunedData {
    /// The guarded node needs every canonical transaction's hash index, body
    /// and receipt: without them an included transaction would read as not
    /// included, and OPS could record it dropped.
    pub fn refuse(self) -> Result<(), String> {
        if self.transaction_lookup || self.receipts || self.bodies {
            return Err("pruning transaction lookup, receipts or bodies is not supported by the guarded node: its status answers need every canonical transaction".into());
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct OpsExecutorBuilder(pub Arc<PolicyRuntime>);
impl<Node> ExecutorBuilder<Node> for OpsExecutorBuilder
where
    Node: FullNodeTypes<Types: NodeTypes<ChainSpec = ChainSpec, Primitives = EthPrimitives>>,
{
    type EVM = OpsEvmConfig;
    async fn build_evm(self, ctx: &BuilderContext<Node>) -> eyre::Result<Self::EVM> {
        if ctx.chain_spec().chain.id() != self.0.network().chain_id {
            eyre::bail!("OPS policy network does not match node chain");
        }
        // Status, release and OPS's `dropped` decision rely on the node's
        // transaction index, bodies and receipts: refuse pruning that removes
        // them (`--full`, `--minimal`, `--prune.*`, or the config file).
        let toml = ctx.reth_config().prune.clone();
        for config in ctx.config().prune_config().into_iter().chain([toml]) {
            crate::pruned_data!(config.segments)
                .refuse()
                .map_err(eyre::Report::msg)?;
        }
        // Before launch nothing is being written: the database's finished
        // block is what Reth has written.
        let database = ctx.provider().database_provider_ro()?;
        let written = database.best_block_number()?;
        if let Some(hash) = database.block_hash(written)? {
            self.0.set_persisted_at_start(written, hash);
        }
        let finality = Arc::new(ProviderFinality(ctx.provider().clone()));
        Ok(OpsEvmConfig::new(ctx.chain_spec(), self.0, finality))
    }
}
