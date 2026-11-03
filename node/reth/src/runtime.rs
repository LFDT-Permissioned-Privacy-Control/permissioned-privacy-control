//! Explicit execution handles tie policy facts and the exact identity evidence to
//! each candidate block. Replay handles are built only from exact block manifests.

use crate::{
    archive::{ArtifactStore, BlockDescriptor, Published},
    context::{
        CreatedContract, ExecutionBinding, ExecutionIdentity, ExecutionOutcome, IdentityResolver,
        PinnedPolicySnapshot,
    },
    facts::FactsPolicy,
    identity::{Admission, CandidateNote, CapturedIdentity, IdentityRegistry},
    manifest::{BlockManifest, ManifestEntry},
    policy::{DiagnosticReport, PolicyFactory},
    stream::{AppliedFacts, FactStream, Prepared},
    wire::{Identity, Network, PolicyArtifact, VerifiedIdentity, Verifier},
};
use alloy_evm::revm::context::TxEnv;
use alloy_primitives::{Address, B256};
use std::{
    collections::{HashMap, HashSet, VecDeque},
    sync::{Arc, Mutex},
};

/// Included transactions whose status answers are kept in memory (about the
/// finality window at the default expected load), and at most this many blocks.
const STATUS_CACHE_TRANSACTIONS: usize = 262_144;
const STATUS_CACHE_BLOCKS: usize = 1024;

/// Who a status answer names for a transaction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StatusIdentity {
    pub principal_id: String,
    pub org_id: String,
    pub context_id: String,
}

impl From<&Identity> for StatusIdentity {
    fn from(identity: &Identity) -> Self {
        Self {
            principal_id: identity.principal_id.clone(),
            org_id: identity.org_id.clone(),
            context_id: identity.context_id.clone(),
        }
    }
}

/// What a status answer needs from one included transaction. Its identity was
/// verified when the projection was built (on publication or on load).
#[derive(Clone, Debug)]
struct IncludedTransaction {
    identity: StatusIdentity,
    reason_code: String,
    created: Vec<CreatedContract>,
}

/// A block's manifest reduced to its status answers.
#[derive(Debug)]
struct BlockStatus {
    facts_version: u64,
    transactions: HashMap<B256, IncludedTransaction>,
}

#[derive(Debug, Default)]
struct StatusCache {
    blocks: HashMap<(u64, B256), Arc<BlockStatus>>,
    order: VecDeque<(u64, B256)>,
    transactions: usize,
}

impl StatusCache {
    fn insert(&mut self, key: (u64, B256), status: Arc<BlockStatus>) {
        self.transactions += status.transactions.len();
        match self.blocks.insert(key, status) {
            Some(old) => self.transactions -= old.transactions.len(),
            None => self.order.push_back(key),
        }
        while self.order.len() > 1
            && (self.transactions > STATUS_CACHE_TRANSACTIONS
                || self.order.len() > STATUS_CACHE_BLOCKS)
        {
            if let Some(old) = self.order.pop_front()
                && let Some(old) = self.blocks.remove(&old)
            {
                self.transactions -= old.transactions.len();
            }
        }
    }

    fn remove(&mut self, key: (u64, B256)) {
        if let Some(old) = self.blocks.remove(&key) {
            self.transactions -= old.transactions.len();
            self.order.retain(|cached| *cached != key);
        }
    }
}

#[derive(Debug)]
pub struct PolicyRuntime {
    pub feed: Arc<FactStream>,
    pub identities: Arc<IdentityRegistry>,
    pub archive: Arc<ArtifactStore>,
    verifier: Verifier,
    /// Serialises fact ingestion. Identity admission never takes it.
    facts: Mutex<()>,
    status: Mutex<StatusCache>,
    /// Random per process start: every private response names it, so OPS
    /// knows which boot an acknowledgement belongs to.
    boot_id: String,
}

/// 128 random bits as hex. `/dev/urandom` mixed with the clock and process
/// id, so a missing device still yields an id that differs across restarts.
fn new_boot_id() -> String {
    use sha2::{Digest, Sha256};
    use std::io::Read;
    static STARTS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let mut random = [0u8; 16];
    let _ =
        std::fs::File::open("/dev/urandom").and_then(|mut device| device.read_exact(&mut random));
    let mut hash = Sha256::new();
    hash.update(random);
    hash.update(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|elapsed| elapsed.as_nanos())
            .unwrap_or_default()
            .to_be_bytes(),
    );
    hash.update(std::process::id().to_be_bytes());
    hash.update(
        STARTS
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            .to_be_bytes(),
    );
    alloy_primitives::hex::encode(&hash.finalize()[..16])
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransactionStatus {
    pub status: String,
    pub facts_version: u64,
    pub block_hash: Option<B256>,
    pub block_number: Option<u64>,
    pub reason_code: String,
    pub created: Vec<CreatedContract>,
    pub finalized: bool,
    pub finalized_block_hash: Option<B256>,
    pub finalized_block_number: Option<u64>,
}

/// The node's canonical chain as seen for one block height: the finalized
/// block, the best block number, and the canonical hashes at the block's
/// height and at the finalized height.
#[derive(Clone, Copy, Debug)]
pub struct ChainView {
    pub finalized: (u64, B256),
    pub best: u64,
    pub canonical_at_block: Option<B256>,
    pub canonical_at_finalized: Option<B256>,
}

/// Read access to the node's canonical chain for trusted finalized history.
pub trait FinalityView: Send + Sync + std::fmt::Debug {
    /// `None` when no finalized block is known.
    fn chain_view(&self, block_number: u64) -> Option<ChainView>;
}

/// Where a block executed for import came from. Trust never rests on the
/// origin alone: a buffered engine payload can reach Reth's block path too,
/// and is untrusted there because it is not yet canonical at its height.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ImportOrigin {
    /// A block through Reth's block path (pipeline stages, re-execution,
    /// buffered downloads).
    Block,
    /// An engine-API payload: never trusted, always replayed from its manifest.
    Payload,
}

/// The transactions of one trusted finalized block. Only `import` creates it.
#[derive(Debug)]
pub struct TrustedTransactions(Arc<HashSet<B256>>);

/// How an imported block executes.
#[derive(Debug)]
pub enum ImportExecution {
    /// Replay from the block's manifest, with the policy and identities it embeds.
    Replay(Arc<ExecutionHandle>),
    /// A finalized canonical block: exactly its own transactions run without
    /// policy (trusted finalized history).
    TrustedFinalized(TrustedTransactions),
}

impl ImportExecution {
    pub fn factory(&self) -> PolicyFactory {
        match self {
            Self::Replay(handle) => handle.factory(),
            Self::TrustedFinalized(transactions) => {
                PolicyFactory::trusted_finalized(transactions.0.clone())
            }
        }
    }
}

/// Trusted only by hash, never by height alone: a finalized block known to the
/// node, canonical at its height and not above the best block, and this block
/// canonical at its own height at or below it.
fn trusted_finalized(block: &BlockDescriptor, finality: &dyn FinalityView) -> bool {
    let Some(view) = finality.chain_view(block.number) else {
        return false;
    };
    let (number, hash) = view.finalized;
    number <= view.best
        && block.number <= number
        && view.canonical_at_finalized == Some(hash)
        && view.canonical_at_block == Some(block.hash)
}

/// Finality evidence from the node's canonical chain for one included
/// transaction: the canonical hash at its height and the finalized block,
/// itself canonical at its height.
#[derive(Clone, Copy, Debug)]
pub struct FinalityEvidence {
    pub canonical_at_inclusion: B256,
    pub finalized_number: u64,
    pub finalized_hash: B256,
}

impl TransactionStatus {
    /// Evidence comes from the node's canonical forkchoice provider, never a
    /// receipt or a locally counted number of confirmations alone.
    pub fn observe_finality(&mut self, canonical_hash: B256, number: u64, hash: B256) {
        self.finalized = matches!(self.status.as_str(), "included" | "reverted")
            && self.block_hash == Some(canonical_hash)
            && self.block_number.is_some_and(|included| {
                included <= number && (included != number || self.block_hash == Some(hash))
            });
        self.finalized_block_hash = self.finalized.then_some(hash);
        self.finalized_block_number = self.finalized.then_some(number);
    }
}

impl PolicyRuntime {
    pub fn new(verifier: Verifier, archive: Arc<ArtifactStore>, capacity: usize) -> Self {
        Self {
            feed: Arc::new(FactStream::new(verifier.clone())),
            identities: Arc::new(IdentityRegistry::new(verifier.clone(), capacity)),
            archive,
            verifier,
            facts: Mutex::new(()),
            status: Mutex::new(StatusCache::default()),
            boot_id: new_boot_id(),
        }
    }
    pub fn verifier(&self) -> &Verifier {
        &self.verifier
    }

    /// This process start's id (32 hex characters).
    pub fn boot_id(&self) -> &str {
        &self.boot_id
    }

    /// Restore retained facts. Expired facts are retained for stream
    /// continuity/status but `pin_candidate` still rejects. Pending identities
    /// live in memory only and are not restored: a pooled transaction cannot
    /// execute until it is submitted again with an identity, which is accepted
    /// even while the pool still holds the transaction.
    pub fn open(
        verifier: Verifier,
        archive: Arc<ArtifactStore>,
        capacity: usize,
        now: i64,
    ) -> Result<Self, String> {
        let mut runtime = Self::new(verifier.clone(), archive, capacity);
        if let Some(checkpoint) = runtime.archive.pointer("facts-head")? {
            runtime.feed = Arc::new(FactStream::restore_retained(
                verifier.clone(),
                &runtime.archive,
                checkpoint,
                now,
            )?);
        }
        Ok(runtime)
    }
    pub fn network(&self) -> &Network {
        self.verifier.network()
    }

    /// The registered identity for `hash`, whether or not its lease is valid.
    pub fn live_identity(&self, hash: B256) -> Option<Identity> {
        self.identities.live(&ExecutionBinding::Transaction(hash))
    }

    /// The status projection of block (number, hash): from memory, or else from
    /// its manifest, whose identities are verified at their issue time (status
    /// never renews a lease or grants execution). `None` when this node has no
    /// manifest for the block.
    fn block_status(&self, number: u64, hash: B256) -> Result<Option<Arc<BlockStatus>>, String> {
        if let Some(status) = self
            .status
            .lock()
            .map_err(|_| "execution status unavailable")?
            .blocks
            .get(&(number, hash))
        {
            return Ok(Some(status.clone()));
        }
        let Some(manifest) = self.archive.manifest(number, hash)? else {
            return Ok(None);
        };
        let mut transactions = HashMap::with_capacity(manifest.entries.len());
        for entry in manifest.entries {
            let identity = self.verifier.verify_archived_identity(entry.envelope)?;
            if identity.scope != "transaction" {
                return Err("invalid archived execution identity".into());
            }
            let transaction = identity
                .binding_hash
                .parse::<B256>()
                .map_err(|_| "invalid archived execution identity")?;
            let included = IncludedTransaction {
                identity: (&identity).into(),
                reason_code: entry.reason_code,
                created: entry.created,
            };
            if transactions.insert(transaction, included).is_some() {
                return Err("execution manifest transaction mismatch".into());
            }
        }
        let status = Arc::new(BlockStatus {
            facts_version: manifest.facts_version,
            transactions,
        });
        self.status
            .lock()
            .map_err(|_| "execution status unavailable")?
            .insert((number, hash), status.clone());
        Ok(Some(status))
    }

    /// The identity a status answer describes. `Some((number, block))`: the
    /// identity that executed `hash` in that block, from its manifest. `None`:
    /// the live registry entry. Unknown is an error, so status is never
    /// disclosed for a hash OPS did not submit.
    pub fn status_identity(
        &self,
        hash: B256,
        block: Option<(u64, B256)>,
    ) -> Result<StatusIdentity, String> {
        let Some((number, block)) = block else {
            return self
                .live_identity(hash)
                .map(|identity| (&identity).into())
                .ok_or_else(|| "unknown execution identity".into());
        };
        self.block_status(number, block)?
            .and_then(|status| {
                status
                    .transactions
                    .get(&hash)
                    .map(|transaction| transaction.identity.clone())
            })
            .ok_or_else(|| "unknown execution identity".into())
    }

    /// `Some((number, block))`: the included status from that block's manifest.
    /// `None`: the latest candidate outcome noted in memory for a pending
    /// transaction.
    pub fn transaction_status(
        &self,
        hash: B256,
        canonical_block: Option<(u64, B256)>,
    ) -> Result<Option<TransactionStatus>, String> {
        let Some((number, block)) = canonical_block else {
            return Ok(self
                .identities
                .candidate_note(hash)
                .map(|note| TransactionStatus {
                    status: if note.denied { "denied" } else { "pending" }.into(),
                    facts_version: note.facts_version,
                    block_hash: None,
                    block_number: None,
                    reason_code: note.reason_code,
                    created: Vec::new(),
                    finalized: false,
                    finalized_block_hash: None,
                    finalized_block_number: None,
                }));
        };
        Ok(self.block_status(number, block)?.and_then(|status| {
            status
                .transactions
                .get(&hash)
                .map(|transaction| TransactionStatus {
                    status: "produced".into(),
                    facts_version: status.facts_version,
                    block_hash: Some(block),
                    block_number: Some(number),
                    reason_code: transaction.reason_code.clone(),
                    created: transaction.created.clone(),
                    finalized: false,
                    finalized_block_hash: None,
                    finalized_block_number: None,
                })
        }))
    }

    /// Publish a candidate's manifest for the assembled block (before it is
    /// returned to Reth) and keep its status answers in memory. When an
    /// earlier build of the same block already published equivalent evidence,
    /// that manifest stays and later answers come from it.
    pub fn persist(&self, handle: &ExecutionHandle, block: &BlockDescriptor) -> Result<(), String> {
        let (status, published) = handle.publish(&self.archive, block)?;
        let mut cache = self
            .status
            .lock()
            .map_err(|_| "execution status unavailable")?;
        let key = (block.number, block.hash);
        match published {
            Published::New => cache.insert(key, Arc::new(status)),
            Published::Existing => cache.remove(key),
        }
        Ok(())
    }

    /// The single fact writer, serialised by `facts`: validate against the
    /// installed generation, make a snapshot or delta durable (its record, the
    /// record list, then the `facts-head` pointer), and only then install it.
    /// A heartbeat only renews the lease: it is installed without any write
    /// and travels in the manifests of the blocks it made fresh. Any write
    /// error leaves the previous facts installed.
    pub fn accept_facts(
        &self,
        kind: &str,
        wire: &[u8],
        now: i64,
    ) -> Result<Arc<AppliedFacts>, String> {
        let _guard = self
            .facts
            .lock()
            .map_err(|_| "policy ingestion unavailable")?;
        match self.feed.prepare(kind, wire, now)? {
            Prepared::Unchanged(facts) => Ok(facts),
            Prepared::Next { base, next, record } => {
                // A delta extends a chain whose records must already be durable.
                if record
                    && kind == "delta"
                    && base.as_ref().is_some_and(|b| b.checkpoint().is_none())
                {
                    return Err("policy facts are not durable".into());
                }
                let next = if record {
                    self.archive.put(wire)?;
                    let list = self.archive.put(&next.record_list()?)?;
                    self.archive.set_pointer("facts-head", list)?;
                    next.with_checkpoint(list)
                } else {
                    next
                };
                let next = Arc::new(next);
                self.feed.install(base.as_ref(), next.clone())?;
                Ok(next)
            }
        }
    }

    pub fn accept_identity(&self, wire: &[u8], now: i64) -> Result<Identity, String> {
        self.admit_identity(self.verifier.verify_identity(wire, now)?, now)
    }

    /// Admit an identity verified once by the caller. Memory only: no storage
    /// I/O and no lock shared with fact ingestion or block persistence. A
    /// transaction identity the registered one dominates is an idempotent
    /// success (nothing installed).
    pub fn admit_identity(&self, verified: VerifiedIdentity, now: i64) -> Result<Identity, String> {
        Ok(self.admit_transaction(verified, now)?.identity().clone())
    }

    /// `admit_identity`, returning whether the attempt was installed and the
    /// registration that undoes exactly this installation.
    pub fn admit_transaction(
        &self,
        verified: VerifiedIdentity,
        now: i64,
    ) -> Result<Admission, String> {
        self.identities.admit_reclaiming(verified, now)
    }

    /// The status of `hash`, canonically included in `block`, from the block's
    /// manifest: `included` or `reverted`, and finalized when `finality` proves
    /// it. The bounded pending slot is released only then: before finality a
    /// reorg can return the transaction to the pool, where its identity lets it
    /// execute again while its lease is valid.
    pub fn canonical_status(
        &self,
        hash: B256,
        block: (u64, B256),
        success: bool,
        finality: Option<FinalityEvidence>,
    ) -> Result<TransactionStatus, String> {
        let mut status = self
            .transaction_status(hash, Some(block))?
            .ok_or("canonical execution evidence unavailable")?;
        status.status = if success { "included" } else { "reverted" }.into();
        if let Some(evidence) = finality {
            status.observe_finality(
                evidence.canonical_at_inclusion,
                evidence.finalized_number,
                evidence.finalized_hash,
            );
        }
        if status.finalized {
            self.identities
                .finish(&ExecutionBinding::Transaction(hash))?;
        }
        Ok(status)
    }

    pub fn pin_candidate(&self, at: i64) -> Result<Arc<ExecutionHandle>, String> {
        let facts = self.feed.pin(at, 1)?;
        // A block may only reference facts whose records are durable.
        if facts.checkpoint().is_none() {
            return Err("policy facts are not durable".into());
        }
        let facts_version = facts.version();
        ExecutionHandle::new(
            facts,
            at,
            self.network().clone(),
            RecordingResolver {
                source: Some(self.identities.clone()),
                at,
                captured: Mutex::new(HashMap::new()),
                outcomes: Mutex::new(HashMap::new()),
                expected: None,
                facts_version,
            },
        )
    }

    /// Identity has been authenticated by the private API. Freeze it before any
    /// asynchronous state lookup so request cleanup cannot affect concurrent work.
    pub fn pin_simulation(
        &self,
        identity: Identity,
        at: i64,
    ) -> Result<Arc<ExecutionHandle>, String> {
        self.verifier.validate_header(&identity.header, at)?;
        if identity.scope != "simulation" {
            return Err("invalid simulation identity scope".into());
        }
        let binding = ExecutionBinding::Simulation {
            digest: identity
                .binding_hash
                .parse()
                .map_err(|_| "invalid simulation digest")?,
            context_id: identity.context_id.clone(),
        };
        let facts = self.feed.pin(at, identity.min_snapshot_version)?;
        ExecutionHandle::new(
            facts,
            at,
            self.network().clone(),
            RecordingResolver {
                source: None,
                at,
                captured: Mutex::new(HashMap::from([(
                    binding,
                    CapturedIdentity {
                        identity,
                        envelope: None,
                    },
                )])),
                outcomes: Mutex::new(HashMap::new()),
                expected: None,
                facts_version: 0,
            },
        )
    }

    /// Execution for importing `block`. A canonical ancestor of the known
    /// finalized block, imported through the block path, needs no manifest:
    /// only its own transactions run, without policy; ordinary consensus
    /// validation still applies. Anything else replays its manifest and fails
    /// closed without one. Forensic replay of finalized history must call
    /// `replay` directly, which always checks the evidence.
    pub fn import(
        &self,
        block: &BlockDescriptor,
        origin: ImportOrigin,
        finality: &dyn FinalityView,
    ) -> Result<ImportExecution, String> {
        if &block.network == self.network()
            && origin == ImportOrigin::Block
            && trusted_finalized(block, finality)
        {
            return Ok(ImportExecution::TrustedFinalized(TrustedTransactions(
                Arc::new(block.transactions.iter().copied().collect()),
            )));
        }
        self.replay(block).map(ImportExecution::Replay)
    }

    pub fn replay(&self, block: &BlockDescriptor) -> Result<Arc<ExecutionHandle>, String> {
        if &block.network != self.network() {
            return Err("execution replay network mismatch".into());
        }
        let at = i64::try_from(block.timestamp).map_err(|_| "invalid block timestamp")?;
        let manifest = self
            .archive
            .manifest(block.number, block.hash)?
            .ok_or("missing execution manifest")?;
        if manifest.parent_hash != block.parent_hash
            || manifest.timestamp != block.timestamp
            || manifest.entries.len() != block.transactions.len()
        {
            return Err("execution manifest block mismatch".into());
        }
        // The record list, then the embedded heartbeat if one renewed the
        // lease, fresh at the block timestamp; missing lease evidence fails.
        let facts = FactStream::restore_for_block(
            self.verifier.clone(),
            &self.archive,
            manifest.records,
            manifest.lease.as_ref(),
            at,
        )?;
        if facts.digest() != manifest.facts_digest || facts.version() != manifest.facts_version {
            return Err("execution replay facts mismatch".into());
        }
        let mut captured = HashMap::new();
        let mut expected = HashMap::new();
        for (hash, entry) in block.transactions.iter().zip(&manifest.entries) {
            let (identity, envelope) = self
                .verifier
                .verify_identity_parts(entry.envelope.clone(), at)?
                .into_parts();
            if identity.scope != "transaction" || identity.binding_hash != format!("{hash:#x}") {
                return Err("execution replay identity mismatch".into());
            }
            let binding = ExecutionBinding::Transaction(*hash);
            if captured
                .insert(
                    binding.clone(),
                    CapturedIdentity {
                        identity,
                        envelope: Some(envelope),
                    },
                )
                .is_some()
            {
                return Err("execution manifest transaction mismatch".into());
            }
            expected.insert(
                binding,
                ExecutionOutcome {
                    success: entry.success,
                    denied: false,
                    reason_code: entry.reason_code.clone(),
                    created: entry.created.clone(),
                },
            );
        }
        ExecutionHandle::new(
            facts,
            at,
            block.network.clone(),
            RecordingResolver {
                source: None,
                at,
                captured: Mutex::new(captured),
                outcomes: Mutex::new(HashMap::new()),
                expected: Some(expected),
                facts_version: manifest.facts_version,
            },
        )
    }
}

#[derive(Debug)]
pub struct ExecutionHandle {
    facts: Arc<AppliedFacts>,
    policy: Arc<PinnedPolicySnapshot>,
    identities: Arc<RecordingResolver>,
    network: Network,
    at: i64,
}

impl ExecutionHandle {
    fn new(
        facts: Arc<AppliedFacts>,
        at: i64,
        network: Network,
        identities: RecordingResolver,
    ) -> Result<Arc<Self>, String> {
        let adapter = FactsPolicy::new(facts.clone(), at)?;
        let policy = Arc::new(PinnedPolicySnapshot::new(
            facts.version(),
            facts.digest(),
            Arc::new(adapter),
        ));
        Ok(Arc::new(Self {
            facts,
            policy,
            identities: Arc::new(identities),
            network,
            at,
        }))
    }
    pub fn factory(&self) -> PolicyFactory {
        PolicyFactory::new(self.policy.clone(), self.identities.clone())
    }

    pub fn candidate_factory(
        &self,
        candidate: &PolicyArtifact,
        org: &str,
    ) -> Result<(PolicyFactory, Arc<DiagnosticReport>), String> {
        let adapter =
            FactsPolicy::new(self.facts.clone(), self.at)?.with_candidate(candidate, org)?;
        let snapshot = Arc::new(PinnedPolicySnapshot::new(
            self.facts.version(),
            self.facts.digest(),
            Arc::new(adapter),
        ));
        Ok(self.factory().candidate(snapshot))
    }

    pub fn candidate_set_factory(
        &self,
        candidates: &[PolicyArtifact],
        org: &str,
    ) -> Result<(PolicyFactory, Arc<DiagnosticReport>), String> {
        let adapter =
            FactsPolicy::new(self.facts.clone(), self.at)?.with_candidates(candidates, org)?;
        let snapshot = Arc::new(PinnedPolicySnapshot::new(
            self.facts.version(),
            self.facts.digest(),
            Arc::new(adapter),
        ));
        Ok(self.factory().candidate(snapshot))
    }

    /// The facts version this handle executes with.
    pub fn facts_version(&self) -> u64 {
        self.facts.version()
    }

    /// Publish this candidate's manifest for the assembled `block` before the
    /// block is returned; the manifest itself is one publication.
    pub fn persist(&self, archive: &ArtifactStore, block: &BlockDescriptor) -> Result<(), String> {
        self.publish(archive, block).map(|_| ())
    }

    fn publish(
        &self,
        archive: &ArtifactStore,
        block: &BlockDescriptor,
    ) -> Result<(BlockStatus, Published), String> {
        if block.network != self.network || block.timestamp != self.at as u64 {
            return Err("produced block execution context mismatch".into());
        }
        let captured = self
            .identities
            .captured
            .lock()
            .map_err(|_| "execution identities unavailable")?;
        let outcomes = self
            .identities
            .outcomes
            .lock()
            .map_err(|_| "execution outcomes unavailable")?;
        let mut entries = Vec::with_capacity(block.transactions.len());
        let mut transactions = HashMap::with_capacity(block.transactions.len());
        for hash in &block.transactions {
            let binding = ExecutionBinding::Transaction(*hash);
            let identity = captured
                .get(&binding)
                .ok_or("missing executed transaction identity")?;
            let envelope = identity
                .envelope
                .as_ref()
                .ok_or("missing executed transaction evidence")?;
            let outcome = outcomes
                .get(&binding)
                .ok_or("missing executed transaction outcome")?;
            if outcome.denied || (!outcome.success && !outcome.created.is_empty()) {
                return Err("invalid included execution outcome".into());
            }
            entries.push(ManifestEntry {
                envelope: envelope.as_ref().clone(),
                success: outcome.success,
                reason_code: outcome.reason_code.clone(),
                created: outcome.created.clone(),
            });
            let included = IncludedTransaction {
                identity: (&identity.identity).into(),
                reason_code: outcome.reason_code.clone(),
                created: outcome.created.clone(),
            };
            if transactions.insert(*hash, included).is_some() {
                return Err("execution manifest transaction mismatch".into());
            }
        }
        let published = archive.publish_manifest(&BlockManifest {
            hash: block.hash,
            parent_hash: block.parent_hash,
            number: block.number,
            timestamp: block.timestamp,
            facts_version: self.facts.version(),
            facts_digest: self.facts.digest(),
            records: self
                .facts
                .checkpoint()
                .ok_or("policy facts are not durable")?,
            lease: self.facts.heartbeat().cloned(),
            entries,
        })?;
        Ok((
            BlockStatus {
                facts_version: self.facts.version(),
                transactions,
            },
            published,
        ))
    }
}

#[derive(Debug)]
struct RecordingResolver {
    /// The live registry, for candidate builds only: identities are captured
    /// from it and outcomes noted on it. Replay and simulation have none, so
    /// they never touch live state.
    source: Option<Arc<IdentityRegistry>>,
    at: i64,
    captured: Mutex<HashMap<ExecutionBinding, CapturedIdentity>>,
    outcomes: Mutex<HashMap<ExecutionBinding, ExecutionOutcome>>,
    expected: Option<HashMap<ExecutionBinding, ExecutionOutcome>>,
    facts_version: u64,
}
impl IdentityResolver for RecordingResolver {
    fn record(&self, binding: &ExecutionBinding, outcome: ExecutionOutcome) -> Result<(), String> {
        if let Some(expected) = &self.expected
            && expected.get(binding) != Some(&outcome)
        {
            return Err("replayed execution outcome differs from archive".into());
        }
        // Candidate builds note the outcome on the live registry entry: memory
        // only, best effort, so a build never waits on disk.
        if let (Some(registry), ExecutionBinding::Transaction(hash)) = (&self.source, binding) {
            registry.note_outcome(
                *hash,
                CandidateNote {
                    denied: outcome.denied,
                    reason_code: outcome.reason_code.clone(),
                    facts_version: self.facts_version,
                },
            );
        }
        self.outcomes
            .lock()
            .map_err(|_| "execution outcomes unavailable")?
            .insert(binding.clone(), outcome);
        Ok(())
    }
    fn resolve(
        &self,
        binding: &ExecutionBinding,
        transaction: &TxEnv,
    ) -> Result<ExecutionIdentity, String> {
        let mut captured = self
            .captured
            .lock()
            .map_err(|_| "execution identities unavailable")?;
        if !captured.contains_key(binding) {
            let source = self
                .source
                .as_ref()
                .ok_or("missing archived execution identity")?;
            captured.insert(binding.clone(), source.capture(binding, self.at)?);
        }
        let identity = &captured
            .get(binding)
            .ok_or("missing execution identity")?
            .identity;
        let signer = identity
            .signer
            .parse::<Address>()
            .map_err(|_| "invalid execution signer")?;
        if signer != transaction.caller {
            return Err("execution signer mismatch".into());
        }
        Ok(ExecutionIdentity {
            principal_id: identity.principal_id.clone(),
            org_id: identity.org_id.clone(),
            context_id: identity.context_id.clone(),
            signer,
            binding: binding.clone(),
            min_snapshot_version: identity.min_snapshot_version,
        })
    }
}
