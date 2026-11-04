//! Explicit execution handles tie policy facts and the exact identity evidence to
//! each candidate block. Replay handles are built only from exact block manifests.

use crate::{
    archive::{
        ArtifactStore, BlockDescriptor, MaintenanceInput, MaintenanceReport, Published, Retention,
    },
    chain::{ChainState, Finality},
    context::{
        CreatedContract, ExecutionBinding, ExecutionIdentity, ExecutionOutcome, IdentityResolver,
        PinnedPolicySnapshot,
    },
    facts::FactsPolicy,
    identity::{Admission, CandidateNote, CapturedIdentity, IdentityRegistry},
    manifest::{BlockManifest, ManifestEntry},
    policy::{DiagnosticReport, PolicyFactory},
    stream::{AppliedFacts, FactPin, FactStream, Prepared},
    wire::{Identity, Network, PolicyArtifact, VerifiedIdentity, Verifier},
};
use alloy_evm::revm::context::TxEnv;
use alloy_primitives::{Address, B256};
use std::{
    collections::{BTreeMap, HashMap, HashSet, VecDeque},
    sync::{Arc, Condvar, Mutex, OnceLock, Weak},
    time::Duration,
};

/// Newly final heights read per maintenance run; older ones are skipped (their
/// slots still end with their lease).
const RELEASE_HEIGHTS: u64 = 8192;
/// The maintenance thread also runs this often without a wake-up.
const MAINTENANCE_BACKSTOP: Duration = Duration::from_secs(10);

/// Included transactions whose status answers are kept in memory (about the
/// finality window at the default expected load), and at most this many blocks.
const STATUS_CACHE_TRANSACTIONS: usize = 262_144;
const STATUS_CACHE_BLOCKS: usize = 1024;
/// Produced blocks whose verified execution is kept for their self-import.
const OWN_BLOCKS: usize = 8;

/// A block this process produced and published, kept so that importing it
/// reuses the verified facts and identities instead of reading and
/// re-verifying its manifest. Exactly what the manifest records.
#[derive(Debug)]
struct OwnBlock {
    descriptor: BlockDescriptor,
    facts: Arc<AppliedFacts>,
    policy: Arc<PinnedPolicySnapshot>,
    captured: HashMap<ExecutionBinding, CapturedIdentity>,
    expected: HashMap<ExecutionBinding, ExecutionOutcome>,
}

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

/// The effective finalized block a batched status answer is consistent with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FinalizedHead {
    pub number: u64,
    pub hash: B256,
    pub timestamp: u64,
}

/// One hash's answer in a batched status call.
#[derive(Clone, Debug)]
pub struct BatchedStatus {
    pub hash: B256,
    pub identity: StatusIdentity,
    pub execution: TransactionStatus,
    /// The pool holds it (only ever true for a transaction not included).
    pub pooled: bool,
}

/// A batched status answer, in request order.
#[derive(Clone, Debug)]
pub struct StatusBatch {
    pub finalized: Option<FinalizedHead>,
    pub canonical_epoch: u64,
    /// `None` where the node has no answer for a hash.
    pub statuses: Vec<Option<BatchedStatus>>,
    /// Per hash: a canonical block holds it (its own receipt exists), none
    /// does, or `None` when that could not be read. Looked up after the
    /// finalized block was fixed.
    pub receipts: Vec<Option<bool>>,
    /// Per requested sender: its account nonce after the finalized block;
    /// `None` without senders, a finalized block, or readable state there.
    pub sender_nonces: Option<Vec<u64>>,
}

/// Hashes (and senders) one batched status call answers at most.
pub const MAX_STATUS_BATCH: usize = 256;

/// Blocks whose evidence one batched call may load from the archive (each
/// load verifies every identity in the block): entries in further uncached
/// blocks get no answer in that call, and the next call finds more cached.
const COLD_BLOCKS_PER_STATUS_CALL: usize = 16;

/// Named blocks above finality kept for the canonical epoch; beyond this the
/// lowest are dropped (only a node whose finality is unknown for that long
/// gets there, and finality re-polls still cover them).
const NAMED_BLOCKS: usize = 16_384;

/// The canonical epoch: a counter that changes whenever a block this process
/// named in a status answer as a transaction's inclusion block has left the
/// canonical chain. Named blocks above the finalized height are kept (a final
/// block cannot leave); checking the highest suffices while it is canonical,
/// because canonical blocks are hash-linked, so any change below it changes
/// the canonical hash at its height (or removes the height). After a change
/// the ones still canonical stay, so none is forgotten.
#[derive(Debug, Default)]
struct CanonicalEpoch {
    epoch: u64,
    named: BTreeMap<u64, B256>,
}

impl CanonicalEpoch {
    /// At the end of an answer that would name `blocks` (possibly none, no
    /// duplicates): bump if an earlier named block left the chain (keeping
    /// the named blocks still canonical), then add these blocks still
    /// canonical. Returns the epoch this answer reports and the blocks that
    /// left the chain during it: the answer must not name them.
    fn note(
        &mut self,
        chain: &dyn ChainState,
        blocks: &[(u64, B256)],
        finalized: Option<u64>,
    ) -> (u64, Vec<(u64, B256)>) {
        let canonical = |&(number, hash): &(u64, B256)| chain.canonical_hash(number) == Some(hash);
        if let Some(finalized) = finalized {
            self.named = self.named.split_off(&finalized.saturating_add(1));
        }
        if let Some((&number, &hash)) = self.named.last_key_value()
            && !canonical(&(number, hash))
        {
            self.epoch += 1;
            self.named
                .retain(|&number, &mut hash| canonical(&(number, hash)));
        }
        let (live, gone): (Vec<_>, Vec<_>) = blocks.iter().partition(|block| canonical(block));
        self.named.extend(live);
        while self.named.len() > NAMED_BLOCKS {
            self.named.pop_first();
        }
        (self.epoch, gone)
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
    /// The last few produced blocks, for their self-import.
    own_blocks: Mutex<VecDeque<Arc<OwnBlock>>>,
    /// Random per process start: every private response names it, so OPS
    /// knows which boot an acknowledgement belongs to.
    boot_id: String,
    /// The node's canonical chain, attached once the node is built.
    chain: OnceLock<Arc<dyn ChainState>>,
    /// What may be treated as final: never above what Reth has written.
    finality: Finality,
    /// The highest final height whose identities were released.
    released_through: Mutex<Option<u64>>,
    /// Changes when a block named in a status answer leaves the chain.
    reported: Mutex<CanonicalEpoch>,
    /// The highest block Reth had written when the node started (its
    /// persisted-block notification starts empty).
    persisted_at_start: OnceLock<(u64, B256)>,
    wake: Arc<Wake>,
    /// How long compacted manifests are kept after their block.
    retention: Retention,
}

/// Wake-ups of the maintenance thread.
#[derive(Debug, Default)]
struct Wake {
    pending: Mutex<bool>,
    signal: Condvar,
}

impl Wake {
    fn notify(&self) {
        if let Ok(mut pending) = self.pending.lock() {
            *pending = true;
            self.signal.notify_one();
        }
    }

    fn wait(&self, timeout: Duration) {
        if let Ok(pending) = self.pending.lock()
            && let Ok((mut pending, _)) =
                self.signal
                    .wait_timeout_while(pending, timeout, |pending| !*pending)
        {
            *pending = false;
        }
    }
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
            own_blocks: Mutex::new(VecDeque::new()),
            boot_id: new_boot_id(),
            chain: OnceLock::new(),
            finality: Finality::default(),
            released_through: Mutex::new(None),
            reported: Mutex::new(CanonicalEpoch::default()),
            persisted_at_start: OnceLock::new(),
            wake: Arc::new(Wake::default()),
            retention: Retention::default(),
        }
    }

    /// Set the manifest retention (default 7 days).
    pub fn with_retention(mut self, retention: Retention) -> Self {
        self.retention = retention;
        self
    }

    /// Attach the node's canonical chain (once). Heights already final now
    /// are never scanned for release: the registry started empty.
    pub fn attach_chain(&self, chain: Arc<dyn ChainState>) {
        if self.chain.set(chain.clone()).is_ok() {
            let start = self
                .finality
                .observe(chain.as_ref())
                .map(|(number, _)| number);
            if let Ok(mut released) = self.released_through.lock() {
                *released = start;
            }
        }
    }

    /// Record the highest block Reth had written at startup (read before the
    /// node launches).
    pub fn set_persisted_at_start(&self, number: u64, hash: B256) {
        let _ = self.persisted_at_start.set((number, hash));
    }

    pub fn persisted_at_start(&self) -> Option<(u64, B256)> {
        self.persisted_at_start.get().copied()
    }

    /// The effective finalized block: the canonical block at the lower of
    /// the forkchoice-finalized and the written height, never going back.
    /// `None` until a chain is attached and finality is known.
    pub fn effective_finality(&self) -> Option<(u64, B256)> {
        self.finality.observe(self.chain.get()?.as_ref())
    }

    /// Finality evidence for a transaction included at `included`: the
    /// canonical hash there and the effective finalized block.
    /// `None` if the finalized block is no longer canonical (a reorganization
    /// below finality proves nothing about the new chain).
    pub fn finality_evidence(&self, included: u64) -> Option<FinalityEvidence> {
        let (finalized_number, finalized_hash) = self.effective_finality()?;
        let chain = self.chain.get()?;
        if chain.canonical_hash(finalized_number)? != finalized_hash {
            return None;
        }
        Some(FinalityEvidence {
            canonical_at_inclusion: chain.canonical_hash(included)?,
            finalized_number,
            finalized_hash,
        })
    }

    /// One maintenance run: release the identities of transactions in newly
    /// final canonical blocks (a reorganization before finality keeps them,
    /// so the transaction executes again without OPS). Runs on the
    /// maintenance thread, never on the block path.
    pub fn maintain(&self, now: i64) -> Result<MaintenanceReport, String> {
        let chain = self.chain.get().ok_or("node chain unavailable")?;
        let Some((finalized, _)) = self.finality.observe(chain.as_ref()) else {
            return Ok(MaintenanceReport::default());
        };
        self.release(chain.as_ref(), finalized)?;
        // A produced block at or below finality is no longer imported from
        // memory (its other builds' evidence is being removed).
        if let Ok(mut own_blocks) = self.own_blocks.lock() {
            own_blocks.retain(|own| own.descriptor.number > finalized);
        }
        // The installed facts and every pinned candidate, read before the
        // archive lists anything: a root that appears later is newer.
        let live = self.feed.roots()?;
        self.archive.maintain(&MaintenanceInput {
            finalized,
            canonical: &|number| chain.canonical_hash(number),
            now,
            retention: self.retention,
            live,
        })
    }

    fn release(&self, chain: &dyn ChainState, finalized: u64) -> Result<(), String> {
        let mut released = self
            .released_through
            .lock()
            .map_err(|_| "identity release unavailable")?;
        let from = match *released {
            Some(through) if through >= finalized => return Ok(()),
            Some(through) => (through + 1).max(finalized.saturating_sub(RELEASE_HEIGHTS - 1)),
            None => finalized.saturating_sub(RELEASE_HEIGHTS - 1),
        };
        for number in from..=finalized {
            // An unreadable block is retried by the next run.
            let Some(transactions) = chain.transactions(number) else {
                *released = number.checked_sub(1).or(*released);
                return Ok(());
            };
            // A finalized inclusion makes every identity for the hash
            // obsolete: released whatever its context.
            for hash in transactions {
                self.identities
                    .finish(&ExecutionBinding::Transaction(hash))?;
            }
        }
        *released = Some(finalized);
        Ok(())
    }

    /// Ask the maintenance thread to run.
    pub fn wake_maintenance(&self) {
        self.wake.notify();
    }

    /// Start the maintenance thread: it runs on every wake-up (new
    /// finality, a published manifest) and at least every 10 s, and stops
    /// once the runtime is dropped.
    pub fn start_maintenance(
        self: &Arc<Self>,
        clock: Arc<dyn Fn() -> i64 + Send + Sync>,
    ) -> std::io::Result<()> {
        let runtime: Weak<Self> = Arc::downgrade(self);
        let wake = self.wake.clone();
        std::thread::Builder::new()
            .name("ops-policy-maintenance".into())
            .spawn(move || {
                loop {
                    wake.wait(MAINTENANCE_BACKSTOP);
                    let Some(runtime) = runtime.upgrade() else {
                        return;
                    };
                    // A run stops at its bounds: continue while work is left,
                    // a bounded number of runs per wake-up.
                    for _ in 0..64 {
                        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                            runtime.maintain(clock())
                        })) {
                            Ok(Ok(report)) if report.pending => continue,
                            Ok(Ok(_)) => break,
                            Ok(Err(error)) => {
                                eprintln!("ops policy maintenance failed: {error}");
                                break;
                            }
                            Err(_) => {
                                eprintln!(
                                    "ops policy maintenance panicked; retrying at the next wake-up"
                                );
                                break;
                            }
                        }
                    }
                }
            })
            .map(|_| ())
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
        if let Some((version, checkpoint)) = runtime.archive.head()? {
            runtime.feed = Arc::new(FactStream::restore_retained(
                verifier.clone(),
                &runtime.archive,
                version,
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
        // A new block is never at or below what is already final.
        if self
            .finality
            .current()
            .is_some_and(|(finalized, _)| block.number <= finalized)
        {
            return Err("produced block at or below the finalized height".into());
        }
        let (status, published, own) = handle.publish(&self.archive, block)?;
        self.wake.notify();
        // Only evidence this build published: an existing manifest from an
        // earlier build may differ in lease or identity times, and import
        // must use exactly the archived evidence (the earlier build's entry,
        // if still cached, matches it).
        if published == Published::New {
            let mut own_blocks = self
                .own_blocks
                .lock()
                .map_err(|_| "execution status unavailable")?;
            own_blocks.push_back(Arc::new(own));
            while own_blocks.len() > OWN_BLOCKS {
                own_blocks.pop_front();
            }
        }
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
                    // The record's own version is the new generation's.
                    self.archive.put_record(next.version(), wire)?;
                    let list = self
                        .archive
                        .put_list(next.version(), &next.record_list()?)?;
                    self.archive.set_head(next.version(), list)?;
                    next.with_checkpoint(list)
                } else {
                    *next
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

    /// Record that a status answer is about to name these inclusion blocks.
    /// Returns the canonical epoch it reports and the blocks that are no
    /// longer canonical, which it must not name. Without an attached chain
    /// nothing is tracked.
    pub fn note_reported(&self, blocks: &[(u64, B256)]) -> Result<(u64, Vec<(u64, B256)>), String> {
        let Some(chain) = self.chain.get() else {
            return Ok((0, Vec::new()));
        };
        let mut blocks = blocks.to_vec();
        blocks.sort_unstable();
        blocks.dedup();
        let finalized = self.finality.current().map(|(number, _)| number);
        Ok(self
            .reported
            .lock()
            .map_err(|_| "execution status unavailable")?
            .note(chain.as_ref(), &blocks, finalized))
    }

    /// The single status call's answer for `hash`: from its canonical block's
    /// evidence (`included`/`reverted`, final once the effective finalized
    /// block proves it), else from its registered identity. Unknown is an
    /// error, so nothing is disclosed for a hash OPS did not submit.
    pub fn status(&self, hash: B256, now: i64) -> Result<TransactionStatus, String> {
        let chain = self.chain.get().ok_or("node chain unavailable")?;
        match chain.inclusion(hash)? {
            Some(inclusion) => self.canonical_status(
                hash,
                (inclusion.number, inclusion.hash),
                inclusion.success,
                self.finality_evidence(inclusion.number),
            ),
            None => Ok(self
                .pending_status(hash, now)?
                .ok_or("unknown execution identity")?
                .1),
        }
    }

    /// Batched status of `hashes` (at most `MAX_STATUS_BATCH`), with the
    /// pool's view of each (`pooled`, read before this call), and the nonces
    /// of `senders` (at most `MAX_STATUS_BATCH`) after the finalized block.
    ///
    /// The effective finalized block F is fixed before any inclusion is looked
    /// up, so "no canonical block holds H" together with a nonce at F past
    /// H's can never describe an H that was itself finalized meanwhile.
    /// Every entry's finality is decided against that one F. A hash without a
    /// canonical block or live identity, without readable evidence for its
    /// block, or past this call's budget of uncached blocks, has no entry.
    /// The canonical epoch is read last, after this answer's blocks are noted.
    pub fn transaction_statuses(
        &self,
        hashes: &[B256],
        pooled: &[bool],
        senders: Option<&[Address]>,
        now: i64,
    ) -> Result<StatusBatch, String> {
        if hashes.is_empty()
            || hashes.len() > MAX_STATUS_BATCH
            || pooled.len() != hashes.len()
            || senders.is_some_and(|senders| senders.is_empty() || senders.len() > MAX_STATUS_BATCH)
        {
            return Err("invalid status batch".into());
        }
        let chain = self.chain.get().ok_or("node chain unavailable")?.clone();
        // Only a block above genesis, still canonical, with a readable header
        // is finality evidence; otherwise the answer has none.
        let finalized = self.effective_finality().and_then(|(number, hash)| {
            (number > 0 && chain.canonical_hash(number) == Some(hash)).then_some(())?;
            Some(FinalizedHead {
                number,
                hash,
                timestamp: chain.block_timestamp(hash)?,
            })
        });
        let mut cold_blocks = COLD_BLOCKS_PER_STATUS_CALL;
        let mut statuses = Vec::with_capacity(hashes.len());
        let mut receipts = Vec::with_capacity(hashes.len());
        let mut blocks = Vec::with_capacity(hashes.len());
        for (&hash, &in_pool) in hashes.iter().zip(pooled) {
            let (entry, receipt, block) = match chain.inclusion(hash) {
                Ok(Some(inclusion)) => (
                    self.batched_included(
                        chain.as_ref(),
                        hash,
                        inclusion,
                        finalized,
                        &mut cold_blocks,
                    ),
                    Some(true),
                    Some((inclusion.number, inclusion.hash)),
                ),
                Ok(None) => (self.batched_pending(hash, in_pool, now), Some(false), None),
                // No evidence either way: never the registry's answer.
                Err(_) => (None, None, None),
            };
            statuses.push(entry);
            receipts.push(receipt);
            blocks.push(block);
        }
        let sender_nonces = match (senders, finalized) {
            (Some(senders), Some(head)) => chain
                .nonces_at(head.hash, senders)
                .ok()
                .filter(|nonces| nonces.len() == senders.len()),
            _ => None,
        };
        // Every inclusion block read, also of hashes without an entry: their
        // receipt names it too.
        let reported: Vec<(u64, B256)> = blocks.iter().flatten().copied().collect();
        let (canonical_epoch, gone) = self.note_reported(&reported)?;
        // A block that left the chain during this answer is never named: its
        // transactions get no answer (and no receipt evidence) this time.
        for ((entry, receipt), block) in statuses.iter_mut().zip(&mut receipts).zip(&blocks) {
            if block.is_some_and(|block| gone.contains(&block)) {
                *entry = None;
                *receipt = None;
            }
        }
        Ok(StatusBatch {
            finalized,
            canonical_epoch,
            statuses,
            receipts,
            sender_nonces,
        })
    }

    /// A canonically included transaction's batched entry, from its block's
    /// evidence (loading at most `cold_blocks` more blocks from the
    /// archive), final when `finalized` proves it; then its slot is released,
    /// as by the single status call.
    fn batched_included(
        &self,
        chain: &dyn ChainState,
        hash: B256,
        inclusion: crate::chain::Inclusion,
        finalized: Option<FinalizedHead>,
        cold_blocks: &mut usize,
    ) -> Option<BatchedStatus> {
        let key = (inclusion.number, inclusion.hash);
        let cached = self.status.lock().ok()?.blocks.get(&key).cloned();
        let block = match cached {
            Some(block) => block,
            None if *cold_blocks == 0 => return None,
            None => {
                *cold_blocks -= 1;
                self.block_status(key.0, key.1).ok().flatten()?
            }
        };
        let transaction = block.transactions.get(&hash)?;
        let mut execution = TransactionStatus {
            status: if inclusion.success {
                "included"
            } else {
                "reverted"
            }
            .into(),
            facts_version: block.facts_version,
            block_hash: Some(inclusion.hash),
            block_number: Some(inclusion.number),
            reason_code: transaction.reason_code.clone(),
            created: transaction.created.clone(),
            finalized: false,
            finalized_block_hash: None,
            finalized_block_number: None,
        };
        if let Some(head) = finalized
            && let Some(canonical) = chain.canonical_hash(inclusion.number)
        {
            execution.observe_finality(canonical, head.number, head.hash);
        }
        if execution.finalized {
            self.identities
                .finish(&ExecutionBinding::Transaction(hash))
                .ok()?;
        }
        Some(BatchedStatus {
            hash,
            identity: transaction.identity.clone(),
            execution,
            pooled: false,
        })
    }

    /// A transaction not included: only a live identity has a status, as in
    /// the single status call.
    fn batched_pending(&self, hash: B256, pooled: bool, now: i64) -> Option<BatchedStatus> {
        let (identity, execution) = self.pending_status(hash, now).ok()??;
        Some(BatchedStatus {
            hash,
            identity: (&identity).into(),
            execution,
            pooled,
        })
    }

    /// The status of a transaction no canonical block holds: `None` without
    /// a registered identity; else `expired` once its lease has passed (this
    /// describes the current ticket only: a pinned candidate can still settle
    /// it), or the latest candidate note, or `pending`.
    pub fn pending_status(
        &self,
        hash: B256,
        now: i64,
    ) -> Result<Option<(Identity, TransactionStatus)>, String> {
        let Some(identity) = self.live_identity(hash) else {
            return Ok(None);
        };
        let quiet = |status: &str, reason_code: &str| TransactionStatus {
            status: status.into(),
            facts_version: identity.min_snapshot_version,
            block_hash: None,
            block_number: None,
            reason_code: reason_code.into(),
            created: Vec::new(),
            finalized: false,
            finalized_block_hash: None,
            finalized_block_number: None,
        };
        let status = if identity.header.expires_at <= now {
            quiet("expired", "IDENTITY_EXPIRED")
        } else {
            self.transaction_status(hash, None)?
                .unwrap_or_else(|| quiet("pending", ""))
        };
        Ok(Some((identity, status)))
    }

    pub fn pin_candidate(&self, at: i64) -> Result<Arc<ExecutionHandle>, String> {
        // Registered as a collection root for the candidate's whole life: it
        // publishes a manifest naming these facts.
        let (facts, pin) = self.feed.pin_tracked(at, 1)?;
        // A block may only reference facts whose records are durable.
        if facts.checkpoint().is_none() {
            return Err("policy facts are not durable".into());
        }
        let facts_version = facts.version();
        ExecutionHandle::new(
            facts,
            at,
            self.network().clone(),
            Some(pin),
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
            None,
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
        self.self_import(block).map(ImportExecution::Replay)
    }

    /// Execution for importing a block through the engine or block path. A
    /// block this process just produced and published (the same hash, parent,
    /// timestamp and transactions) reuses the execution its manifest records,
    /// already verified, once; anything else replays its manifest.
    pub fn self_import(&self, block: &BlockDescriptor) -> Result<Arc<ExecutionHandle>, String> {
        if &block.network != self.network() {
            return Err("execution replay network mismatch".into());
        }
        let own = {
            let mut own_blocks = self
                .own_blocks
                .lock()
                .map_err(|_| "execution status unavailable")?;
            own_blocks
                .iter()
                .position(|own| own.descriptor == *block)
                .and_then(|index| own_blocks.remove(index))
        };
        let at = i64::try_from(block.timestamp).map_err(|_| "invalid block timestamp")?;
        // At or below finality other builds' evidence is being removed: only
        // the archive decides.
        let below_finality = self
            .finality
            .current()
            .is_some_and(|(finalized, _)| block.number <= finalized);
        match own.filter(|_| !below_finality) {
            // Replay would refuse a record issued after the block (beyond
            // the clock tolerance); so does the cached path.
            Some(own) if own.facts.max_issued() <= at.saturating_add(5) => {
                Ok(ExecutionHandle::replaying(&own, block))
            }
            _ => self.replay(block),
        }
    }

    /// Forensic replay: always from the block's manifest, re-verifying its
    /// records and identities.
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
            manifest.facts_version,
            manifest.records,
            manifest.lease.as_ref(),
            at,
        )?;
        if facts.digest() != manifest.facts_digest
            || facts.version() != manifest.facts_version
            || facts.base_version() != manifest.base_version
        {
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
            None,
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
    /// A candidate's facts stay a collection root while it lives.
    _pin: Option<FactPin>,
}

impl ExecutionHandle {
    fn new(
        facts: Arc<AppliedFacts>,
        at: i64,
        network: Network,
        pin: Option<FactPin>,
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
            _pin: pin,
        }))
    }
    pub fn factory(&self) -> PolicyFactory {
        PolicyFactory::new(self.policy.clone(), self.identities.clone())
    }

    /// The replay of `own`, a block this process published: its facts and
    /// policy as pinned, only its transactions' captured identities, and the
    /// recorded outcomes as the expected ones.
    fn replaying(own: &OwnBlock, block: &BlockDescriptor) -> Arc<Self> {
        Arc::new(Self {
            facts: own.facts.clone(),
            policy: own.policy.clone(),
            identities: Arc::new(RecordingResolver {
                source: None,
                at: block.timestamp as i64,
                captured: Mutex::new(own.captured.clone()),
                outcomes: Mutex::new(HashMap::new()),
                expected: Some(own.expected.clone()),
                facts_version: own.facts.version(),
            }),
            network: block.network.clone(),
            at: block.timestamp as i64,
            _pin: None,
        })
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

    /// The context of the identity this handle holds for transaction `hash`
    /// (captured, or embedded in the replayed evidence).
    pub fn identity_context(&self, hash: B256) -> Option<String> {
        self.identities
            .captured
            .lock()
            .ok()?
            .get(&ExecutionBinding::Transaction(hash))
            .map(|captured| captured.identity.context_id.clone())
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
    ) -> Result<(BlockStatus, Published, OwnBlock), String> {
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
        let mut own_captured = HashMap::with_capacity(block.transactions.len());
        let mut own_expected = HashMap::with_capacity(block.transactions.len());
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
            own_captured.insert(binding.clone(), identity.clone());
            // The outcome replay expects, as the manifest records it.
            own_expected.insert(
                binding.clone(),
                ExecutionOutcome {
                    success: outcome.success,
                    denied: false,
                    reason_code: outcome.reason_code.clone(),
                    created: outcome.created.clone(),
                },
            );
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
            base_version: self.facts.base_version(),
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
            OwnBlock {
                descriptor: block.clone(),
                facts: self.facts.clone(),
                policy: self.policy.clone(),
                captured: own_captured,
                expected: own_expected,
            },
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
