//! Explicit execution handles tie policy facts and the exact identity evidence to
//! each candidate block. Replay handles are built only from exact block manifests.

use crate::{
    archive::{ArtifactStore, BlockDescriptor, BlockManifest, BoundIdentity},
    context::{
        CreatedContract, ExecutionBinding, ExecutionIdentity, ExecutionOutcome, IdentityResolver,
        PinnedPolicySnapshot,
    },
    facts::FactsPolicy,
    identity::{CandidateNote, CapturedIdentity, IdentityRegistry},
    policy::{DiagnosticReport, PolicyFactory},
    stream::{AppliedFacts, FactStream},
    wire::{Identity, Network, PolicyArtifact, VerifiedIdentity, Verifier},
};
use alloy_evm::revm::context::TxEnv;
use alloy_primitives::{Address, B256};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

#[derive(Debug)]
pub struct PolicyRuntime {
    pub feed: Arc<FactStream>,
    pub identities: Arc<IdentityRegistry>,
    pub archive: Arc<ArtifactStore>,
    verifier: Verifier,
    /// Serialises fact ingestion. Identity admission never takes it.
    facts: Mutex<()>,
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
        }
    }
    pub fn verifier(&self) -> &Verifier {
        &self.verifier
    }

    /// Restore retained facts. Expired facts are retained for stream
    /// continuity/status but `pin_candidate` still rejects. Pending identities
    /// live in memory only and are not restored: a pooled transaction cannot
    /// execute until it is submitted again through OPS.
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

    /// The identity a status answer describes. `Some(block)`: the identity that
    /// executed `hash` in that block, from its manifest, signature re-verified at
    /// its issue time (status never renews a lease or grants execution).
    /// `None`: the live registry entry. Unknown is an error, so status is never
    /// disclosed for a hash OPS did not submit.
    pub fn status_identity(&self, hash: B256, block: Option<B256>) -> Result<Identity, String> {
        let Some(block) = block else {
            return self
                .live_identity(hash)
                .ok_or_else(|| "unknown execution identity".into());
        };
        let manifest = self.archive.manifest_by_hash(block)?;
        if &manifest.block.network != self.network() {
            return Err("execution manifest network mismatch".into());
        }
        let entry = manifest
            .identities
            .iter()
            .find(|entry| entry.transaction_hash == hash)
            .ok_or("unknown execution identity")?;
        let envelope = self
            .verifier
            .decode_envelope("identity", &self.archive.get(entry.envelope)?)?;
        let identity = self.verifier.verify_archived_identity(envelope)?;
        if identity.scope != "transaction" || identity.binding_hash != format!("{hash:#x}") {
            return Err("retained identity mismatch".into());
        }
        Ok(identity)
    }

    /// `Some(block)`: the included status from that block's evidence. `None`:
    /// the latest candidate outcome noted in memory for a pending transaction.
    pub fn transaction_status(
        &self,
        hash: B256,
        canonical_block: Option<B256>,
    ) -> Result<Option<TransactionStatus>, String> {
        let Some(block) = canonical_block else {
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
        let key = format!(
            "included-{}-{}",
            alloy_primitives::hex::encode(hash),
            alloy_primitives::hex::encode(block)
        );
        self.archive
            .pointer(&key)?
            .map(|id| crate::wire::decode_strict(&self.archive.get(id)?))
            .transpose()
    }

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
        let facts = self.feed.accept(kind, wire, now)?;
        let checkpoint = facts.checkpoint(&self.archive)?;
        self.archive.set_pointer("facts-head", checkpoint)?;
        Ok(facts)
    }

    pub fn accept_identity(&self, wire: &[u8], now: i64) -> Result<Identity, String> {
        self.admit_identity(self.verifier.verify_identity(wire, now)?, now)
    }

    /// Admit an identity verified once by the caller. Memory only: no storage
    /// I/O and no lock shared with fact ingestion or block persistence.
    pub fn admit_identity(&self, verified: VerifiedIdentity, now: i64) -> Result<Identity, String> {
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
        block: B256,
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

    pub fn replay(&self, block: &BlockDescriptor) -> Result<Arc<ExecutionHandle>, String> {
        if &block.network != self.network() {
            return Err("execution replay network mismatch".into());
        }
        let at = i64::try_from(block.timestamp).map_err(|_| "invalid block timestamp")?;
        let manifest = self.archive.load_for_block(block)?;
        let restored = FactStream::restore(
            self.verifier.clone(),
            &self.archive,
            manifest.checkpoint,
            at,
        )?;
        let facts = restored.pin(at, manifest.facts_version)?;
        if facts.digest() != manifest.facts_digest || facts.version() != manifest.facts_version {
            return Err("execution replay facts mismatch".into());
        }
        let mut captured = HashMap::new();
        for entry in &manifest.identities {
            let (identity, envelope) = self
                .verifier
                .verify_identity(&self.archive.get(entry.envelope)?, at)?
                .into_parts();
            if identity.scope != "transaction"
                || identity.binding_hash != format!("{:#x}", entry.transaction_hash)
            {
                return Err("execution replay identity mismatch".into());
            }
            captured.insert(
                ExecutionBinding::Transaction(entry.transaction_hash),
                CapturedIdentity {
                    identity,
                    envelope: Some(envelope),
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
                expected: Some(
                    manifest
                        .identities
                        .iter()
                        .map(|entry| {
                            (
                                ExecutionBinding::Transaction(entry.transaction_hash),
                                entry.outcome.clone(),
                            )
                        })
                        .collect(),
                ),
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

    pub fn persist(&self, archive: &ArtifactStore, block: &BlockDescriptor) -> Result<(), String> {
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
        let identities = block
            .transactions
            .iter()
            .map(|hash| {
                let identity = captured
                    .get(&ExecutionBinding::Transaction(*hash))
                    .ok_or("missing executed transaction identity")?;
                let envelope = identity
                    .envelope
                    .as_ref()
                    .ok_or("missing executed transaction evidence")?;
                Ok(BoundIdentity {
                    transaction_hash: *hash,
                    envelope: archive.put(&envelope.to_wire())?,
                    outcome: outcomes
                        .get(&ExecutionBinding::Transaction(*hash))
                        .cloned()
                        .ok_or("missing executed transaction outcome")?,
                })
            })
            .collect::<Result<Vec<_>, String>>()?;
        let checkpoint = self.facts.checkpoint(archive)?;
        let manifest = BlockManifest {
            format_version: 1,
            block: block.clone(),
            facts_version: self.facts.version(),
            facts_digest: self.facts.digest(),
            checkpoint,
            identities,
        };
        archive.publish(&manifest)?;
        for entry in &manifest.identities {
            let status = TransactionStatus {
                status: "produced".into(),
                facts_version: self.facts.version(),
                block_hash: Some(block.hash),
                block_number: Some(block.number),
                reason_code: entry.outcome.reason_code.clone(),
                created: entry.outcome.created.clone(),
                finalized: false,
                finalized_block_hash: None,
                finalized_block_number: None,
            };
            let id = archive
                .put(&serde_json::to_vec(&status).map_err(|_| "invalid execution status")?)?;
            archive.set_pointer(
                &format!(
                    "included-{}-{}",
                    alloy_primitives::hex::encode(entry.transaction_hash),
                    alloy_primitives::hex::encode(block.hash)
                ),
                id,
            )?;
        }
        Ok(())
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
