//! Bounded authenticated identity ingestion, in memory only. While an entry is
//! live it refuses any other principal, organization or signer for its binding.
//! A standalone registry keeps an entry until `finish`; the node runtime also
//! reclaims expired leases on admission. Rebinding protection after release or a
//! restart is OPS's durable submission row, saved before transport, not this
//! registry.

use crate::{
    context::{ExecutionBinding, ExecutionIdentity, IdentityResolver},
    wire::{Identity, SignedEnvelope, VerifiedIdentity, Verifier},
};
use alloy_evm::revm::context::TxEnv;
use alloy_primitives::{Address, B256};
use std::{
    collections::{BTreeSet, HashMap},
    sync::{Arc, Mutex},
};

#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
enum Key {
    Transaction(B256),
    Simulation(String),
}

#[derive(Clone, Debug)]
struct StoredIdentity {
    identity: Identity,
    envelope: Arc<SignedEnvelope>,
    candidate: Option<CandidateNote>,
    /// Registry-local installation number: a later installation for the same
    /// binding always has a higher one, so cleanup and expiry can tell
    /// whether the entry is still the one they were issued for.
    seq: u64,
}

/// The undo token of one installation (conditional cleanup): a
/// definitive pool rejection of the attempt removes the entry only if it is
/// still this installation, and then restores the entry it replaced.
#[derive(Debug)]
pub struct Registration {
    key: Key,
    seq: u64,
    prior: Option<Box<StoredIdentity>>,
}

/// What admitting a transaction identity did.
#[derive(Debug)]
pub enum Admission {
    /// Installed; the registration can undo exactly this installation.
    Installed {
        identity: Identity,
        registration: Registration,
    },
    /// The registry already holds an identity for this binding, principal,
    /// organization, signer and network whose fact floor and expiry are at
    /// least the attempt's: an idempotent success, nothing is
    /// installed. Typically a client's request that arrives after a renewal.
    Dominated(Identity),
}

impl Admission {
    /// The attempt's identity.
    pub fn identity(&self) -> &Identity {
        match self {
            Self::Installed { identity, .. } | Self::Dominated(identity) => identity,
        }
    }
}

/// The latest candidate-build outcome of a pending transaction, in memory
/// only. Lost on restart, where a denied transaction reads as unknown; a
/// denial is never final anyway.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CandidateNote {
    pub denied: bool,
    pub reason_code: String,
    pub facts_version: u64,
}

/// One atomic registry read. Record this envelope when this identity is used, so
/// a concurrent ticket renewal cannot substitute different replay evidence.
/// `None` only for a simulation pinned outside the registry; simulations never
/// become block evidence.
#[derive(Clone, Debug)]
pub struct CapturedIdentity {
    pub identity: Identity,
    pub envelope: Option<Arc<SignedEnvelope>>,
}

/// Seconds a transaction may wait between admission and inclusion, in the
/// capacity bound below.
pub const INCLUSION_BOUND_SECS: u64 = 2;

/// Identities the registry must hold: every transaction from admission until
/// its slot is released when OPS observes finality, plus an allowance for
/// admitted submissions awaiting inclusion, with 25 % headroom: ⌈1.25 × (tps × (inclusion bound + finality bound) + pending limit)⌉.
/// `None` on overflow.
pub fn required_capacity(
    expected_tps: u64,
    finality_bound_secs: u64,
    pending_limit: u64,
) -> Option<u64> {
    let window = INCLUSION_BOUND_SECS.checked_add(finality_bound_secs)?;
    let load = expected_tps
        .checked_mul(window)?
        .checked_add(pending_limit)?;
    Some(load.checked_mul(5)?.div_ceil(4))
}

/// Startup check: refuse a capacity too small for the configured load.
pub fn validate_capacity(
    capacity: usize,
    expected_tps: u64,
    finality_bound_secs: u64,
    pending_limit: u64,
) -> Result<(), String> {
    if expected_tps == 0 || finality_bound_secs == 0 {
        return Err(
            "OPS_NODE_POLICY_EXPECTED_TPS and OPS_NODE_POLICY_FINALITY_BOUND must be at least 1"
                .into(),
        );
    }
    let required = required_capacity(expected_tps, finality_bound_secs, pending_limit)
        .ok_or("identity capacity bound overflows")?;
    if (capacity as u64) < required {
        return Err(format!(
            "OPS_NODE_POLICY_CAPACITY {capacity} is below the {required} identities needed for \
             OPS_NODE_POLICY_EXPECTED_TPS {expected_tps}, OPS_NODE_POLICY_FINALITY_BOUND \
             {finality_bound_secs} s and OPS_NODE_POLICY_PENDING_LIMIT {pending_limit}"
        ));
    }
    Ok(())
}

/// Expired leases released per admission, so one admission after an idle TTL
/// never pops a whole cohort while block building waits on the same lock. A
/// full registry always has room after a batch if any lease has expired: the
/// oldest index entry is then expired, so the batch releases at least one.
const RELEASE_BATCH: usize = 64;

/// Live identities plus an expiry index, so releasing expired leases never
/// scans the registry. Both change only together, under the registry mutex.
/// An index entry names the installation (`seq`) it was made for.
#[derive(Debug, Default)]
struct Entries {
    identities: HashMap<Key, StoredIdentity>,
    expiry: BTreeSet<(i64, Key, u64)>,
    next_seq: u64,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Released {
    examined: usize,
    released: usize,
}

impl Entries {
    /// A new installation number.
    fn seq(&mut self) -> u64 {
        self.next_seq += 1;
        self.next_seq
    }

    /// Replace or add, returning the replaced entry. The old index tuple is
    /// removed before the new one is added, so an equal-expiry renewal stays
    /// indexed.
    fn insert(&mut self, key: Key, stored: StoredIdentity) -> Option<StoredIdentity> {
        let index = (stored.identity.header.expires_at, key.clone(), stored.seq);
        let old = self.identities.insert(key.clone(), stored);
        if let Some(old) = &old {
            self.expiry
                .remove(&(old.identity.header.expires_at, key, old.seq));
        }
        self.expiry.insert(index);
        old
    }

    fn remove(&mut self, key: &Key) -> Option<StoredIdentity> {
        let old = self.identities.remove(key)?;
        self.expiry
            .remove(&(old.identity.header.expires_at, key.clone(), old.seq));
        Some(old)
    }

    /// Release up to `limit` leases with `expires_at <= now`, oldest first.
    /// An index entry removes its identity only if that is still the
    /// installation it was made for.
    fn release_expired(&mut self, now: i64, limit: usize) -> Released {
        let mut stats = Released::default();
        while stats.released < limit {
            let Some((expires_at, _, _)) = self.expiry.first() else {
                break;
            };
            stats.examined += 1;
            if *expires_at > now {
                break;
            }
            let (_, key, seq) = self.expiry.pop_first().expect("checked above");
            if self
                .identities
                .get(&key)
                .is_some_and(|stored| stored.seq == seq)
            {
                self.identities.remove(&key);
                stats.released += 1;
            } else {
                debug_assert!(false, "expiry index entry without its installation");
            }
        }
        stats
    }
}

#[derive(Debug)]
pub struct IdentityRegistry {
    verifier: Verifier,
    capacity: usize,
    identities: Mutex<Entries>,
}

impl IdentityRegistry {
    pub fn new(verifier: Verifier, capacity: usize) -> Self {
        Self {
            verifier,
            capacity: capacity.max(1),
            identities: Mutex::new(Entries::default()),
        }
    }

    /// Verify and install. A successful result is the acknowledgement that the
    /// context is installed.
    pub fn accept(&self, envelope: &[u8], now: i64) -> Result<Identity, String> {
        self.admit(self.verifier.verify_identity(envelope, now)?, now)
    }

    /// Install an identity whose signature was already verified once; only its
    /// validity window is rechecked at `now`. A dominated transaction identity
    /// is an error here: the caller needs it installed.
    pub fn admit(&self, verified: VerifiedIdentity, now: i64) -> Result<Identity, String> {
        match self.install(verified, now, false, false)? {
            Admission::Installed { identity, .. } => Ok(identity),
            Admission::Dominated(_) => Err("execution binding conflict".into()),
        }
    }

    /// Admit a transaction identity for delivery: install it, or accept a
    /// dominated attempt as an idempotent success, first releasing a bounded
    /// batch of expired leases under the same lock. Only the node runtime may
    /// reclaim: releasing an expired transaction lease ends the node's
    /// refusal of other principals for that hash, so the caller must hold
    /// another binding guarantee.
    pub(crate) fn admit_reclaiming(
        &self,
        verified: VerifiedIdentity,
        now: i64,
    ) -> Result<Admission, String> {
        self.install(verified, now, true, true)
    }

    fn install(
        &self,
        verified: VerifiedIdentity,
        now: i64,
        reclaim: bool,
        dominance: bool,
    ) -> Result<Admission, String> {
        let (identity, envelope) = verified.into_parts();
        self.verifier.validate_header(&identity.header, now)?;
        let key = key_for_identity(&identity)?;
        let mut store = self
            .identities
            .lock()
            .map_err(|_| "identity registry unavailable".to_owned())?;
        if reclaim {
            store.release_expired(now, RELEASE_BATCH);
        }
        let mut candidate = None;
        if let Some(old) = store.identities.get(&key) {
            let installed = &old.identity;
            if installed.principal_id != identity.principal_id
                || installed.org_id != identity.org_id
                || installed.signer != identity.signer
                || installed.header.network != identity.header.network
                || installed.binding_hash != identity.binding_hash
            {
                return Err("execution binding conflict".into());
            }
            if identity.header.issued_at < installed.header.issued_at
                || identity.header.expires_at < installed.header.expires_at
                || identity.min_snapshot_version < installed.min_snapshot_version
            {
                // Not installable. A transaction attempt the installed
                // identity dominates (floor and expiry at least the
                // attempt's) is a duplicate; anything else is a conflict.
                if dominance
                    && key_is_transaction(&key)
                    && installed.min_snapshot_version >= identity.min_snapshot_version
                    && installed.header.expires_at >= identity.header.expires_at
                {
                    return Ok(Admission::Dominated(identity));
                }
                return Err("execution binding conflict".into());
            }
            // A renewal keeps the latest candidate outcome until the next build.
            candidate = old.candidate.clone();
        } else if store.identities.len() >= self.capacity {
            return Err("execution identity capacity reached".into());
        }
        let seq = store.seq();
        let prior = store.insert(
            key.clone(),
            StoredIdentity {
                identity: identity.clone(),
                envelope,
                candidate,
                seq,
            },
        );
        Ok(Admission::Installed {
            identity,
            registration: Registration {
                key,
                seq,
                prior: prior.map(Box::new),
            },
        })
    }

    /// Undo `registration` after a definitive pool rejection of its attempt:
    /// only if the entry is still that installation, restoring the entry it
    /// replaced (a reorg may still need it) or else releasing the slot. A
    /// newer installation, or a release meanwhile, makes it a no-op. `true`
    /// when something was undone.
    pub fn revert(&self, registration: Registration) -> Result<bool, String> {
        let mut store = self
            .identities
            .lock()
            .map_err(|_| "identity registry unavailable".to_owned())?;
        let Registration { key, seq, prior } = registration;
        let Some(current) = store.identities.get(&key) else {
            return Ok(false);
        };
        if current.seq != seq {
            return Ok(false);
        }
        let candidate = current.candidate.clone();
        match prior {
            // Restored as a new installation: a stale registration of the
            // prior entry can no longer remove it (it then just expires).
            Some(prior) => {
                let mut prior = *prior;
                prior.candidate = candidate;
                prior.seq = store.seq();
                store.insert(key, prior);
            }
            None => {
                store.remove(&key);
            }
        }
        Ok(true)
    }

    /// Best effort: note a candidate outcome on the live entry for `hash` (the
    /// current one, even if renewed during the build). A missing entry
    /// (released meanwhile) is a no-op, so a note can never deny an executable
    /// transaction or change an identity, its expiry or capacity.
    pub(crate) fn note_outcome(&self, hash: B256, note: CandidateNote) {
        if let Ok(mut store) = self.identities.lock()
            && let Some(stored) = store.identities.get_mut(&Key::Transaction(hash))
        {
            stored.candidate = Some(note);
        }
    }

    pub(crate) fn candidate_note(&self, hash: B256) -> Option<CandidateNote> {
        self.identities
            .lock()
            .ok()?
            .identities
            .get(&Key::Transaction(hash))?
            .candidate
            .clone()
    }

    /// The registered identity for `binding`, whether or not its lease is valid.
    pub fn live(&self, binding: &ExecutionBinding) -> Option<Identity> {
        self.get(binding).ok().map(|stored| stored.identity)
    }

    pub fn lookup(&self, binding: &ExecutionBinding, at: i64) -> Result<Identity, String> {
        Ok(self.capture(binding, at)?.identity)
    }

    pub fn capture(&self, binding: &ExecutionBinding, at: i64) -> Result<CapturedIdentity, String> {
        let stored = self.get(binding)?;
        self.verifier.validate_header(&stored.identity.header, at)?;
        Ok(CapturedIdentity {
            identity: stored.identity,
            envelope: Some(stored.envelope),
        })
    }

    fn get(&self, binding: &ExecutionBinding) -> Result<StoredIdentity, String> {
        let store = self
            .identities
            .lock()
            .map_err(|_| "identity registry unavailable".to_owned())?;
        let stored = store
            .identities
            .get(&key_for_binding(binding))
            .ok_or_else(|| "missing execution identity".to_owned())?;
        let expected = match binding {
            ExecutionBinding::Transaction(hash) => hash,
            ExecutionBinding::Simulation { digest, .. } => digest,
        };
        if stored.identity.binding_hash != format!("{expected:#x}") {
            return Err("execution identity binding mismatch".into());
        }
        Ok(stored.clone())
    }

    /// Release a binding: finalized-inclusion reconciliation, or the end of a
    /// simulation.
    pub fn finish(&self, binding: &ExecutionBinding) -> Result<(), String> {
        self.identities
            .lock()
            .map_err(|_| "identity registry unavailable".to_owned())?
            .remove(&key_for_binding(binding));
        Ok(())
    }

    /// Registered identities, including expired leases not yet reclaimed.
    pub fn occupancy(&self) -> Result<usize, String> {
        Ok(self
            .identities
            .lock()
            .map_err(|_| "identity registry unavailable")?
            .identities
            .len())
    }

    pub fn for_execution(self: &Arc<Self>, at: i64) -> Arc<RegistryView> {
        Arc::new(RegistryView {
            registry: self.clone(),
            at,
        })
    }
}

#[derive(Debug)]
pub struct RegistryView {
    registry: Arc<IdentityRegistry>,
    at: i64,
}

impl IdentityResolver for RegistryView {
    fn resolve(
        &self,
        binding: &ExecutionBinding,
        transaction: &TxEnv,
    ) -> Result<ExecutionIdentity, String> {
        let identity = self.registry.lookup(binding, self.at)?;
        let signer = identity
            .signer
            .parse::<Address>()
            .map_err(|_| "invalid execution signer".to_owned())?;
        if signer != transaction.caller {
            return Err("execution signer mismatch".into());
        }
        Ok(ExecutionIdentity {
            principal_id: identity.principal_id,
            org_id: identity.org_id,
            context_id: identity.context_id,
            signer,
            binding: binding.clone(),
            min_snapshot_version: identity.min_snapshot_version,
        })
    }
}

fn key_for_identity(identity: &Identity) -> Result<Key, String> {
    match identity.scope.as_str() {
        "transaction" => Ok(Key::Transaction(
            identity
                .binding_hash
                .parse()
                .map_err(|_| "invalid transaction binding".to_owned())?,
        )),
        "simulation" => Ok(Key::Simulation(identity.context_id.clone())),
        _ => Err("invalid identity scope".into()),
    }
}

fn key_is_transaction(key: &Key) -> bool {
    matches!(key, Key::Transaction(_))
}

fn key_for_binding(binding: &ExecutionBinding) -> Key {
    match binding {
        ExecutionBinding::Transaction(hash) => Key::Transaction(*hash),
        ExecutionBinding::Simulation { context_id, .. } => Key::Simulation(context_id.clone()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{Header, Network};

    fn stored(
        principal: &str,
        binding: B256,
        scope: &str,
        context: &str,
        expires_at: i64,
    ) -> StoredIdentity {
        let network = Network {
            chain_id: 1,
            deployment_id: "test".into(),
        };
        StoredIdentity {
            identity: Identity {
                header: Header {
                    network,
                    issued_at: expires_at - 60,
                    expires_at,
                },
                scope: scope.into(),
                context_id: context.into(),
                principal_id: principal.into(),
                org_id: "org".into(),
                signer: format!("{:#x}", Address::ZERO),
                binding_hash: format!("{binding:#x}"),
                min_snapshot_version: 1,
            },
            envelope: Arc::new(SignedEnvelope {
                kind: "identity".into(),
                key_id: "k".into(),
                payload: vec![1],
                signature: [0; 64],
            }),
            candidate: None,
            seq: 0,
        }
    }

    /// Insert as the registry does: with a fresh installation number.
    fn put(entries: &mut Entries, key: Key, mut stored: StoredIdentity) -> u64 {
        stored.seq = entries.seq();
        let seq = stored.seq;
        entries.insert(key, stored);
        seq
    }

    fn consistent(entries: &Entries) {
        assert_eq!(entries.identities.len(), entries.expiry.len());
        for (key, stored) in &entries.identities {
            assert!(
                entries.expiry.contains(&(
                    stored.identity.header.expires_at,
                    key.clone(),
                    stored.seq
                )),
                "{key:?} is not indexed at its expiry"
            );
        }
    }

    #[test]
    fn expiry_index_matches_entries_through_every_transition() {
        let mut entries = Entries::default();
        let tx = Key::Transaction(B256::repeat_byte(1));
        let sim = Key::Simulation("sim-1".into());
        put(
            &mut entries,
            tx.clone(),
            stored("p", B256::repeat_byte(1), "transaction", "a", 100),
        );
        put(
            &mut entries,
            sim.clone(),
            stored("p", B256::repeat_byte(2), "simulation", "sim-1", 100),
        );
        consistent(&entries);
        // Renewal with an equal expiry yields the same index tuple.
        put(
            &mut entries,
            tx.clone(),
            stored("p", B256::repeat_byte(1), "transaction", "b", 100),
        );
        consistent(&entries);
        put(
            &mut entries,
            tx.clone(),
            stored("p", B256::repeat_byte(1), "transaction", "c", 160),
        );
        consistent(&entries);
        assert_eq!(entries.release_expired(100, usize::MAX).released, 1);
        consistent(&entries);
        assert!(
            entries.identities.contains_key(&tx),
            "renewed lease released early"
        );
        entries.remove(&tx);
        entries.remove(&sim);
        consistent(&entries);
        assert!(entries.identities.is_empty());
    }

    #[test]
    fn release_examines_only_expired_leases() {
        let mut entries = Entries::default();
        for index in 0..10_000u64 {
            let hash = B256::from(alloy_primitives::U256::from(index + 1));
            let expires_at = if index < 5 { 100 } else { 1_000 };
            put(
                &mut entries,
                Key::Transaction(hash),
                stored("p", hash, "transaction", "c", expires_at),
            );
        }
        let first = entries.release_expired(100, 2);
        assert_eq!(
            first,
            Released {
                examined: 2,
                released: 2
            },
            "bounded batch"
        );
        let rest = entries.release_expired(100, usize::MAX);
        assert_eq!(
            rest,
            Released {
                examined: 4,
                released: 3
            },
            "no scan of live leases"
        );
        assert_eq!(
            entries.release_expired(100, usize::MAX),
            Released {
                examined: 1,
                released: 0
            }
        );
        consistent(&entries);
        assert_eq!(entries.identities.len(), 9_995);
    }

    #[test]
    fn expiry_removal_is_conditional_on_context() {
        let registry = IdentityRegistry::new(
            Verifier::new(
                Network {
                    chain_id: 1,
                    deployment_id: "test".into(),
                },
                Default::default(),
            ),
            16,
        );
        let hash = B256::repeat_byte(1);
        let key = Key::Transaction(hash);
        let mut store = registry.identities.lock().unwrap();
        let first = put(
            &mut store,
            key.clone(),
            stored("p", hash, "transaction", "a", 100),
        );
        // A renewal replaces it; the replaced lease's expiry removes nothing.
        let renewal = store.seq();
        let mut renewed = stored("p", hash, "transaction", "b", 160);
        renewed.seq = renewal;
        let prior = store.insert(key.clone(), renewed);
        assert_eq!(store.release_expired(100, usize::MAX).released, 0);
        assert_eq!(store.identities[&key].identity.context_id, "b");
        consistent(&store);
        drop(store);
        // A stale token (the first installation's) undoes nothing.
        let stale = || Registration {
            key: key.clone(),
            seq: first,
            prior: None,
        };
        assert!(!registry.revert(stale()).unwrap());
        assert_eq!(registry.occupancy().unwrap(), 1);
        // Undo the renewal: the first lease is back, indexed at its expiry.
        let token = Registration {
            key: key.clone(),
            seq: renewal,
            prior: prior.map(Box::new),
        };
        assert!(registry.revert(token).unwrap());
        // Restored as a new installation: the first attempt's own token
        // cannot remove it any more.
        assert!(!registry.revert(stale()).unwrap());
        let mut store = registry.identities.lock().unwrap();
        assert_eq!(store.identities[&key].identity.context_id, "a");
        consistent(&store);
        assert_eq!(store.release_expired(100, usize::MAX).released, 1);
        assert!(store.identities.is_empty());
        consistent(&store);
    }
}
