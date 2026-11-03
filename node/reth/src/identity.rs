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

/// Expired leases released per admission, so one admission after an idle TTL
/// never pops a whole cohort while block building waits on the same lock. A
/// full registry always has room after a batch if any lease has expired: the
/// oldest index entry is then expired, so the batch releases at least one.
const RELEASE_BATCH: usize = 64;

/// Live identities plus an expiry index, so releasing expired leases never
/// scans the registry. Both change only together, under the registry mutex.
#[derive(Debug, Default)]
struct Entries {
    identities: HashMap<Key, StoredIdentity>,
    expiry: BTreeSet<(i64, Key)>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Released {
    examined: usize,
    released: usize,
}

impl Entries {
    /// Replace or add. The old index tuple is removed before the new one is
    /// added, so an equal-expiry renewal stays indexed.
    fn insert(&mut self, key: Key, stored: StoredIdentity) {
        let expires_at = stored.identity.header.expires_at;
        if let Some(old) = self.identities.insert(key.clone(), stored) {
            self.expiry
                .remove(&(old.identity.header.expires_at, key.clone()));
        }
        self.expiry.insert((expires_at, key));
    }

    fn remove(&mut self, key: &Key) {
        if let Some(old) = self.identities.remove(key) {
            self.expiry
                .remove(&(old.identity.header.expires_at, key.clone()));
        }
    }

    /// Release up to `limit` leases with `expires_at <= now`, oldest first.
    fn release_expired(&mut self, now: i64, limit: usize) -> Released {
        let mut stats = Released::default();
        while stats.released < limit {
            let Some((expires_at, _)) = self.expiry.first() else {
                break;
            };
            stats.examined += 1;
            if *expires_at > now {
                break;
            }
            let (_, key) = self.expiry.pop_first().expect("checked above");
            let removed = self.identities.remove(&key);
            debug_assert!(removed.is_some(), "expiry index entry without an identity");
            stats.released += 1;
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
    /// validity window is rechecked at `now`.
    pub fn admit(&self, verified: VerifiedIdentity, now: i64) -> Result<Identity, String> {
        self.install(verified, now, false)
    }

    /// `admit`, first releasing a bounded batch of expired leases under the
    /// same lock. Only the node runtime may reclaim: releasing an expired
    /// transaction lease ends the node's refusal of other principals for that
    /// hash, so the caller must hold another binding guarantee.
    pub(crate) fn admit_reclaiming(
        &self,
        verified: VerifiedIdentity,
        now: i64,
    ) -> Result<Identity, String> {
        self.install(verified, now, true)
    }

    fn install(
        &self,
        verified: VerifiedIdentity,
        now: i64,
        reclaim: bool,
    ) -> Result<Identity, String> {
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
        if let Some(old) = store.identities.get(&key) {
            let old = &old.identity;
            if old.principal_id != identity.principal_id
                || old.org_id != identity.org_id
                || old.signer != identity.signer
                || old.header.network != identity.header.network
                || old.binding_hash != identity.binding_hash
                || identity.header.issued_at < old.header.issued_at
                || identity.header.expires_at < old.header.expires_at
                || identity.min_snapshot_version < old.min_snapshot_version
            {
                return Err("execution binding conflict".into());
            }
        } else if store.identities.len() >= self.capacity {
            return Err("execution identity capacity reached".into());
        }
        // A renewal keeps the latest candidate outcome until the next build.
        let candidate = store
            .identities
            .get(&key)
            .and_then(|old| old.candidate.clone());
        store.insert(
            key,
            StoredIdentity {
                identity: identity.clone(),
                envelope,
                candidate,
            },
        );
        Ok(identity)
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
        }
    }

    fn consistent(entries: &Entries) {
        assert_eq!(entries.identities.len(), entries.expiry.len());
        for (key, stored) in &entries.identities {
            assert!(
                entries
                    .expiry
                    .contains(&(stored.identity.header.expires_at, key.clone())),
                "{key:?} is not indexed at its expiry"
            );
        }
    }

    #[test]
    fn expiry_index_matches_entries_through_every_transition() {
        let mut entries = Entries::default();
        let tx = Key::Transaction(B256::repeat_byte(1));
        let sim = Key::Simulation("sim-1".into());
        entries.insert(
            tx.clone(),
            stored("p", B256::repeat_byte(1), "transaction", "a", 100),
        );
        entries.insert(
            sim.clone(),
            stored("p", B256::repeat_byte(2), "simulation", "sim-1", 100),
        );
        consistent(&entries);
        // Renewal with an equal expiry yields the same index tuple.
        entries.insert(
            tx.clone(),
            stored("p", B256::repeat_byte(1), "transaction", "b", 100),
        );
        consistent(&entries);
        entries.insert(
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
            entries.insert(
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
}
