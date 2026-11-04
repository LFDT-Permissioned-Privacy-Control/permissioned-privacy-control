//! Authenticated atomic fact stream. A heartbeat changes only the freshness lease;
//! all handles already pinned by an execution remain immutable.

use crate::{
    archive::{ArtifactId, ArtifactStore},
    wire::{
        Delta, Header, Heartbeat, Sanction, SignedEnvelope, Snapshot, Verifier, decode_strict,
        hex_digest, validate_snapshot,
    },
};
use alloy_primitives::{B256, hex};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    sync::{Arc, Mutex},
};

const MAX_CHAIN_BYTES: usize = 256 << 20;
const MAX_CHAIN_RECORDS: usize = 8192;

/// The durable record list of one generation: its own record (the snapshot or
/// delta that made it) and the list of the generation it extends, so its
/// size is constant and a chain's lists grow linearly with its length.
/// Written once per snapshot/delta; every block manifest built on that
/// generation references it by id, and the id commits to the whole chain
/// back to its snapshot.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RecordList {
    format_version: u32,
    facts_version: u64,
    facts_digest: B256,
    /// The chain's snapshot version.
    base_version: u64,
    /// Records in the chain up to and including this one (a snapshot: 1).
    records: u64,
    /// The list of the generation this delta extends; none for a snapshot.
    previous: Option<ListRef>,
    record: ArchivedRecord,
}

/// A stored record list: the facts version it completes, and its id.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ListRef {
    version: u64,
    list: ArtifactId,
}

const LIST_FORMAT: u32 = 4;
/// A stored record list is read with this bound (one is about 400 bytes).
const MAX_LIST_BYTES: usize = 4096;
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ArchivedRecord {
    kind: String,
    /// The record's own version (a snapshot's or delta's `version`).
    version: u64,
    envelope: ArtifactId,
}

#[derive(Clone, Debug)]
pub struct AppliedFacts {
    snapshot: Arc<Snapshot>,
    digest: B256,
    lease: Header,
    /// The snapshot or delta that made this generation (a heartbeat keeps
    /// it: it renews the lease of the same facts).
    record: ArchivedRecord,
    /// The chain's snapshot version, and its records up to this generation.
    base_version: u64,
    chain_records: usize,
    /// The generation this delta extends: its version and durable list.
    previous: Option<(u64, Option<ArtifactId>)>,
    chain_bytes: usize,
    heartbeat: Option<Arc<SignedEnvelope>>,
    /// The durable record-list object, once the records are on disk. Only
    /// durable facts may be pinned by a candidate block.
    checkpoint: Option<ArtifactId>,
    /// The latest issue time of the snapshot and deltas this generation was
    /// built from (replay refuses a record issued after the block).
    max_issued: i64,
}

impl AppliedFacts {
    pub fn snapshot(&self) -> &Snapshot {
        &self.snapshot
    }
    pub fn version(&self) -> u64 {
        self.snapshot.version
    }
    pub fn digest(&self) -> B256 {
        self.digest
    }
    pub fn expires_at(&self) -> i64 {
        self.lease.expires_at
    }
    /// The durable record list, `None` until the records are durable.
    pub fn checkpoint(&self) -> Option<ArtifactId> {
        self.checkpoint
    }
    /// The heartbeat that renewed this generation's lease, if any. It is never
    /// written separately: block manifests embed it.
    pub fn heartbeat(&self) -> Option<&SignedEnvelope> {
        self.heartbeat.as_deref()
    }
    /// The latest issue time among this generation's records.
    pub fn max_issued(&self) -> i64 {
        self.max_issued
    }
    /// The version of the snapshot this generation's chain starts from.
    pub fn base_version(&self) -> u64 {
        self.base_version
    }

    /// This generation's record list. A delta's names the durable list of
    /// the generation it extends, so that one must be durable first.
    fn list(&self) -> Result<RecordList, String> {
        let previous = match self.previous {
            None => None,
            Some((version, Some(list))) => Some(ListRef { version, list }),
            Some((_, None)) => return Err("policy facts are not durable".into()),
        };
        Ok(RecordList {
            format_version: LIST_FORMAT,
            facts_version: self.version(),
            facts_digest: self.digest,
            base_version: self.base_version,
            records: self.chain_records as u64,
            previous,
            record: self.record.clone(),
        })
    }

    /// The stored form of this generation's record list.
    pub(crate) fn record_list(&self) -> Result<Vec<u8>, String> {
        serde_json::to_vec(&self.list()?).map_err(|_| "invalid policy record list".into())
    }

    pub(crate) fn with_checkpoint(&self, checkpoint: ArtifactId) -> Self {
        Self {
            checkpoint: Some(checkpoint),
            ..self.clone()
        }
    }
}

/// The result of validating one fact envelope against the installed
/// generation, before anything is written or installed.
pub enum Prepared {
    /// Already installed: nothing to write or install.
    Unchanged(Arc<AppliedFacts>),
    /// A new generation. `record` is true for a snapshot or delta, whose
    /// envelope must be durable before `next` is installed; a heartbeat only
    /// renews the lease.
    Next {
        base: Option<Arc<AppliedFacts>>,
        next: Box<AppliedFacts>,
        record: bool,
    },
}

/// The installed generation and the (facts, base) versions every live
/// candidate pinned, under one lock: collection reads both at once, so a
/// record a pinned candidate may still publish a manifest for is never
/// collected.
#[derive(Debug, Default)]
struct Current {
    facts: Option<Arc<AppliedFacts>>,
    pins: HashMap<u64, (u64, u64)>,
    next_pin: u64,
}

#[derive(Debug)]
pub struct FactStream {
    verifier: Verifier,
    current: Mutex<Current>,
    /// The installed facts version, for requests waiting on a fact floor.
    versions: tokio::sync::watch::Sender<u64>,
}

/// Keeps the facts a candidate pinned collectable only after it is dropped.
#[derive(Debug)]
pub struct FactPin {
    stream: Arc<FactStream>,
    id: u64,
}

impl Drop for FactPin {
    fn drop(&mut self) {
        if let Ok(mut current) = self.stream.current.lock() {
            current.pins.remove(&self.id);
        }
    }
}

impl FactStream {
    pub fn new(verifier: Verifier) -> Self {
        Self {
            verifier,
            current: Mutex::new(Current::default()),
            versions: tokio::sync::watch::Sender::new(0),
        }
    }

    /// The installed facts version as it changes.
    pub fn versions(&self) -> tokio::sync::watch::Receiver<u64> {
        self.versions.subscribe()
    }

    /// Whether the installed facts are fresh at `now` but below `minimum`:
    /// a request with that floor can wait for publication. Stale or missing
    /// facts cannot be waited out.
    pub fn behind(&self, now: i64, minimum: u64) -> bool {
        self.latest().ok().flatten().is_some_and(|facts| {
            facts.version() < minimum && self.verifier.validate_header(&facts.lease, now).is_ok()
        })
    }

    /// Reverify archived signatures and the entire linked stream. `at` is the
    /// current time for startup. Restoring an expired chain never grants a new
    /// lease.
    pub fn restore(
        verifier: Verifier,
        store: &ArtifactStore,
        version: u64,
        checkpoint: ArtifactId,
        at: i64,
    ) -> Result<Self, String> {
        let stream = Self::restore_records(verifier, store, version, checkpoint, at)?;
        let facts = stream.latest()?.ok_or("missing retained policy facts")?;
        stream.verifier.validate_header(&facts.lease, at)?;
        Ok(stream)
    }

    pub(crate) fn restore_retained(
        verifier: Verifier,
        store: &ArtifactStore,
        version: u64,
        checkpoint: ArtifactId,
        at: i64,
    ) -> Result<Self, String> {
        Self::restore_records(verifier, store, version, checkpoint, at)
    }

    /// The facts a block was built on: its record list, then the embedded
    /// heartbeat if one renewed the lease, fresh at the block timestamp `at`.
    /// Missing or expired lease evidence fails closed.
    pub fn restore_for_block(
        verifier: Verifier,
        store: &ArtifactStore,
        version: u64,
        checkpoint: ArtifactId,
        lease: Option<&SignedEnvelope>,
        at: i64,
    ) -> Result<Arc<AppliedFacts>, String> {
        let stream = Self::restore_records(verifier, store, version, checkpoint, at)?;
        if let Some(lease) = lease {
            stream.restore_record("heartbeat", &lease.to_wire(), at, None)?;
        }
        let facts = stream.latest()?.ok_or("missing retained policy facts")?;
        stream.verifier.validate_header(&facts.lease, at)?;
        if facts.checkpoint != Some(checkpoint) {
            return Err("policy checkpoint state mismatch".into());
        }
        Ok(facts)
    }

    /// The generation of list (`version`, `checkpoint`): walk its chain back
    /// to the snapshot through each list's `previous` (the stored ids commit
    /// to the whole chain), then re-verify and re-apply every record forward,
    /// each generation installed with its own list, which it must reproduce
    /// field for field.
    fn restore_records(
        verifier: Verifier,
        store: &ArtifactStore,
        version: u64,
        checkpoint: ArtifactId,
        at: i64,
    ) -> Result<Self, String> {
        let invalid = || "invalid policy checkpoint".to_owned();
        let mut chain: Vec<(ListRef, RecordList)> = Vec::new();
        let mut next = Some(ListRef {
            version,
            list: checkpoint,
        });
        while let Some(at_ref) = next {
            if chain.len() >= MAX_CHAIN_RECORDS {
                return Err(invalid());
            }
            let list: RecordList = decode_strict(&store.get_list_bounded(
                at_ref.version,
                at_ref.list,
                MAX_LIST_BYTES,
            )?)?;
            let snapshot = list.records == 1;
            // One shape per position: a snapshot opens the chain, every
            // other record is a delta naming the generation it extends.
            if list.format_version != LIST_FORMAT
                || list.facts_version != at_ref.version
                || list.record.version != list.facts_version
                || list.records == 0
                || list.records > MAX_CHAIN_RECORDS as u64
                || snapshot != list.previous.is_none()
                || snapshot != (list.base_version == list.facts_version)
                || list.record.kind != if snapshot { "snapshot" } else { "delta" }
                || list.base_version > list.facts_version
            {
                return Err(invalid());
            }
            // Consistent with the list read before, whose `previous` named
            // this one: same chain, one record shorter, an older version.
            if let Some((child, child_list)) = chain.last()
                && (child_list.records != list.records + 1
                    || child_list.base_version != list.base_version
                    || at_ref.version >= child.version)
            {
                return Err(invalid());
            }
            next = list.previous;
            chain.push((at_ref, list));
        }
        let stream = Self::new(verifier);
        for (list_ref, list) in chain.iter().rev() {
            let wire = store.get_record(list.record.version, list.record.envelope)?;
            stream.restore_record(&list.record.kind, &wire, at, Some(list_ref.list))?;
            let facts = stream.latest()?.ok_or("missing retained policy facts")?;
            if facts.version() != list.facts_version
                || facts.digest() != list.facts_digest
                || facts.list()? != *list
            {
                return Err("policy checkpoint state mismatch".into());
            }
        }
        Ok(stream)
    }

    /// Re-verify and apply one archived record on the installed generation,
    /// installing the result with `checkpoint` as its durable list (a
    /// heartbeat keeps its generation's).
    fn restore_record(
        &self,
        kind: &str,
        wire: &[u8],
        at: i64,
        checkpoint: Option<ArtifactId>,
    ) -> Result<(), String> {
        let payload = self.verifier.open(kind, wire)?;
        let value: serde_json::Value = decode_strict(&payload)?;
        let issued = value
            .get("issued_at")
            .and_then(|v| v.as_i64())
            .ok_or("invalid archived policy timestamp")?;
        if issued > at.saturating_add(5) {
            return Err("future archived policy facts".into());
        }
        match self.prepare(kind, wire, issued)? {
            Prepared::Unchanged(_) => Ok(()),
            Prepared::Next { base, next, .. } => {
                let next = match checkpoint {
                    Some(list) => next.with_checkpoint(list),
                    None => *next,
                };
                self.install(base.as_ref(), Arc::new(next))
            }
        }
    }

    pub fn pin(&self, now: i64, minimum_version: u64) -> Result<Arc<AppliedFacts>, String> {
        let facts = self.latest()?.ok_or("missing policy facts")?;
        self.check(&facts, now, minimum_version)?;
        Ok(facts)
    }

    fn check(&self, facts: &AppliedFacts, now: i64, minimum_version: u64) -> Result<(), String> {
        self.verifier.validate_header(&facts.lease, now)?;
        if facts.version() < minimum_version {
            return Err("policy facts are behind execution context".into());
        }
        Ok(())
    }

    /// `pin`, registering the pinned versions as a collection root until the
    /// returned guard is dropped (a candidate block's whole life).
    pub fn pin_tracked(
        self: &Arc<Self>,
        now: i64,
        minimum_version: u64,
    ) -> Result<(Arc<AppliedFacts>, FactPin), String> {
        let mut current = self.current.lock().map_err(|_| "fact stream unavailable")?;
        let facts = current.facts.clone().ok_or("missing policy facts")?;
        self.check(&facts, now, minimum_version)?;
        current.next_pin += 1;
        let id = current.next_pin;
        current
            .pins
            .insert(id, (facts.version(), facts.base_version()));
        Ok((
            facts,
            FactPin {
                stream: self.clone(),
                id,
            },
        ))
    }

    /// The lowest (facts version, base version) over the installed
    /// generation and every pinned candidate: what collection must keep.
    pub fn roots(&self) -> Result<Option<(u64, u64)>, String> {
        let current = self.current.lock().map_err(|_| "fact stream unavailable")?;
        Ok(current
            .facts
            .iter()
            .map(|facts| (facts.version(), facts.base_version()))
            .chain(current.pins.values().copied())
            .reduce(|(facts, base), (f, b)| (facts.min(f), base.min(b))))
    }

    /// Watermark/status only; this does not authorize execution with expired facts.
    pub fn latest(&self) -> Result<Option<Arc<AppliedFacts>>, String> {
        Ok(self
            .current
            .lock()
            .map_err(|_| "fact stream unavailable")?
            .facts
            .clone())
    }

    /// Validate in memory only and install: no durability. Unit tests use it;
    /// a node installs through `PolicyRuntime::accept_facts`, restore through
    /// `prepare` and `install`, and candidate blocks refuse facts without a
    /// durable record list.
    pub fn accept(
        &self,
        kind: &str,
        envelope: &[u8],
        now: i64,
    ) -> Result<Arc<AppliedFacts>, String> {
        match self.prepare(kind, envelope, now)? {
            Prepared::Unchanged(facts) => Ok(facts),
            Prepared::Next { base, next, .. } => {
                let next = Arc::new(*next);
                self.install(base.as_ref(), next.clone())?;
                Ok(next)
            }
        }
    }

    /// Install `next` if `base` is still the installed generation (compare and
    /// swap), so a stale writer can never overwrite a newer generation.
    pub(crate) fn install(
        &self,
        base: Option<&Arc<AppliedFacts>>,
        next: Arc<AppliedFacts>,
    ) -> Result<(), String> {
        let mut current = self.current.lock().map_err(|_| "fact stream unavailable")?;
        let unchanged = match (current.facts.as_ref(), base) {
            (None, None) => true,
            (Some(current), Some(base)) => Arc::ptr_eq(current, base),
            _ => false,
        };
        if !unchanged {
            return Err("policy facts changed concurrently".into());
        }
        let version = next.version();
        current.facts = Some(next);
        // Only a version change wakes waiters (not a heartbeat).
        self.versions.send_if_modified(|installed| {
            let changed = *installed != version;
            *installed = version;
            changed
        });
        Ok(())
    }

    /// Verify and validate one envelope against the latest installed
    /// generation. The stream lock is held only to read that generation:
    /// verification, decoding and delta application run outside it.
    pub fn prepare(&self, kind: &str, wire: &[u8], now: i64) -> Result<Prepared, String> {
        let envelope = self.verifier.open_envelope(kind, wire)?;
        let payload = &envelope.payload;
        let digest = B256::from_slice(&Sha256::digest(payload));
        let id = ArtifactId::of(wire);
        let current = self.latest()?;
        let next = match kind {
            "snapshot" => {
                let snapshot: Snapshot = decode_strict(payload)?;
                self.verifier.validate_header(&snapshot.header, now)?;
                validate_snapshot(&snapshot)?;
                if let Some(old) = current.as_ref() {
                    if snapshot.version == old.version() && digest == old.digest {
                        return Ok(Prepared::Unchanged(old.clone()));
                    }
                    if snapshot.version <= old.version() {
                        return Err("conflicting or stale policy snapshot".into());
                    }
                }
                AppliedFacts {
                    lease: snapshot.header.clone(),
                    max_issued: snapshot.header.issued_at,
                    record: ArchivedRecord {
                        kind: kind.into(),
                        version: snapshot.version,
                        envelope: id,
                    },
                    base_version: snapshot.version,
                    chain_records: 1,
                    previous: None,
                    snapshot: Arc::new(snapshot),
                    digest,
                    chain_bytes: wire.len(),
                    heartbeat: None,
                    checkpoint: None,
                }
            }
            "delta" => {
                let delta: Delta = decode_strict(payload)?;
                self.verifier.validate_header(&delta.header, now)?;
                if delta.previous_version == 0
                    || delta.version <= delta.previous_version
                    || !hex_digest(&delta.previous_digest)
                {
                    return Err("invalid policy delta".into());
                }
                let old = current
                    .as_ref()
                    .ok_or("missing bootstrap policy snapshot")?;
                if delta.version == old.version() && digest == old.digest {
                    return Ok(Prepared::Unchanged(old.clone()));
                }
                if delta.previous_version != old.version()
                    || delta.previous_digest != hex::encode(old.digest)
                {
                    return Err("resynchronisation required: policy delta gap or conflict".into());
                }
                if old.chain_records >= MAX_CHAIN_RECORDS
                    || old.chain_bytes + wire.len() > MAX_CHAIN_BYTES
                {
                    return Err("resynchronisation required: policy checkpoint limit".into());
                }
                let snapshot = apply_delta(old.snapshot(), &delta)?;
                AppliedFacts {
                    max_issued: old.max_issued.max(delta.header.issued_at),
                    lease: delta.header,
                    snapshot: Arc::new(snapshot),
                    digest,
                    record: ArchivedRecord {
                        kind: kind.into(),
                        version: delta.version,
                        envelope: id,
                    },
                    base_version: old.base_version,
                    chain_records: old.chain_records + 1,
                    previous: Some((old.version(), old.checkpoint)),
                    chain_bytes: old.chain_bytes + wire.len(),
                    heartbeat: None,
                    checkpoint: None,
                }
            }
            "heartbeat" => {
                let heartbeat: Heartbeat = decode_strict(payload)?;
                self.verifier.validate_header(&heartbeat.header, now)?;
                let old = current
                    .as_ref()
                    .ok_or("missing bootstrap policy snapshot")?;
                if heartbeat.version != old.version() || heartbeat.digest != hex::encode(old.digest)
                {
                    return Err("policy heartbeat state mismatch".into());
                }
                if heartbeat.header.issued_at < old.lease.issued_at
                    || heartbeat.header.expires_at < old.lease.expires_at
                {
                    return Err("stale policy heartbeat".into());
                }
                if heartbeat.header.expires_at == old.lease.expires_at
                    && heartbeat.header.issued_at == old.lease.issued_at
                {
                    return Ok(Prepared::Unchanged(old.clone()));
                }
                AppliedFacts {
                    lease: heartbeat.header,
                    heartbeat: Some(Arc::new(envelope.clone())),
                    ..old.as_ref().clone()
                }
            }
            _ => return Err("unexpected policy fact message kind".into()),
        };
        Ok(Prepared::Next {
            base: current,
            next: Box::new(next),
            record: kind != "heartbeat",
        })
    }
}

fn apply_delta(previous: &Snapshot, delta: &Delta) -> Result<Snapshot, String> {
    let mut next = previous.clone();
    update_rows(
        &mut next.principals,
        &delta.upserts.principals,
        &delta.deletes.principals,
        |p| p.id.clone(),
    )?;
    update_rows(
        &mut next.groups,
        &delta.upserts.groups,
        &delta.deletes.groups,
        |g| g.id.clone(),
    )?;
    update_rows(
        &mut next.contracts,
        &delta.upserts.contracts,
        &delta.deletes.contracts,
        |c| c.address.clone(),
    )?;
    update_rows(
        &mut next.policies,
        &delta.upserts.policies,
        &delta.deletes.policies,
        |p| {
            if p.group_id.is_empty() {
                p.org_id.clone()
            } else {
                format!("{}\0{}", p.org_id, p.group_id)
            }
        },
    )?;
    let deleted_sanctions = delta
        .deletes
        .sanctions
        .iter()
        .map(sanction_key)
        .collect::<Vec<_>>();
    update_rows(
        &mut next.sanctions,
        &delta.upserts.sanctions,
        &deleted_sanctions,
        sanction_key,
    )?;
    next.version = delta.version;
    next.header = delta.header.clone();
    validate_snapshot(&next)?;
    Ok(next)
}

fn sanction_key(sanction: &Sanction) -> String {
    format!("{}\0{}", sanction.org_id, sanction.address)
}

fn update_rows<T: Clone>(
    rows: &mut Vec<T>,
    upserts: &[T],
    deletes: &[String],
    key: impl Fn(&T) -> String,
) -> Result<(), String> {
    let mut seen = HashSet::new();
    let mut indexed: BTreeMap<String, T> = rows.iter().map(|row| (key(row), row.clone())).collect();
    for row in upserts {
        let id = key(row);
        if !seen.insert(id.clone()) {
            return Err("duplicate policy delta key".into());
        }
        indexed.insert(id, row.clone());
    }
    for id in deletes {
        if !seen.insert(id.clone()) || indexed.remove(id).is_none() {
            return Err("conflicting or missing policy delta key".into());
        }
    }
    *rows = indexed.into_values().collect();
    Ok(())
}
