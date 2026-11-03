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

/// The durable record list: the snapshot and deltas a generation was built
/// from, by version and content address. Written once per snapshot/delta;
/// every block manifest built on that generation references it by id.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RecordList {
    format_version: u32,
    facts_version: u64,
    facts_digest: B256,
    records: Vec<ArchivedRecord>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
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
    records: Arc<Vec<ArchivedRecord>>,
    chain_bytes: usize,
    heartbeat: Option<Arc<SignedEnvelope>>,
    /// The durable record-list object, once the records are on disk. Only
    /// durable facts may be pinned by a candidate block.
    checkpoint: Option<ArtifactId>,
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
    /// The version of the snapshot this generation's chain starts from.
    pub fn base_version(&self) -> u64 {
        self.records
            .first()
            .map(|record| record.version)
            .unwrap_or(0)
    }

    pub(crate) fn record_list(&self) -> Result<Vec<u8>, String> {
        serde_json::to_vec(&RecordList {
            format_version: 3,
            facts_version: self.version(),
            facts_digest: self.digest,
            records: self.records.as_ref().clone(),
        })
        .map_err(|_| "invalid policy record list".into())
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
        next: AppliedFacts,
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
        }
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
            stream.restore_record("heartbeat", &lease.to_wire(), at)?;
        }
        let facts = stream.latest()?.ok_or("missing retained policy facts")?;
        stream.verifier.validate_header(&facts.lease, at)?;
        if facts.checkpoint != Some(checkpoint) {
            return Err("policy checkpoint state mismatch".into());
        }
        Ok(facts)
    }

    fn restore_records(
        verifier: Verifier,
        store: &ArtifactStore,
        version: u64,
        checkpoint: ArtifactId,
        at: i64,
    ) -> Result<Self, String> {
        let list: RecordList = decode_strict(&store.get_list(version, checkpoint)?)?;
        if list.format_version != 3
            || list.facts_version != version
            || list.records.is_empty()
            || list.records.len() > MAX_CHAIN_RECORDS
        {
            return Err("invalid policy checkpoint".into());
        }
        let stream = Self::new(verifier);
        for (index, record) in list.records.iter().enumerate() {
            if record.kind != if index == 0 { "snapshot" } else { "delta" } {
                return Err("invalid checkpoint record order".into());
            }
            stream.restore_record(
                &record.kind,
                &store.get_record(record.version, record.envelope)?,
                at,
            )?;
        }
        let facts = stream.latest()?.ok_or("missing retained policy facts")?;
        if facts.version() != list.facts_version
            || facts.digest() != list.facts_digest
            || facts
                .records
                .as_ref()
                .iter()
                .map(|r| (r.version, r.envelope))
                .ne(list.records.iter().map(|r| (r.version, r.envelope)))
        {
            return Err("policy checkpoint state mismatch".into());
        }
        stream.install(Some(&facts), Arc::new(facts.with_checkpoint(checkpoint)))?;
        Ok(stream)
    }

    fn restore_record(&self, kind: &str, wire: &[u8], at: i64) -> Result<(), String> {
        let payload = self.verifier.open(kind, wire)?;
        let value: serde_json::Value = decode_strict(&payload)?;
        let issued = value
            .get("issued_at")
            .and_then(|v| v.as_i64())
            .ok_or("invalid archived policy timestamp")?;
        if issued > at.saturating_add(5) {
            return Err("future archived policy facts".into());
        }
        self.accept(kind, wire, issued)?;
        Ok(())
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

    /// Validate in memory only and install: no durability. Unit tests and
    /// restore use it; a node installs through `PolicyRuntime::accept_facts`,
    /// and candidate blocks refuse facts without a durable record list.
    pub fn accept(
        &self,
        kind: &str,
        envelope: &[u8],
        now: i64,
    ) -> Result<Arc<AppliedFacts>, String> {
        match self.prepare(kind, envelope, now)? {
            Prepared::Unchanged(facts) => Ok(facts),
            Prepared::Next { base, next, .. } => {
                let next = Arc::new(next);
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
        current.facts = Some(next);
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
                let records = Arc::new(vec![ArchivedRecord {
                    kind: kind.into(),
                    version: snapshot.version,
                    envelope: id,
                }]);
                AppliedFacts {
                    lease: snapshot.header.clone(),
                    snapshot: Arc::new(snapshot),
                    digest,
                    records,
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
                if old.records.len() >= MAX_CHAIN_RECORDS
                    || old.chain_bytes + wire.len() > MAX_CHAIN_BYTES
                {
                    return Err("resynchronisation required: policy checkpoint limit".into());
                }
                let snapshot = apply_delta(old.snapshot(), &delta)?;
                let mut records = old.records.as_ref().clone();
                records.push(ArchivedRecord {
                    kind: kind.into(),
                    version: delta.version,
                    envelope: id,
                });
                AppliedFacts {
                    lease: delta.header,
                    snapshot: Arc::new(snapshot),
                    digest,
                    records: Arc::new(records),
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
            next,
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
