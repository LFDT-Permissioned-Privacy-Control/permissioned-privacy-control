//! Durable local evidence for produced blocks. This layer authenticates content
//! addresses, not issuer signatures. Replay must also verify the retained signed
//! records and identities before constructing an execution handle.
//!
//! Layout of the state directory (version 4; older layouts are refused, there
//! is no importer):
//! - `LAYOUT`: the layout marker, written first on initialisation;
//! - `LOCK`: held exclusively by the one node process using the directory;
//! - `tmp/`: files being written, cleared at every open;
//! - `facts/<version / 4096 as {:08x}>/<version as {:016x}>-<sha256>`: signed
//!   snapshot and delta records, by their own version;
//! - `lists/<version / 4096 as {:08x}>/<version as {:016x}>-<sha256>`: record
//!   lists, by the facts version they complete; each names its own record and
//!   the list of the generation it extends, back to its chain's snapshot;
//! - `pointers/facts-head`: the installed generation's record list;
//! - `blocks/<height / 4096 as {:08x}>/<height as {:016x}>-<hash>`: one
//!   produced block's manifest, a one-entry segment (see `manifest`);
//! - `blocks/<height / 4096 as {:08x}>/s-<first>-<last>-<last timestamp>-<lowest facts version>-<lowest base version>`
//!   (all `{:016x}`): finalized canonical manifests compacted into one
//!   segment.
//!
//! Versions order fact records: snapshot versions strictly increase, so each
//! fact chain (a snapshot and its deltas) occupies its own ascending version
//! range, and every record and list a list reaches has at least the list's
//! base (snapshot) version. Collection therefore deletes by version range:
//! lists and records below the lowest base version any retained manifest, the
//! installed facts or a pinned candidate uses.

use crate::{
    manifest::{
        BlockManifest, IndexRow, assemble_segment, read_entry, read_entry_at, read_index,
        read_index_at, write_segment,
    },
    storage::{DiskStorage, Storage},
    wire::{Network, decode_strict},
};
use alloy_primitives::{B256, hex};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    fmt, io,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicU64, Ordering},
    },
    time::{SystemTime, UNIX_EPOCH},
};

const MAX_OBJECT: usize = 64 << 20;
static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ArtifactId(B256);
impl ArtifactId {
    /// The content address of `bytes`.
    pub fn of(bytes: &[u8]) -> Self {
        Self(B256::from_slice(&Sha256::digest(bytes)))
    }
    pub fn as_b256(&self) -> B256 {
        self.0
    }
    pub(crate) fn from_b256(value: B256) -> Self {
        Self(value)
    }
}
impl fmt::Display for ArtifactId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex::encode(self.0))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlockDescriptor {
    pub network: Network,
    pub hash: B256,
    pub parent_hash: B256,
    pub number: u64,
    pub timestamp: u64,
    pub transactions: Vec<B256>,
}

/// Whether `publish_manifest` wrote the manifest or found an equivalent one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Published {
    New,
    Existing,
}

/// Block manifests per height bucket directory under `blocks/`, and versions
/// per bucket under `facts/` and `lists/`.
const BUCKET: u64 = 4096;
/// Largest manifest segment file read back whole (a one-entry segment).
const MAX_SEGMENT: usize = 1 << 30;
/// A compacted segment stops growing at this size (a single larger entry gets
/// its own segment).
pub const SEGMENT_BYTES: usize = 64 << 20;
/// Finalized canonical manifests that make a compaction worthwhile before a
/// bucket is complete.
pub const MIN_SEGMENT_BLOCKS: usize = 256;
/// Unlinks per directory sync.
const DELETE_BATCH: usize = 64;
/// Removals per maintenance run.
pub const RUN_REMOVALS: usize = 1024;
/// Per-block files read as collection roots in one run; above it the run
/// defers collection (retention is a minimum, so deferring is safe).
const ROOT_FILES: usize = 65_536;

const LAYOUT: &[u8] = b"ops-node-policy-archive 4\n";

/// How long compacted manifests (and the fact records only they reference)
/// are kept, counted from the block's timestamp. Only finalized blocks are
/// ever pruned.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Retention {
    Forever,
    Seconds(u64),
}

impl Default for Retention {
    fn default() -> Self {
        Self::Seconds(7 * 24 * 3600)
    }
}

impl Retention {
    /// `forever`, or a whole number followed by `s`, `m`, `h` or `d`, at
    /// least one hour: OPS must still be able to read a finalized block's
    /// status after it was reported final.
    pub fn parse(value: &str) -> Result<Self, String> {
        if value == "forever" {
            return Ok(Self::Forever);
        }
        let invalid = || {
            "OPS_NODE_POLICY_MANIFEST_RETENTION must be `forever` or at least 1 hour, as a whole number of s, m, h or d"
                .to_owned()
        };
        let split = value.len().checked_sub(1).ok_or_else(invalid)?;
        if !value.is_char_boundary(split) {
            return Err(invalid());
        }
        let (number, unit) = value.split_at(split);
        let scale = match unit {
            "s" => 1,
            "m" => 60,
            "h" => 3600,
            "d" => 86_400,
            _ => return Err(invalid()),
        };
        if number.is_empty() || !number.bytes().all(|b| b.is_ascii_digit()) {
            return Err(invalid());
        }
        let seconds = number
            .parse::<u64>()
            .ok()
            .and_then(|number| number.checked_mul(scale))
            .filter(|seconds| *seconds >= 3600 && *seconds <= i64::MAX as u64)
            .ok_or_else(invalid)?;
        Ok(Self::Seconds(seconds))
    }

    fn expired(self, timestamp: u64, now: i64) -> bool {
        match self {
            Self::Forever => false,
            Self::Seconds(seconds) => now >= 0 && timestamp.saturating_add(seconds) <= now as u64,
        }
    }
}

/// One run of archive maintenance.
pub struct MaintenanceInput<'a> {
    /// The effective finalized height (never above what Reth has written).
    pub finalized: u64,
    /// The canonical hash at a height (`None` when unknown).
    pub canonical: &'a dyn Fn(u64) -> Option<B256>,
    pub now: i64,
    pub retention: Retention,
    /// The lowest (facts version, base version) over the installed facts and
    /// every pinned candidate, read before this run lists anything.
    pub live: Option<(u64, u64)>,
}

/// What one maintenance run did. `pending`: it stopped at a bound and should
/// run again.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MaintenanceReport {
    pub compacted: usize,
    pub removed_manifests: usize,
    pub pruned_segments: usize,
    pub removed_lists: usize,
    pub removed_records: usize,
    pub pending: bool,
}

impl MaintenanceReport {
    /// Files removed so far in this run.
    pub fn removed(&self) -> usize {
        self.removed_manifests + self.pruned_segments + self.removed_lists + self.removed_records
    }

    /// Removals this run may still make.
    fn budget(&self) -> usize {
        RUN_REMOVALS.saturating_sub(self.removed())
    }
}

/// What a collection pass did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Collected {
    Done,
    /// Stopped at the run's bound: run again now.
    More,
    /// Too many roots to read this run: retry at a later run, not at once.
    Deferred,
}

/// A compacted segment, from its name.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Segment {
    first: u64,
    last: u64,
    last_timestamp: u64,
    facts_version: u64,
    base_version: u64,
    name: String,
}

impl Segment {
    /// The segment holding `rows`.
    fn of(rows: &[IndexRow]) -> Option<Self> {
        let first = rows.iter().map(|row| row.number).min()?;
        let last = rows.iter().map(|row| row.number).max()?;
        let last_timestamp = rows.iter().map(|row| row.timestamp).max()?;
        let facts_version = rows.iter().map(|row| row.facts_version).min()?;
        let base_version = rows.iter().map(|row| row.base_version).min()?;
        Some(Self {
            name: format!(
                "s-{first:016x}-{last:016x}-{last_timestamp:016x}-{facts_version:016x}-{base_version:016x}"
            ),
            first,
            last,
            last_timestamp,
            facts_version,
            base_version,
        })
    }

    fn parse(name: &str) -> Option<Self> {
        let fields = name.strip_prefix("s-")?;
        let parts: Vec<u64> = fields
            .split('-')
            .map(|part| {
                (part.len() == 16)
                    .then(|| u64::from_str_radix(part, 16).ok())
                    .flatten()
            })
            .collect::<Option<_>>()?;
        let [first, last, last_timestamp, facts_version, base_version] = parts[..] else {
            return None;
        };
        (first <= last && first / BUCKET == last / BUCKET && base_version <= facts_version).then(
            || Self {
                first,
                last,
                last_timestamp,
                facts_version,
                base_version,
                name: name.to_owned(),
            },
        )
    }
}

/// A per-block manifest file name: (height, block hash).
fn parse_manifest_name(name: &str) -> Option<(u64, B256)> {
    let (number, hash) = name.split_once('-')?;
    if number.len() != 16 || hash.len() != 64 {
        return None;
    }
    Some((
        u64::from_str_radix(number, 16).ok()?,
        hash.parse::<B256>().ok()?,
    ))
}

/// A versioned object file name: (version, id).
fn parse_versioned_name(name: &str) -> Option<(u64, ArtifactId)> {
    let (version, id) = name.split_once('-')?;
    if version.len() != 16 || id.len() != 64 {
        return None;
    }
    Some((
        u64::from_str_radix(version, 16).ok()?,
        ArtifactId(id.parse::<B256>().ok()?),
    ))
}

#[derive(Debug, Default)]
struct MaintenanceState {
    /// The height bucket compaction works on: every lower bucket is compacted.
    bucket: Option<u64>,
    /// The lowest height bucket that may still hold prunable segments.
    prune_bucket: Option<u64>,
    /// Collection stopped at its bound or was deferred: run it again.
    collect: bool,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Head {
    version: u64,
    list: ArtifactId,
}

pub struct ArtifactStore {
    root: PathBuf,
    storage: Arc<dyn Storage>,
    /// Bucket directories already made durable by this process.
    directories: Mutex<HashSet<PathBuf>>,
    /// Compacted segments per height bucket, loaded lazily from a listing and
    /// changed only under this lock, so a reader can never store a stale
    /// listing over a newly published segment.
    segments: Mutex<HashMap<u64, Arc<Vec<Segment>>>>,
    maintenance: Mutex<MaintenanceState>,
    /// The exclusive state-directory lock: one writer of `facts-head` and of
    /// block evidence per directory.
    _lock: Box<dyn std::any::Any + Send + Sync>,
}

impl fmt::Debug for ArtifactStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ArtifactStore")
            .field("root", &self.root)
            .finish_non_exhaustive()
    }
}

impl ArtifactStore {
    pub fn open(root: impl AsRef<Path>) -> Result<Self, String> {
        Self::open_with(root, Arc::new(DiskStorage))
    }

    /// Open on an explicit storage implementation (tests count and fault-inject).
    pub fn open_with(root: impl AsRef<Path>, storage: Arc<dyn Storage>) -> Result<Self, String> {
        let root = root.as_ref().to_owned();
        storage
            .ensure_private_dir(&root)
            .map_err(private_directory_error)?;
        // Decide on the layout before changing anything: a foreign or older
        // directory is left exactly as it was.
        let names = storage.list(&root).map_err(io_error)?;
        if names.iter().any(|name| name == "LAYOUT") {
            let marker = storage
                .read(&root.join("LAYOUT"), 64)
                .map_err(|_| "cannot read the policy state directory layout marker".to_owned())?
                .unwrap_or_default();
            if marker != LAYOUT {
                return Err(format!(
                    "policy state directory layout {:?} is not the {:?} this node uses; start the node with an empty directory",
                    printable(&marker),
                    printable(LAYOUT)
                ));
            }
        } else if names.iter().all(|name| name.starts_with(".pending-")) {
            // Empty, or an initialisation interrupted before its marker was
            // durable: the marker is the first durable entry.
            publish_immutable(storage.as_ref(), &root, &root, "LAYOUT", LAYOUT)?;
        } else {
            return Err(layout_error());
        }
        let lock = storage
            .lock(&root.join("LOCK"))
            .map_err(|error| match error.kind() {
                io::ErrorKind::WouldBlock => {
                    "policy state directory is in use by another node process".to_owned()
                }
                _ => "cannot lock the policy state directory; it must be on a local \
                      filesystem with advisory locks"
                    .to_owned(),
            })?;
        // An initialisation interrupted before its marker leaves a temp name
        // in the root; with the lock held nobody else is writing one.
        for name in names.iter().filter(|name| name.starts_with(".pending-")) {
            storage.remove(&root.join(name)).map_err(io_error)?;
        }
        for directory in ["tmp", "facts", "lists", "blocks", "pointers"] {
            storage
                .ensure_private_dir(&root.join(directory))
                .map_err(private_directory_error)?;
        }
        // Leftovers of writes interrupted by a crash.
        let temporary = root.join("tmp");
        for name in storage.list(&temporary).map_err(io_error)? {
            storage.remove(&temporary.join(name)).map_err(io_error)?;
        }
        Ok(Self {
            root,
            storage,
            directories: Mutex::new(HashSet::new()),
            segments: Mutex::new(HashMap::new()),
            // A crash may have pruned without collecting: the first run after
            // open collects once.
            maintenance: Mutex::new(MaintenanceState {
                collect: true,
                ..MaintenanceState::default()
            }),
            _lock: lock,
        })
    }

    /// Store a signed snapshot or delta record of `version` (its own
    /// version) durably.
    pub fn put_record(&self, version: u64, wire: &[u8]) -> Result<ArtifactId, String> {
        self.put_versioned("facts", version, wire)
    }

    /// A stored record, checked against its content address.
    pub fn get_record(&self, version: u64, id: ArtifactId) -> Result<Vec<u8>, String> {
        self.get_versioned("facts", version, id, MAX_OBJECT)
    }

    /// Store a record list completing facts `version` durably.
    pub fn put_list(&self, version: u64, bytes: &[u8]) -> Result<ArtifactId, String> {
        self.put_versioned("lists", version, bytes)
    }

    /// A stored record list, checked against its content address.
    pub fn get_list(&self, version: u64, id: ArtifactId) -> Result<Vec<u8>, String> {
        self.get_versioned("lists", version, id, MAX_OBJECT)
    }

    /// `get_list`, refusing a file larger than `limit`.
    pub(crate) fn get_list_bounded(
        &self,
        version: u64,
        id: ArtifactId,
        limit: usize,
    ) -> Result<Vec<u8>, String> {
        self.get_versioned("lists", version, id, limit)
    }

    /// Point `facts-head` at the stored list of facts `version`.
    pub fn set_head(&self, version: u64, list: ArtifactId) -> Result<(), String> {
        self.get_list(version, list)?;
        let bytes = serde_json::to_vec(&Head { version, list })
            .map_err(|_| "invalid execution archive pointer")?;
        self.replace_atomic(&self.root.join("pointers"), "facts-head", &bytes)
    }

    /// The installed generation's record list, if any: (facts version, id).
    pub fn head(&self) -> Result<Option<(u64, ArtifactId)>, String> {
        self.storage
            .read(&self.root.join("pointers").join("facts-head"), 256)
            .map_err(io_error)?
            .map(|bytes| decode_strict::<Head>(&bytes).map(|head| (head.version, head.list)))
            .transpose()
    }

    fn versioned_path(&self, area: &str, version: u64, id: ArtifactId) -> PathBuf {
        self.root
            .join(area)
            .join(bucket_name(version))
            .join(format!("{version:016x}-{id}"))
    }

    fn put_versioned(&self, area: &str, version: u64, bytes: &[u8]) -> Result<ArtifactId, String> {
        if bytes.is_empty() || bytes.len() > MAX_OBJECT || version == 0 {
            return Err("invalid execution artifact size".into());
        }
        let id = ArtifactId::of(bytes);
        let directory = self.directory(&self.root.join(area).join(bucket_name(version)))?;
        self.publish_immutable(&directory, &format!("{version:016x}-{id}"), bytes)?;
        Ok(id)
    }

    fn get_versioned(
        &self,
        area: &str,
        version: u64,
        id: ArtifactId,
        limit: usize,
    ) -> Result<Vec<u8>, String> {
        let bytes = self.read_bounded(&self.versioned_path(area, version, id), limit)?;
        if ArtifactId::of(&bytes) != id {
            return Err("execution artifact digest mismatch".into());
        }
        Ok(bytes)
    }

    /// Publish a produced block's manifest before the block is returned: one
    /// per-height segment file, published with a file `sync_all` and a
    /// directory `sync_all` (a new height bucket adds one directory sync per
    /// 4096 blocks). The record list it references must already be durable.
    /// Idempotent per block: an existing manifest whose transactions carry the
    /// same principals, organizations, signers and outcomes stays (another
    /// build may differ only in lease, facts or identity lease times), also
    /// when two builds of the block publish at the same time.
    pub fn publish_manifest(&self, manifest: &BlockManifest) -> Result<Published, String> {
        self.get_list(manifest.facts_version, manifest.records)?;
        let directory = self.directory(&self.block_directory(manifest.number))?;
        let name = manifest_name(manifest.number, manifest.hash);
        let existing = match self
            .storage
            .read(&directory.join(&name), MAX_SEGMENT)
            .map_err(|_| "invalid execution archive file".to_owned())?
        {
            Some(existing) => {
                self.storage.sync_dir(&directory).map_err(io_error)?;
                existing
            }
            // Another build of this block may link its manifest between this
            // check and this link (concurrent payload builds): its evidence
            // decides, exactly as if it had been there first.
            None => match link_immutable(
                self.storage.as_ref(),
                &self.root.join("tmp"),
                &directory,
                &name,
                &write_segment(&[manifest])?,
                MAX_SEGMENT,
            )? {
                Linked::Published => return Ok(Published::New),
                // The other build published exactly this manifest.
                Linked::Same => return Ok(Published::Existing),
                Linked::Other(existing) => existing,
            },
        };
        let existing = read_entry(&existing, manifest.number, manifest.hash)?
            .ok_or("invalid execution manifest")?;
        if evidence(&existing)? != evidence(manifest)? {
            return Err("conflicting execution manifest".into());
        }
        Ok(Published::Existing)
    }

    /// The manifest of block (number, hash), if this node published it: its
    /// own file, or else a compacted segment, read footer → index → entry.
    /// Reserved for self-import, trusted forensic replay and status lookups;
    /// historical user RPC calls use current permissions instead.
    pub fn manifest(&self, number: u64, hash: B256) -> Result<Option<BlockManifest>, String> {
        let directory = self.block_directory(number);
        if let Some(segment) = self
            .storage
            .read(&directory.join(manifest_name(number, hash)), MAX_SEGMENT)
            .map_err(|_| "invalid execution archive file".to_owned())?
        {
            return read_entry(&segment, number, hash);
        }
        // Compaction registers a segment before it unlinks the originals, so
        // a manifest missing above is in a segment listed now.
        for segment in self
            .bucket_segments(number / BUCKET)?
            .iter()
            .filter(|segment| segment.first <= number && number <= segment.last)
        {
            if let Some(found) = self.segment_entry(&directory.join(&segment.name), number, hash)? {
                return Ok(Some(found));
            }
        }
        Ok(None)
    }

    /// One entry of a compacted segment; `None` if the segment was pruned
    /// meanwhile.
    fn segment_entry(
        &self,
        path: &Path,
        number: u64,
        hash: B256,
    ) -> Result<Option<BlockManifest>, String> {
        let Some(size) = self.storage.size(path).map_err(io_error)? else {
            return Ok(None);
        };
        let read = |offset: u64, length: usize| self.read_at(path, offset, length);
        match read_entry_at(&read, size, number, hash) {
            Err(_) if self.storage.size(path).map_err(io_error)?.is_none() => Ok(None),
            other => other,
        }
    }

    fn read_at(&self, path: &Path, offset: u64, length: usize) -> Result<Vec<u8>, String> {
        self.storage
            .read_at(path, offset, length)
            .map_err(|_| "invalid execution archive file".to_owned())?
            .ok_or_else(|| "invalid execution archive file".to_owned())
    }

    /// The verified index rows of the segment file at `path` (positional
    /// reads); `None` if it is gone.
    fn rows_at(&self, path: &Path) -> Result<Option<Vec<IndexRow>>, String> {
        let Some(size) = self.storage.size(path).map_err(io_error)? else {
            return Ok(None);
        };
        let read = |offset: u64, length: usize| self.read_at(path, offset, length);
        read_index_at(&read, size).map(Some)
    }

    fn block_directory(&self, number: u64) -> PathBuf {
        self.root.join("blocks").join(bucket_name(number))
    }

    /// The compacted segments of a height bucket, sorted by first height.
    fn bucket_segments(&self, bucket: u64) -> Result<Arc<Vec<Segment>>, String> {
        let mut segments = self
            .segments
            .lock()
            .map_err(|_| "execution archive unavailable")?;
        if let Some(known) = segments.get(&bucket) {
            return Ok(known.clone());
        }
        let listed = self.list_names(&self.root.join("blocks").join(format!("{bucket:08x}")))?;
        let mut found: Vec<Segment> = listed
            .iter()
            .filter_map(|name| Segment::parse(name))
            .collect();
        found.sort_by_key(|segment| (segment.first, segment.last));
        let found = Arc::new(found);
        segments.insert(bucket, found.clone());
        Ok(found)
    }

    fn change_segments(
        &self,
        bucket: u64,
        change: impl FnOnce(&mut Vec<Segment>),
    ) -> Result<(), String> {
        let current = self.bucket_segments(bucket)?;
        let mut segments = self
            .segments
            .lock()
            .map_err(|_| "execution archive unavailable")?;
        let mut next = segments
            .get(&bucket)
            .cloned()
            .unwrap_or(current)
            .as_ref()
            .clone();
        change(&mut next);
        next.sort_by_key(|segment| (segment.first, segment.last));
        segments.insert(bucket, Arc::new(next));
        Ok(())
    }

    /// Names in `directory`; none if it does not exist.
    fn list_names(&self, directory: &Path) -> Result<Vec<String>, String> {
        match self.storage.list(directory) {
            Ok(names) => Ok(names),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(Vec::new()),
            Err(error) => Err(io_error(error)),
        }
    }

    /// Bucket numbers present under an area (`blocks`, `facts`, `lists`),
    /// ascending.
    fn buckets(&self, area: &str) -> Result<Vec<u64>, String> {
        let mut buckets: Vec<u64> = self
            .list_names(&self.root.join(area))?
            .iter()
            .filter(|name| name.len() == 8)
            .filter_map(|name| u64::from_str_radix(name, 16).ok())
            .collect();
        buckets.sort_unstable();
        Ok(buckets)
    }

    /// The directory, made durable once per process.
    fn directory(&self, directory: &Path) -> Result<PathBuf, String> {
        let mut known = self
            .directories
            .lock()
            .map_err(|_| "execution archive unavailable")?;
        if !known.contains(directory) {
            self.storage
                .ensure_private_dir(directory)
                .map_err(private_directory_error)?;
            known.insert(directory.to_owned());
        }
        Ok(directory.to_owned())
    }

    fn read_bounded(&self, path: &Path, limit: usize) -> Result<Vec<u8>, String> {
        self.storage
            .read(path, limit)
            .map_err(|_| "invalid execution archive file".to_owned())?
            .ok_or_else(|| "invalid execution archive file".to_owned())
    }

    fn publish_immutable(&self, directory: &Path, name: &str, bytes: &[u8]) -> Result<(), String> {
        publish_immutable(
            self.storage.as_ref(),
            &self.root.join("tmp"),
            directory,
            name,
            bytes,
        )
    }

    /// temp file (in `tmp/`) → `sync_all` → rename → directory `sync_all`:
    /// 2 syncs.
    fn replace_atomic(&self, directory: &Path, key: &str, bytes: &[u8]) -> Result<(), String> {
        let temporary = self.root.join("tmp").join(temporary_name());
        self.storage
            .write_synced(&temporary, bytes)
            .map_err(io_error)?;
        let result = self
            .storage
            .rename(&temporary, &directory.join(key))
            .and_then(|_| self.storage.sync_dir(directory))
            .map_err(io_error);
        if result.is_err() {
            let _ = self.storage.remove(&temporary);
        }
        result
    }

    /// Remove `paths` (each in `directory`), one directory sync per batch.
    fn remove_all(&self, directory: &Path, names: &[String]) -> Result<usize, String> {
        let mut removed = 0;
        for batch in names.chunks(DELETE_BATCH) {
            for name in batch {
                if self
                    .storage
                    .remove(&directory.join(name))
                    .map_err(io_error)?
                {
                    removed += 1;
                }
            }
            self.storage.sync_dir(directory).map_err(io_error)?;
        }
        Ok(removed)
    }

    /// One bounded maintenance run, never on the block-publication path:
    /// compact finalized canonical manifests of one height bucket and remove
    /// noncanonical ones at or below finality; prune segments past
    /// retention; then collect fact records and lists no root uses.
    pub fn maintain(&self, input: &MaintenanceInput) -> Result<MaintenanceReport, String> {
        let mut state = self
            .maintenance
            .lock()
            .map_err(|_| "execution archive unavailable")?;
        let mut report = MaintenanceReport::default();
        self.compact(&mut state, input, &mut report)?;
        self.prune(&mut state, input, &mut report)?;
        // Collection follows a prune: compaction only moves roots into a
        // segment, and facts used only by removed noncanonical builds are
        // collected with the next prune.
        if input.retention != Retention::Forever && (state.collect || report.pruned_segments > 0) {
            let collected = self.collect(input, &mut report)?;
            state.collect = collected != Collected::Done;
            report.pending |= collected == Collected::More;
        }
        Ok(report)
    }

    /// The bucket compaction starts from after a restart: the highest bucket
    /// holding a segment (every lower one is complete), else the lowest bucket.
    fn first_bucket(&self) -> Result<Option<u64>, String> {
        let buckets = self.buckets("blocks")?;
        for bucket in buckets.iter().rev() {
            if !self.bucket_segments(*bucket)?.is_empty() {
                return Ok(Some(*bucket));
            }
        }
        Ok(buckets.first().copied())
    }

    fn compact(
        &self,
        state: &mut MaintenanceState,
        input: &MaintenanceInput,
        report: &mut MaintenanceReport,
    ) -> Result<(), String> {
        let bucket = match state.bucket {
            Some(bucket) => bucket,
            None => match self.first_bucket()? {
                Some(bucket) => bucket,
                None => return Ok(()),
            },
        };
        state.bucket = Some(bucket);
        if bucket * BUCKET > input.finalized {
            return Ok(());
        }
        let directory = self.block_directory(bucket * BUCKET);
        let complete = bucket * BUCKET + BUCKET - 1 <= input.finalized;
        let segments = self.bucket_segments(bucket)?;
        let covered_through = segments.iter().map(|segment| segment.last).max();
        let mut rows = HashMap::new();
        let mut leftovers = Vec::new();
        let mut noncanonical = Vec::new();
        let mut candidates: BTreeMap<u64, String> = BTreeMap::new();
        let mut later = false;
        for name in self.list_names(&directory)? {
            let Some((number, hash)) = parse_manifest_name(&name) else {
                continue;
            };
            if number > input.finalized {
                later = true;
                continue;
            }
            // An original left by an interrupted compaction.
            if covered_through.is_some_and(|last| number <= last)
                && self.covered(&directory, &segments, &mut rows, number, hash)?
            {
                leftovers.push(name);
                continue;
            }
            match (input.canonical)(number) {
                Some(canonical) if canonical == hash => {
                    candidates.insert(number, name);
                }
                // At or below finality another block is canonical: this one
                // never will be (a discarded rebuild or reorged candidate).
                Some(_) => noncanonical.push(name),
                // Unknown: keep it.
                None => later = true,
            }
        }
        if !leftovers.is_empty() {
            // The segment covering them must be durable before they go.
            self.storage.sync_dir(&directory).map_err(io_error)?;
            let more = leftovers.len() > report.budget();
            leftovers.truncate(report.budget());
            report.removed_manifests += self.remove_all(&directory, &leftovers)?;
            report.pending |= more;
        }
        let more = noncanonical.len() > report.budget();
        noncanonical.truncate(report.budget());
        report.removed_manifests += self.remove_all(&directory, &noncanonical)?;
        report.pending |= more;
        let budget = report.budget();
        if !candidates.is_empty() && (complete || candidates.len() >= MIN_SEGMENT_BLOCKS) {
            if budget == 0 {
                report.pending = true;
                return Ok(());
            }
            let (names, published) =
                self.compact_segment(&directory, bucket, &candidates, budget)?;
            report.compacted += published;
            report.removed_manifests += self.remove_all(&directory, &names)?;
            if names.len() < candidates.len() {
                report.pending = true;
            }
            return Ok(());
        }
        if complete && candidates.is_empty() && !later && !report.pending {
            state.bucket = Some(bucket + 1);
            report.pending = (bucket + 1) * BUCKET <= input.finalized;
        }
        Ok(())
    }

    /// Whether (number, hash) is in one of `segments`; each segment's index
    /// is read at most once per run (`rows`).
    fn covered(
        &self,
        directory: &Path,
        segments: &[Segment],
        rows: &mut HashMap<String, Vec<IndexRow>>,
        number: u64,
        hash: B256,
    ) -> Result<bool, String> {
        for segment in segments
            .iter()
            .filter(|segment| segment.first <= number && number <= segment.last)
        {
            if !rows.contains_key(&segment.name) {
                let read = self
                    .rows_at(&directory.join(&segment.name))?
                    .unwrap_or_default();
                rows.insert(segment.name.clone(), read);
            }
            if rows[&segment.name]
                .iter()
                .any(|row| row.number == number && row.hash == hash)
            {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Copy the lowest candidates' verified frames, unchanged, into one
    /// segment of at most `SEGMENT_BYTES` (a larger single entry alone),
    /// publish it, then register it; returns the originals to unlink.
    fn compact_segment(
        &self,
        directory: &Path,
        bucket: u64,
        candidates: &BTreeMap<u64, String>,
        limit: usize,
    ) -> Result<(Vec<String>, usize), String> {
        let mut entries = Vec::new();
        let mut names = Vec::new();
        let mut bytes = 0usize;
        for (number, name) in candidates {
            let path = directory.join(name);
            let Some(file) = self
                .storage
                .read(&path, MAX_SEGMENT)
                .map_err(|_| "invalid execution archive file".to_owned())?
            else {
                continue;
            };
            let rows = read_index(&file)?;
            let [row] = rows.as_slice() else {
                return Err("invalid execution manifest".into());
            };
            if row.number != *number || manifest_name(row.number, row.hash) != *name {
                return Err("invalid execution manifest".into());
            }
            let frame =
                file[row.offset as usize..(row.offset + row.length as u64) as usize].to_vec();
            if !entries.is_empty()
                && (bytes + frame.len() > SEGMENT_BYTES || entries.len() >= limit)
            {
                break;
            }
            bytes += frame.len();
            entries.push((row.clone(), frame));
            names.push(name.clone());
        }
        let rows: Vec<IndexRow> = entries.iter().map(|(row, _)| row.clone()).collect();
        let Some(segment) = Segment::of(&rows) else {
            return Ok((Vec::new(), 0));
        };
        let encoded = assemble_segment(entries)?;
        self.publish_immutable(directory, &segment.name, &encoded)?;
        let published = rows.len();
        self.change_segments(bucket, |segments| {
            if !segments.iter().any(|known| known.name == segment.name) {
                segments.push(segment);
            }
        })?;
        Ok((names, published))
    }

    fn prune(
        &self,
        state: &mut MaintenanceState,
        input: &MaintenanceInput,
        report: &mut MaintenanceReport,
    ) -> Result<(), String> {
        if input.retention == Retention::Forever {
            return Ok(());
        }
        let compacting = state.bucket.unwrap_or(0);
        let mut bucket = match state.prune_bucket {
            Some(bucket) => bucket,
            None => match self.buckets("blocks")?.first() {
                Some(bucket) => *bucket,
                None => return Ok(()),
            },
        };
        while bucket <= compacting && report.budget() > 0 {
            let directory = self.block_directory(bucket * BUCKET);
            let expired: Vec<Segment> = self
                .bucket_segments(bucket)?
                .iter()
                .filter(|segment| {
                    segment.last <= input.finalized
                        && input.retention.expired(segment.last_timestamp, input.now)
                })
                .take(report.budget())
                .cloned()
                .collect();
            let all = expired.len() == self.bucket_segments(bucket)?.len();
            if !expired.is_empty() {
                let names: Vec<String> =
                    expired.iter().map(|segment| segment.name.clone()).collect();
                // Unregistered first: a lookup that misses the file reads
                // as absent, never as a damaged archive.
                self.change_segments(bucket, |segments| {
                    segments.retain(|segment| !names.contains(&segment.name))
                })?;
                report.pruned_segments += self.remove_all(&directory, &names)?;
            }
            // A bucket below the one being compacted with no segment left is
            // done, and its directory goes; segments are pruned oldest first.
            if all && bucket < compacting {
                self.remove_directory(&directory)?;
                if let Ok(mut segments) = self.segments.lock() {
                    segments.remove(&bucket);
                }
                bucket += 1;
            } else {
                break;
            }
        }
        state.prune_bucket = Some(bucket);
        if report.budget() == 0 {
            report.pending = true;
        }
        Ok(())
    }

    /// Delete record lists and records below the lowest base version over
    /// every root: retained segments and per-block manifests, the installed
    /// facts and pinned candidates (in `input.live`, read before this
    /// listing). A root's list reaches every list of its chain from the
    /// snapshot on, so lists go by the base version too (the roots' facts
    /// versions are no longer a bound; segment names keep them).
    fn collect(
        &self,
        input: &MaintenanceInput,
        report: &mut MaintenanceReport,
    ) -> Result<Collected, String> {
        let mut lowest = input.live;
        let mut lower = |facts: u64, base: u64| {
            lowest = Some(match lowest {
                None => (facts, base),
                Some((f, b)) => (f.min(facts), b.min(base)),
            });
        };
        let mut files = 0;
        for bucket in self.buckets("blocks")? {
            for segment in self.bucket_segments(bucket)?.iter() {
                lower(segment.facts_version, segment.base_version);
            }
            let directory = self.block_directory(bucket * BUCKET);
            for name in self.list_names(&directory)? {
                if parse_manifest_name(&name).is_none() {
                    continue;
                }
                files += 1;
                if files > ROOT_FILES {
                    return Ok(Collected::Deferred);
                }
                if let Some(rows) = self.rows_at(&directory.join(&name))? {
                    for row in rows {
                        lower(row.facts_version, row.base_version);
                    }
                }
            }
        }
        let Some((_, base)) = lowest else {
            return Ok(Collected::Done);
        };
        let budget = report.budget();
        if budget == 0 {
            return Ok(Collected::More);
        }
        let lists = self.remove_below("lists", base, budget)?;
        let records = self.remove_below("facts", base, budget - lists)?;
        report.removed_lists += lists;
        report.removed_records += records;
        Ok(if lists + records >= budget {
            Collected::More
        } else {
            Collected::Done
        })
    }

    /// Remove an empty directory, made durable in its parent, and forget it.
    fn remove_directory(&self, directory: &Path) -> Result<(), String> {
        if self.storage.remove_dir(directory).map_err(io_error)? {
            if let Some(parent) = directory.parent() {
                self.storage.sync_dir(parent).map_err(io_error)?;
            }
            if let Ok(mut known) = self.directories.lock() {
                known.remove(directory);
            }
        }
        Ok(())
    }

    /// Remove at most `limit` objects of `area` with a version below `bound`,
    /// lowest first.
    fn remove_below(&self, area: &str, bound: u64, limit: usize) -> Result<usize, String> {
        let mut removed = 0;
        for bucket in self.buckets(area)? {
            if bucket * BUCKET >= bound || removed >= limit {
                break;
            }
            let directory = self.root.join(area).join(format!("{bucket:08x}"));
            let mut names: Vec<String> = self
                .list_names(&directory)?
                .into_iter()
                .filter(|name| {
                    parse_versioned_name(name).is_some_and(|(version, _)| version < bound)
                })
                .collect();
            names.sort();
            names.truncate(limit - removed);
            removed += self.remove_all(&directory, &names)?;
            // A version bucket wholly below the bound is now empty.
            if (bucket + 1) * BUCKET <= bound {
                self.remove_directory(&directory)?;
            }
        }
        Ok(removed)
    }
}

/// What `link_immutable` found under the name.
enum Linked {
    /// These bytes, linked here, now durable.
    Published,
    /// These same bytes, linked first by another writer, now durable.
    Same,
    /// Other bytes another writer linked first, now durable.
    Other(Vec<u8>),
}

/// temp file → `sync_all` → hard link → unlink temp → directory `sync_all`:
/// 2 syncs. The temp lives in `temporary` (cleared at open), so a crash at any
/// point leaves at most a leftover there and never a partial published name.
/// When another writer linked the name first, its directory entry is made
/// durable all the same and its bytes are compared (a file longer than
/// `limit` is an error, never truncated).
fn link_immutable(
    storage: &dyn Storage,
    temporary: &Path,
    directory: &Path,
    name: &str,
    bytes: &[u8],
    limit: usize,
) -> Result<Linked, String> {
    let destination = directory.join(name);
    let temporary = temporary.join(temporary_name());
    // Only our own temp is ever removed: a failed create leaves nothing to clean.
    storage.write_synced(&temporary, bytes).map_err(io_error)?;
    let linked = storage.link(&temporary, &destination).map_err(io_error);
    let cleanup = storage.remove(&temporary).map(|_| ()).map_err(io_error);
    let found = if linked? {
        Linked::Published
    } else {
        match storage
            .read(&destination, limit)
            .map_err(|_| "invalid execution archive file".to_owned())?
        {
            Some(existing) if existing == bytes => Linked::Same,
            Some(existing) => Linked::Other(existing),
            None => return Err("invalid execution archive file".into()),
        }
    };
    cleanup?;
    storage.sync_dir(directory).map_err(io_error)?;
    Ok(found)
}

/// `link_immutable` for content that must be exactly these bytes.
fn publish_immutable(
    storage: &dyn Storage,
    temporary: &Path,
    directory: &Path,
    name: &str,
    bytes: &[u8],
) -> Result<(), String> {
    match link_immutable(storage, temporary, directory, name, bytes, bytes.len())? {
        Linked::Published | Linked::Same => Ok(()),
        Linked::Other(_) => Err("conflicting immutable execution artifact".into()),
    }
}

fn bucket_name(number: u64) -> String {
    format!("{:08x}", number / BUCKET)
}

fn manifest_name(number: u64, hash: B256) -> String {
    format!("{number:016x}-{}", hex::encode(hash))
}

type Evidence = (
    String,
    String,
    String,
    String,
    bool,
    String,
    Vec<crate::context::CreatedContract>,
);

/// Per transaction, in order: binding, principal, organization, signer and
/// outcome. Two builds of one block must agree on all of it.
fn evidence(manifest: &BlockManifest) -> Result<Vec<Evidence>, String> {
    manifest
        .entries
        .iter()
        .map(|entry| {
            let identity = decode_strict::<crate::wire::Identity>(&entry.envelope.payload)?;
            Ok((
                identity.binding_hash,
                identity.principal_id,
                identity.org_id,
                identity.signer,
                entry.success,
                entry.reason_code.clone(),
                entry.created.clone(),
            ))
        })
        .collect()
}

fn private_directory_error(error: io::Error) -> String {
    match error.kind() {
        io::ErrorKind::PermissionDenied => "execution archive requires a private directory".into(),
        _ => io_error(error),
    }
}

/// The marker for an error message: printable ASCII only, bounded.
fn printable(marker: &[u8]) -> String {
    marker
        .iter()
        .take(48)
        .map(|byte| match byte {
            b' '..=b'~' => *byte as char,
            _ => '?',
        })
        .collect()
}

fn layout_error() -> String {
    "unsupported policy state directory layout; start the node with an empty directory".into()
}

/// Unique across process restarts even when the pid repeats (pid 1 in a
/// container): the wall-clock time of this process's first temp name is part
/// of every name.
fn temporary_name() -> String {
    static STARTED: OnceLock<u128> = OnceLock::new();
    let started = STARTED.get_or_init(|| {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|elapsed| elapsed.as_nanos())
            .unwrap_or_default()
    });
    format!(
        ".pending-{}-{started}-{}",
        std::process::id(),
        NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
    )
}

fn io_error(_: io::Error) -> String {
    "execution archive unavailable".into()
}
