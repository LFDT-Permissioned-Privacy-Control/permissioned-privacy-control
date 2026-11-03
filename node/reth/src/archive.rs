//! Durable local evidence for produced blocks. This layer authenticates content
//! addresses, not issuer signatures. Replay must also verify the retained signed
//! checkpoint and identities before constructing an execution handle.
//!
//! Layout of the state directory (version 2; older layouts are refused, there
//! is no importer):
//! - `LAYOUT`: the layout marker, written first on initialisation;
//! - `LOCK`: held exclusively by the one node process using the directory;
//! - `tmp/`: files being written, cleared at every open;
//! - `objects/`: content-addressed immutable objects;
//! - `pointers/`: node-owned mutable names for objects (`facts-head`);
//! - `blocks/<height / 4096 as {:08x}>/<height as {:016x}>-<hash>`: one execution manifest per
//!   produced block, a one-entry segment (see `manifest`).

use crate::{
    manifest::{BlockManifest, read_entry, write_segment},
    storage::{DiskStorage, Storage},
    wire::{Network, decode_strict},
};
use alloy_primitives::{B256, hex};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::HashSet,
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

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
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

/// Block manifests per height bucket directory under `blocks/`.
const BUCKET: u64 = 4096;
/// Largest manifest segment file read back.
const MAX_SEGMENT: usize = 1 << 30;

const LAYOUT: &[u8] = b"ops-node-policy-archive 2\n";

pub struct ArtifactStore {
    root: PathBuf,
    storage: Arc<dyn Storage>,
    /// Height buckets already made durable by this process.
    buckets: Mutex<HashSet<u64>>,
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
                    "policy state directory layout {:?} is not the {:?} this node uses",
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
        for directory in ["tmp", "objects", "blocks", "pointers"] {
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
            buckets: Mutex::new(HashSet::new()),
            _lock: lock,
        })
    }

    pub fn put(&self, bytes: &[u8]) -> Result<ArtifactId, String> {
        if bytes.is_empty() || bytes.len() > MAX_OBJECT {
            return Err("invalid execution artifact size".into());
        }
        let id = ArtifactId(B256::from_slice(&Sha256::digest(bytes)));
        self.publish_immutable(&self.root.join("objects"), &id.to_string(), bytes)?;
        Ok(id)
    }

    pub fn get(&self, id: ArtifactId) -> Result<Vec<u8>, String> {
        let bytes =
            self.read_bounded(&self.root.join("objects").join(id.to_string()), MAX_OBJECT)?;
        if B256::from_slice(&Sha256::digest(&bytes)) != id.0 {
            return Err("execution artifact digest mismatch".into());
        }
        Ok(bytes)
    }

    /// Durable mutable index into immutable evidence. Keys are node-owned names,
    /// never paths supplied by API clients. The referenced object must exist.
    pub fn set_pointer(&self, key: &str, id: ArtifactId) -> Result<(), String> {
        pointer_key(key)?;
        self.get(id)?;
        let bytes = serde_json::to_vec(&id).map_err(|_| "invalid execution archive pointer")?;
        self.replace_atomic(&self.root.join("pointers"), key, &bytes)
    }

    pub fn pointer(&self, key: &str) -> Result<Option<ArtifactId>, String> {
        pointer_key(key)?;
        self.storage
            .read(&self.root.join("pointers").join(key), 256)
            .map_err(io_error)?
            .map(|bytes| decode_strict(&bytes))
            .transpose()
    }

    /// Publish a produced block's manifest before the block is returned: one
    /// per-height segment file, published with a file `sync_all` and a
    /// directory `sync_all` (a new height bucket adds one directory sync per
    /// 4096 blocks). The record list it references must already be durable.
    /// Idempotent per block: an existing manifest whose transactions carry the
    /// same principals, organizations, signers and outcomes stays (another
    /// build may differ only in lease, facts or identity lease times).
    pub fn publish_manifest(&self, manifest: &BlockManifest) -> Result<Published, String> {
        self.get(manifest.records)?;
        let directory = self.bucket(manifest.number)?;
        let name = manifest_name(manifest.number, manifest.hash);
        if let Some(existing) = self
            .storage
            .read(&directory.join(&name), MAX_SEGMENT)
            .map_err(|_| "invalid execution archive file".to_owned())?
        {
            let existing = read_entry(&existing, manifest.number, manifest.hash)?
                .ok_or("invalid execution manifest")?;
            if evidence(&existing)? != evidence(manifest)? {
                return Err("conflicting execution manifest".into());
            }
            self.storage.sync_dir(&directory).map_err(io_error)?;
            return Ok(Published::Existing);
        }
        self.publish_immutable(&directory, &name, &write_segment(&[manifest])?)?;
        Ok(Published::New)
    }

    /// The manifest of block (number, hash), if this node published it.
    /// Reserved for self-import, trusted forensic replay and status lookups;
    /// historical user RPC calls use current permissions instead.
    pub fn manifest(&self, number: u64, hash: B256) -> Result<Option<BlockManifest>, String> {
        let path = self
            .root
            .join("blocks")
            .join(bucket_name(number))
            .join(manifest_name(number, hash));
        match self
            .storage
            .read(&path, MAX_SEGMENT)
            .map_err(|_| "invalid execution archive file".to_owned())?
        {
            None => Ok(None),
            Some(segment) => read_entry(&segment, number, hash),
        }
    }

    /// The height bucket directory, made durable once per process.
    fn bucket(&self, number: u64) -> Result<PathBuf, String> {
        let directory = self.root.join("blocks").join(bucket_name(number));
        let mut known = self
            .buckets
            .lock()
            .map_err(|_| "execution archive unavailable")?;
        if !known.contains(&(number / BUCKET)) {
            self.storage
                .ensure_private_dir(&directory)
                .map_err(private_directory_error)?;
            known.insert(number / BUCKET);
        }
        Ok(directory)
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
}

/// temp file → `sync_all` → hard link → unlink temp → directory `sync_all`:
/// 2 syncs. The temp lives in `temporary` (cleared at open), so a crash at any
/// point leaves at most a leftover there and never a partial published name.
fn publish_immutable(
    storage: &dyn Storage,
    temporary: &Path,
    directory: &Path,
    name: &str,
    bytes: &[u8],
) -> Result<(), String> {
    let destination = directory.join(name);
    let temporary = temporary.join(temporary_name());
    // Only our own temp is ever removed: a failed create leaves nothing to clean.
    storage.write_synced(&temporary, bytes).map_err(io_error)?;
    let linked = storage.link(&temporary, &destination).map_err(io_error);
    let cleanup = storage.remove(&temporary).map(|_| ()).map_err(io_error);
    if !linked?
        && storage
            .read(&destination, bytes.len())
            .map_err(|_| "invalid execution archive file".to_owned())?
            .as_deref()
            != Some(bytes)
    {
        return Err("conflicting immutable execution artifact".into());
    }
    cleanup?;
    storage.sync_dir(directory).map_err(io_error)
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

fn pointer_key(key: &str) -> Result<(), String> {
    if key.is_empty()
        || key.len() > 192
        || !key.as_bytes()[0].is_ascii_alphanumeric()
        || !key
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
    {
        return Err("invalid execution archive pointer".into());
    }
    Ok(())
}
