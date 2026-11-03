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
//! - `blocks/`: one execution manifest per produced block.

use crate::{
    storage::{DiskStorage, Storage},
    wire::{Network, decode_strict, identifier},
};
use alloy_primitives::{B256, hex};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::HashSet,
    fmt, io,
    path::{Path, PathBuf},
    sync::{
        Arc, OnceLock,
        atomic::{AtomicU64, Ordering},
    },
    time::{SystemTime, UNIX_EPOCH},
};

const MAX_OBJECT: usize = 64 << 20;
const MAX_MANIFEST: usize = 16 << 20;
static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ArtifactId(B256);
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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BoundIdentity {
    pub transaction_hash: B256,
    pub envelope: ArtifactId,
    pub outcome: crate::context::ExecutionOutcome,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlockManifest {
    pub format_version: u32,
    pub block: BlockDescriptor,
    pub facts_version: u64,
    /// Digest of the exact last applied snapshot/delta payload, not checkpoint JSON.
    pub facts_digest: B256,
    /// Immutable checkpoint document referencing retained signed stream artifacts.
    pub checkpoint: ArtifactId,
    pub identities: Vec<BoundIdentity>,
}

const LAYOUT: &[u8] = b"ops-node-policy-archive 2\n";

pub struct ArtifactStore {
    root: PathBuf,
    storage: Arc<dyn Storage>,
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

    /// Call before publishing the assembled block. ACK requires durable artifacts
    /// and manifest. A retry is idempotent; an existing hash cannot be overwritten.
    pub fn publish(&self, manifest: &BlockManifest) -> Result<(), String> {
        self.validate(manifest)?;
        let bytes = serde_json::to_vec(manifest).map_err(|_| "invalid execution manifest")?;
        if bytes.len() > MAX_MANIFEST {
            return Err("execution manifest too large".into());
        }
        self.publish_immutable(
            &self.root.join("blocks"),
            &hex::encode(manifest.block.hash),
            &bytes,
        )
    }

    /// Reserved for block self-import and trusted forensic replay. Historical user
    /// RPC calls must choose current permissions instead of this archive.
    pub fn load_for_block(&self, expected: &BlockDescriptor) -> Result<BlockManifest, String> {
        let bytes = self.read_bounded(
            &self.root.join("blocks").join(hex::encode(expected.hash)),
            MAX_MANIFEST,
        )?;
        let manifest: BlockManifest = decode_strict(&bytes)?;
        if &manifest.block != expected {
            return Err("execution manifest block mismatch".into());
        }
        self.validate(&manifest)?;
        Ok(manifest)
    }

    /// A manifest by block hash alone, for status lookups: decoded and checked
    /// for format and block hash only (the network and the one needed entry
    /// are the caller's to check). Replay uses `load_for_block`.
    pub fn manifest_by_hash(&self, block: B256) -> Result<BlockManifest, String> {
        let bytes = self.read_bounded(
            &self.root.join("blocks").join(hex::encode(block)),
            MAX_MANIFEST,
        )?;
        let manifest: BlockManifest = decode_strict(&bytes)?;
        if manifest.format_version != 1 || manifest.block.hash != block {
            return Err("execution manifest block mismatch".into());
        }
        Ok(manifest)
    }

    fn validate(&self, manifest: &BlockManifest) -> Result<(), String> {
        if manifest.format_version != 1
            || manifest.block.network.chain_id == 0
            || !identifier(&manifest.block.network.deployment_id)
            || manifest.block.hash.is_zero()
            || manifest.facts_version == 0
            || manifest.facts_digest.is_zero()
            || manifest.identities.len() != manifest.block.transactions.len()
        {
            return Err("invalid execution manifest".into());
        }
        let mut unique = HashSet::new();
        for (hash, identity) in manifest.block.transactions.iter().zip(&manifest.identities) {
            if *hash != identity.transaction_hash || !unique.insert(*hash) {
                return Err("execution manifest transaction mismatch".into());
            }
            self.get(identity.envelope)?;
            if identity.outcome.denied
                || (!identity.outcome.success && !identity.outcome.created.is_empty())
            {
                return Err("invalid included execution outcome".into());
            }
        }
        self.get(manifest.checkpoint)?;
        Ok(())
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
