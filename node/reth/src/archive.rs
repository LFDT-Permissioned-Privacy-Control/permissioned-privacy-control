//! Durable local evidence for produced blocks. This layer authenticates content
//! addresses, not issuer signatures. Replay must also verify the retained signed
//! checkpoint and identities before constructing an execution handle.

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

#[derive(Debug)]
pub struct ArtifactStore {
    root: PathBuf,
    storage: Arc<dyn Storage>,
}

impl ArtifactStore {
    pub fn open(root: impl AsRef<Path>) -> Result<Self, String> {
        Self::open_with(root, Arc::new(DiskStorage))
    }

    /// Open on an explicit storage implementation (tests count and fault-inject).
    pub fn open_with(root: impl AsRef<Path>, storage: Arc<dyn Storage>) -> Result<Self, String> {
        let root = root.as_ref().to_owned();
        for directory in [
            root.clone(),
            root.join("objects"),
            root.join("blocks"),
            root.join("pointers"),
        ] {
            storage
                .ensure_private_dir(&directory)
                .map_err(|error| match error.kind() {
                    io::ErrorKind::PermissionDenied => {
                        "execution archive requires a private directory".to_owned()
                    }
                    _ => io_error(error),
                })?;
        }
        Ok(Self { root, storage })
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

    /// temp file → `sync_all` → hard link → unlink temp → directory `sync_all`:
    /// 2 syncs. The temp name is gone before the directory sync, so a crash
    /// afterwards leaves only the published name.
    fn publish_immutable(&self, directory: &Path, name: &str, bytes: &[u8]) -> Result<(), String> {
        let destination = directory.join(name);
        let temporary = directory.join(temporary_name());
        // Only our own temp is ever removed: a failed create leaves nothing to clean.
        self.storage
            .write_synced(&temporary, bytes)
            .map_err(io_error)?;
        let linked = self
            .storage
            .link(&temporary, &destination)
            .map_err(io_error);
        let cleanup = self
            .storage
            .remove(&temporary)
            .map(|_| ())
            .map_err(io_error);
        if !linked? && self.read_bounded(&destination, bytes.len())? != bytes {
            return Err("conflicting immutable execution artifact".into());
        }
        cleanup?;
        self.storage.sync_dir(directory).map_err(io_error)
    }

    /// temp file → `sync_all` → rename → directory `sync_all`: 2 syncs.
    fn replace_atomic(&self, directory: &Path, key: &str, bytes: &[u8]) -> Result<(), String> {
        let temporary = directory.join(temporary_name());
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
