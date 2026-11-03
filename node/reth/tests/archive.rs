use alloy_primitives::B256;
use ops_reth_policy::{
    archive::{ArtifactId, ArtifactStore},
    manifest::{BlockManifest, ManifestEntry},
};
use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

mod common;

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        Self(std::env::temp_dir().join(format!(
            "ops-policy-archive-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        )))
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
/// A stored record list completing facts `version`.
fn list(store: &ArtifactStore, version: u64) -> ArtifactId {
    store
        .put_list(version, b"exact retained snapshot + delta record list")
        .unwrap()
}

fn manifest(store: &ArtifactStore) -> BlockManifest {
    let verifier = common::fixture::verifier();
    let envelope = |hash: B256| {
        verifier
            .open_envelope(
                "identity",
                &common::fixture::seal("identity", &common::fixture::identity(hash, "ctx")),
            )
            .unwrap()
    };
    BlockManifest {
        hash: B256::repeat_byte(1),
        parent_hash: B256::repeat_byte(2),
        number: 3,
        timestamp: 1020,
        facts_version: 7,
        base_version: 7,
        facts_digest: B256::repeat_byte(6),
        records: list(store, 7),
        lease: None,
        entries: [B256::repeat_byte(4), B256::repeat_byte(5)]
            .into_iter()
            .map(|hash| ManifestEntry {
                envelope: envelope(hash),
                success: true,
                reason_code: String::new(),
                created: Vec::new(),
            })
            .collect(),
    }
}

#[test]
fn manifest_survives_restart_and_republish_is_idempotent() {
    let temp = Temp::new();
    let store = ArtifactStore::open(&temp.0).unwrap();
    let expected = manifest(&store);
    store.publish_manifest(&expected).unwrap();
    store.publish_manifest(&expected).unwrap(); // Retry after acknowledgement loss.
    // Another build of the same block with another lease binds the same
    // transactions: the existing manifest stays.
    let mut rebuilt = expected.clone();
    rebuilt.lease = None;
    rebuilt.facts_version = 8;
    rebuilt.records = list(&store, 8);
    store.publish_manifest(&rebuilt).unwrap();
    drop(store);
    let reopened = ArtifactStore::open(&temp.0).unwrap();
    assert_eq!(reopened.manifest(3, expected.hash).unwrap(), Some(expected));
    let lists: usize = fs::read_dir(temp.0.join("lists"))
        .unwrap()
        .map(|bucket| fs::read_dir(bucket.unwrap().path()).unwrap().count())
        .sum();
    assert_eq!(
        lists, 2,
        "the record lists of versions 7 and 8, nothing else"
    );
    assert_eq!(
        fs::read_dir(temp.0.join("facts")).unwrap().count(),
        0,
        "identities live only inside the manifest"
    );
}

#[test]
fn exact_block_is_required() {
    let temp = Temp::new();
    let store = ArtifactStore::open(&temp.0).unwrap();
    store.publish_manifest(&manifest(&store)).unwrap();
    assert_eq!(store.manifest(3, B256::repeat_byte(9)).unwrap(), None);
    assert_eq!(store.manifest(4, B256::repeat_byte(1)).unwrap(), None);
    assert!(store.manifest(3, B256::repeat_byte(1)).unwrap().is_some());
}

#[test]
fn conflicting_manifest_and_missing_records_cannot_be_published() {
    let temp = Temp::new();
    let store = ArtifactStore::open(&temp.0).unwrap();
    let original = manifest(&store);
    let mut missing = original.clone();
    missing.records = ArtifactId::of(b"never stored");
    assert!(store.publish_manifest(&missing).is_err());
    assert_eq!(store.manifest(3, original.hash).unwrap(), None);
    store.publish_manifest(&original).unwrap();
    let mut conflicting = original.clone();
    conflicting.entries.reverse();
    assert!(store.publish_manifest(&conflicting).is_err());
    assert_eq!(store.manifest(3, original.hash).unwrap(), Some(original));
}

#[test]
fn corrupt_manifest_never_becomes_replay_evidence() {
    let temp = Temp::new();
    let store = ArtifactStore::open(&temp.0).unwrap();
    let expected = manifest(&store);
    store.publish_manifest(&expected).unwrap();
    let path = temp
        .0
        .join("blocks")
        .join(format!("{:08x}", 0))
        .join(format!(
            "{:016x}-{}",
            3,
            alloy_primitives::hex::encode(expected.hash)
        ));
    let mut bytes = fs::read(&path).unwrap();
    let middle = bytes.len() / 3;
    bytes[middle] ^= 1;
    fs::write(&path, &bytes).unwrap();
    assert!(store.manifest(3, expected.hash).is_err());
}

#[test]
fn only_synced_objects_survive_a_crash() {
    use common::{Action, MemoryStorage, Op};
    use std::path::Path;
    let storage = MemoryStorage::new();
    let root = Path::new("/state");
    let store = ArtifactStore::open_with(root, storage.clone()).unwrap();
    let before = storage.counts();
    let kept = store.put_list(1, b"durable evidence").unwrap();
    assert_eq!(
        (storage.counts() - before).syncs,
        2,
        "file sync + directory sync"
    );
    storage.set_hook(|op, _| match op {
        Op::SyncDir => Action::Fail,
        _ => Action::Proceed,
    });
    assert!(store.put_list(1, b"entry never made durable").is_err());
    storage.crash();
    storage.restart();
    let reopened = ArtifactStore::open_with(root, storage.clone()).unwrap();
    assert_eq!(reopened.get_list(1, kept).unwrap(), b"durable evidence");
    let lost = ArtifactStore::open_with(root, MemoryStorage::new())
        .unwrap()
        .put_list(1, b"entry never made durable")
        .unwrap();
    assert!(
        reopened.get_list(1, lost).is_err(),
        "unsynced directory entry survived"
    );
}

#[test]
fn retry_after_a_failed_directory_sync_makes_the_object_durable() {
    use common::{Action, MemoryStorage, Op};
    use std::path::Path;
    let storage = MemoryStorage::new();
    let root = Path::new("/state");
    let store = ArtifactStore::open_with(root, storage.clone()).unwrap();
    storage.set_hook(|op, _| match op {
        Op::SyncDir => Action::Fail,
        _ => Action::Proceed,
    });
    assert!(store.put_list(1, b"evidence").is_err());
    storage.clear_hook();
    let id = store.put_list(1, b"evidence").unwrap();
    storage.crash();
    storage.restart();
    assert_eq!(
        ArtifactStore::open_with(root, storage.clone())
            .unwrap()
            .get_list(1, id)
            .unwrap(),
        b"evidence"
    );
}

#[test]
fn old_archive_layout_is_refused_and_left_unchanged() {
    use common::MemoryStorage;
    use std::path::Path;
    let storage = MemoryStorage::new();
    let root = Path::new("/state");
    // A layout-1 directory: objects, pointers and manifests, no marker.
    storage.plant(&root.join("objects").join("ab".repeat(32)), b"object");
    storage.plant(&root.join("pointers").join("tx-01"), b"pointer");
    storage.plant(&root.join("blocks").join("cd".repeat(32)), b"manifest");
    ops_reth_policy::storage::Storage::ensure_private_dir(storage.as_ref(), root).unwrap();
    assert_eq!(storage.names(root), vec!["blocks", "objects", "pointers"]);
    let (tree, counts) = (storage.tree(), storage.counts());
    let error = ArtifactStore::open_with(root, storage.clone()).unwrap_err();
    assert!(
        error.contains("unsupported policy state directory layout"),
        "{error}"
    );
    assert_eq!(storage.tree(), tree, "the refused directory was modified");
    let used = storage.counts() - counts;
    assert_eq!((used.writes, used.others), (0, 0), "{used:?}");
}

#[test]
fn foreign_marker_is_refused() {
    use common::MemoryStorage;
    use std::path::Path;
    let storage = MemoryStorage::new();
    let root = Path::new("/state");
    storage.plant(&root.join("LAYOUT"), b"ops-node-policy-archive 1\n");
    let tree = storage.tree();
    let error = ArtifactStore::open_with(root, storage.clone()).unwrap_err();
    assert!(
        error.contains("\"ops-node-policy-archive 1?\" is not the"),
        "{error}"
    );
    assert_eq!(storage.tree(), tree, "the refused directory was modified");
}

#[test]
fn crash_at_every_step_of_initialisation_recovers() {
    use common::{Action, MemoryStorage};
    use std::{
        path::Path,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
    };
    for step in 0..32 {
        let storage = MemoryStorage::new();
        let root = Path::new("/state");
        let count = Arc::new(AtomicUsize::new(0));
        storage.set_hook({
            let count = count.clone();
            move |_, _| {
                if count.fetch_add(1, Ordering::SeqCst) == step {
                    Action::CrashAfter
                } else {
                    Action::Proceed
                }
            }
        });
        let first = ArtifactStore::open_with(root, storage.clone());
        let operations = count.load(Ordering::SeqCst);
        drop(first);
        storage.restart();
        let store = ArtifactStore::open_with(root, storage.clone())
            .unwrap_or_else(|error| panic!("crash after step {step}: {error}"));
        let id = store.put_list(1, b"evidence").unwrap();
        assert_eq!(store.get_list(1, id).unwrap(), b"evidence");
        if step >= operations {
            break;
        }
    }
}

#[test]
fn interrupted_initialisation_and_tmp_leftovers_recover() {
    use common::MemoryStorage;
    use std::path::Path;
    let storage = MemoryStorage::new();
    let root = Path::new("/state");
    // A crash before the marker was durable leaves at most a temp name.
    storage.plant(&root.join(".pending-1-2-3"), b"partial");
    let store = ArtifactStore::open_with(root, storage.clone()).unwrap();
    let id = store.put_list(1, b"evidence").unwrap();
    drop(store);
    storage.plant(&root.join("tmp").join(".pending-9-9-9"), b"leftover");
    let store = ArtifactStore::open_with(root, storage.clone()).unwrap();
    assert!(
        storage.names(&root.join("tmp")).is_empty(),
        "tmp/ cleared at open"
    );
    assert_eq!(store.get_list(1, id).unwrap(), b"evidence");
}

#[test]
fn a_state_directory_has_one_node_process() {
    let temp = Temp::new();
    let first = ArtifactStore::open(&temp.0).unwrap();
    let error = ArtifactStore::open(&temp.0).unwrap_err();
    assert!(error.contains("in use"), "{error}");
    drop(first);
    ArtifactStore::open(&temp.0).unwrap();
}

#[test]
fn republish_keeps_equivalent_evidence_and_refuses_another_principal() {
    let temp = Temp::new();
    let store = ArtifactStore::open(&temp.0).unwrap();
    let original = manifest(&store);
    assert_eq!(
        store.publish_manifest(&original).unwrap(),
        ops_reth_policy::archive::Published::New
    );
    let mut renewed = original.clone();
    renewed.facts_version += 1;
    renewed.records = list(&store, renewed.facts_version);
    let verifier = common::fixture::verifier();
    let mut later = common::fixture::identity(B256::repeat_byte(4), "ctx-later");
    later["issued_at"] = serde_json::json!(1800000005);
    renewed.entries[0].envelope = verifier
        .open_envelope("identity", &common::fixture::seal("identity", &later))
        .unwrap();
    assert_eq!(
        store.publish_manifest(&renewed).unwrap(),
        ops_reth_policy::archive::Published::Existing,
        "a rebuild differing only in facts and identity lease times"
    );
    let mut other = later.clone();
    other["principal_id"] = serde_json::json!("another_principal");
    let mut rebound = original.clone();
    rebound.entries[0].envelope = verifier
        .open_envelope("identity", &common::fixture::seal("identity", &other))
        .unwrap();
    assert!(store.publish_manifest(&rebound).is_err());
    let mut outcome = original.clone();
    outcome.entries[1].reason_code = "APPLICATION_REVERTED".into();
    outcome.entries[1].success = false;
    assert!(store.publish_manifest(&outcome).is_err());
    assert_eq!(store.manifest(3, original.hash).unwrap(), Some(original));
}
