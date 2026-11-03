use alloy_primitives::B256;
use ops_reth_policy::{
    archive::{ArtifactStore, BlockDescriptor, BlockManifest, BoundIdentity},
    wire::Network,
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
fn block() -> BlockDescriptor {
    BlockDescriptor {
        network: Network {
            chain_id: 31337,
            deployment_id: "test-a".into(),
        },
        hash: B256::repeat_byte(1),
        parent_hash: B256::repeat_byte(2),
        number: 3,
        timestamp: 1020,
        transactions: vec![B256::repeat_byte(4), B256::repeat_byte(5)],
    }
}
fn manifest(store: &ArtifactStore) -> BlockManifest {
    let envelope = store.put(b"exact signed envelope bytes").unwrap();
    BlockManifest {
        format_version: 1,
        block: block(),
        facts_version: 7,
        facts_digest: B256::repeat_byte(6),
        checkpoint: store
            .put(b"exact retained snapshot + delta + lease envelopes")
            .unwrap(),
        identities: block()
            .transactions
            .into_iter()
            .map(|transaction_hash| BoundIdentity {
                transaction_hash,
                envelope,
                outcome: ops_reth_policy::context::ExecutionOutcome {
                    success: true,
                    denied: false,
                    reason_code: String::new(),
                    created: Vec::new(),
                },
            })
            .collect(),
    }
}

#[test]
fn immutable_artifacts_and_manifest_survive_restart() {
    let temp = Temp::new();
    let store = ArtifactStore::open(&temp.0).unwrap();
    let expected = manifest(&store);
    store.publish(&expected).unwrap();
    store.publish(&expected).unwrap(); // Idempotent retry after acknowledgement loss.
    drop(store);
    let reopened = ArtifactStore::open(&temp.0).unwrap();
    let recovered = reopened.load_for_block(&block()).unwrap();
    assert_eq!(recovered, expected);
    assert_eq!(
        reopened.get(recovered.identities[0].envelope).unwrap(),
        b"exact signed envelope bytes"
    );
    assert_eq!(fs::read_dir(temp.0.join("objects")).unwrap().count(), 2);
}

#[test]
fn exact_block_and_transaction_order_are_required() {
    let temp = Temp::new();
    let store = ArtifactStore::open(&temp.0).unwrap();
    store.publish(&manifest(&store)).unwrap();
    for changed in 0..5 {
        let mut wrong = block();
        match changed {
            0 => wrong.hash = B256::repeat_byte(9),
            1 => wrong.parent_hash = B256::repeat_byte(9),
            2 => wrong.timestamp += 1,
            3 => wrong.transactions.reverse(),
            _ => wrong.network.deployment_id = "test-b".into(),
        }
        assert!(
            store.load_for_block(&wrong).is_err(),
            "accepted different block field {changed}"
        );
    }
}

#[test]
fn conflicting_manifest_and_incomplete_evidence_cannot_be_published() {
    let temp = Temp::new();
    let store = ArtifactStore::open(&temp.0).unwrap();
    let original = manifest(&store);
    let mut missing = original.clone();
    missing.checkpoint = store.put(b"missing checkpoint").unwrap();
    fs::remove_file(temp.0.join("objects").join(missing.checkpoint.to_string())).unwrap();
    assert!(store.publish(&missing).is_err());
    assert!(store.load_for_block(&block()).is_err());
    store.publish(&original).unwrap();
    let mut conflicting = original.clone();
    conflicting.facts_version += 1;
    assert!(store.publish(&conflicting).is_err());
    assert_eq!(store.load_for_block(&block()).unwrap(), original);
    let mut incomplete = original.clone();
    incomplete.identities.pop();
    assert!(store.publish(&incomplete).is_err());
}

#[test]
fn corrupt_content_never_becomes_replay_evidence() {
    let temp = Temp::new();
    let store = ArtifactStore::open(&temp.0).unwrap();
    let expected = manifest(&store);
    store.publish(&expected).unwrap();
    fs::write(
        temp.0.join("objects").join(expected.checkpoint.to_string()),
        b"tampered",
    )
    .unwrap();
    assert!(store.get(expected.checkpoint).is_err());
    assert!(store.load_for_block(&block()).is_err());
    assert!(
        store
            .put(b"exact retained snapshot + delta + lease envelopes")
            .is_err()
    );
}

#[test]
fn only_synced_objects_survive_a_crash() {
    use common::{Action, MemoryStorage, Op};
    use std::path::Path;
    let storage = MemoryStorage::new();
    let root = Path::new("/state");
    let store = ArtifactStore::open_with(root, storage.clone()).unwrap();
    let before = storage.counts();
    let kept = store.put(b"durable evidence").unwrap();
    assert_eq!(
        (storage.counts() - before).syncs,
        2,
        "file sync + directory sync"
    );
    storage.set_hook(|op, _| match op {
        Op::SyncDir => Action::Fail,
        _ => Action::Proceed,
    });
    assert!(store.put(b"entry never made durable").is_err());
    storage.crash();
    storage.restart();
    let reopened = ArtifactStore::open_with(root, storage.clone()).unwrap();
    assert_eq!(reopened.get(kept).unwrap(), b"durable evidence");
    let lost = ArtifactStore::open_with(root, MemoryStorage::new())
        .unwrap()
        .put(b"entry never made durable")
        .unwrap();
    assert!(
        reopened.get(lost).is_err(),
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
    assert!(store.put(b"evidence").is_err());
    storage.clear_hook();
    let id = store.put(b"evidence").unwrap();
    storage.crash();
    storage.restart();
    assert_eq!(
        ArtifactStore::open_with(root, storage.clone())
            .unwrap()
            .get(id)
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
        let id = store.put(b"evidence").unwrap();
        assert_eq!(store.get(id).unwrap(), b"evidence");
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
    let id = store.put(b"evidence").unwrap();
    drop(store);
    storage.plant(&root.join("tmp").join(".pending-9-9-9"), b"leftover");
    let store = ArtifactStore::open_with(root, storage.clone()).unwrap();
    assert!(
        storage.names(&root.join("tmp")).is_empty(),
        "tmp/ cleared at open"
    );
    assert_eq!(store.get(id).unwrap(), b"evidence");
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
