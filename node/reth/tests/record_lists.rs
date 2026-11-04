//! Record lists (independent review, finding 6): one constant-size list per
//! snapshot or delta, chained to the list of the generation it extends, so
//! the bytes written for a fact chain grow linearly with its length, not
//! quadratically. Replay and restart walk the chain back to its snapshot;
//! every step stays crash-safe, and a list that does not link exactly into
//! its chain is refused.

use alloy_primitives::B256;
use common::{
    Action, MemoryStorage, Op,
    fixture::{AT, descriptor, execute, identity, seal, snapshot, verifier},
};
use ops_reth_policy::{
    archive::{ArtifactId, ArtifactStore, BlockDescriptor},
    runtime::PolicyRuntime,
    stream::FactStream,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

mod common;

const ROOT: &str = "/state";
const TX: B256 = B256::repeat_byte(1);
/// A list's size whatever the chain's length (under 400 bytes as JSON).
const LIST_BYTES: usize = 512;

fn open(storage: &Arc<MemoryStorage>) -> PolicyRuntime {
    let archive = ArtifactStore::open_with(Path::new(ROOT), storage.clone()).unwrap();
    PolicyRuntime::open(verifier(), Arc::new(archive), 16, AT).unwrap()
}

fn digest_of(payload: &Value) -> String {
    alloy_primitives::hex::encode(Sha256::digest(serde_json::to_vec(payload).unwrap()))
}

/// Delta `version` on top of `previous`/`digest` (no row changes).
fn delta(previous: u64, digest: &str, version: u64) -> Value {
    json!({"network":common::fixture::network(),"issued_at":1800000000,"expires_at":1800000060,
    "previous_version":previous,"previous_digest":digest,"version":version,
    "upserts":{"principals":[],"groups":[],"contracts":[],"policies":[],"sanctions":[]},
    "deletes":{"principals":[],"groups":[],"contracts":[],"policies":[],"sanctions":[]}})
}

/// Install deltas `from + 1 ..= to`; the last one's digest.
fn deltas(runtime: &PolicyRuntime, from: u64, digest: &str, to: u64) -> String {
    let mut digest = digest.to_owned();
    for version in from + 1..=to {
        let next = delta(version - 1, &digest, version);
        runtime
            .accept_facts("delta", &seal("delta", &next), AT)
            .unwrap();
        digest = digest_of(&next);
    }
    digest
}

/// A block of `TX` built and published on the installed facts.
fn produce(runtime: &PolicyRuntime, number: u64, hash: u8) -> BlockDescriptor {
    runtime
        .accept_identity(&seal("identity", &identity(TX, "ctx")), AT)
        .unwrap();
    let candidate = runtime.pin_candidate(AT).unwrap();
    assert!(execute(&candidate, TX));
    let block = BlockDescriptor {
        number,
        hash: B256::repeat_byte(hash),
        ..descriptor(vec![TX])
    };
    runtime.persist(&candidate, &block).unwrap();
    block
}

/// Sizes of every stored record list.
fn list_sizes(storage: &MemoryStorage) -> Vec<usize> {
    storage
        .tree()
        .iter()
        .filter(|(directory, _)| directory.starts_with(Path::new(ROOT).join("lists")))
        .flat_map(|(_, files)| files.values().map(Vec::len).collect::<Vec<_>>())
        .collect()
}

#[test]
fn record_lists_grow_linearly_and_replay_walks_the_chain() {
    const DELTAS: u64 = 300;
    let storage = MemoryStorage::new();
    let runtime = open(&storage);
    runtime
        .accept_facts("snapshot", &seal("snapshot", &snapshot()), AT)
        .unwrap();
    let first = produce(&runtime, 1, 10);
    let digest = deltas(&runtime, 1, &digest_of(&snapshot()), 2);
    let second = produce(&runtime, 2, 20);
    deltas(&runtime, 2, &digest, DELTAS + 1);
    let last = produce(&runtime, 3, 30);
    let sizes = list_sizes(&storage);
    assert_eq!(
        sizes.len() as u64,
        DELTAS + 1,
        "one list per snapshot or delta"
    );
    let largest = sizes.iter().copied().max().unwrap();
    let total: usize = sizes.iter().sum();
    eprintln!(
        "{} record lists, largest {largest} B, {total} B in all",
        sizes.len()
    );
    assert!(
        largest <= LIST_BYTES,
        "a list grows with its chain: {largest} bytes after {DELTAS} deltas"
    );
    assert!(total <= (DELTAS as usize + 1) * LIST_BYTES, "{total} bytes");
    // Each block replays from its own list, walking back to the snapshot,
    // before and after a restart (which restores the chain's tip).
    for block in [&first, &second, &last] {
        runtime.replay(block).unwrap();
    }
    drop(runtime);
    let restarted = open(&storage);
    assert_eq!(
        restarted.feed.latest().unwrap().unwrap().version(),
        DELTAS + 1
    );
    for block in [&first, &second, &last] {
        restarted.replay(block).unwrap();
    }
}

/// Snapshot v1, delta v2 with a block, delta v3 with a block.
fn chain(storage: &Arc<MemoryStorage>) -> (PolicyRuntime, String, Vec<BlockDescriptor>) {
    let runtime = open(storage);
    runtime
        .accept_facts("snapshot", &seal("snapshot", &snapshot()), AT)
        .unwrap();
    let two = deltas(&runtime, 1, &digest_of(&snapshot()), 2);
    let on_two = produce(&runtime, 1, 10);
    let three = deltas(&runtime, 2, &two, 3);
    let on_three = produce(&runtime, 2, 20);
    (runtime, three, vec![on_two, on_three])
}

#[test]
fn crash_at_every_step_of_a_chained_delta_keeps_every_block_replayable() {
    let mut completed = false;
    for step in 0..64 {
        let storage = MemoryStorage::new();
        let (runtime, three, mut blocks) = chain(&storage);
        let count = Arc::new(AtomicUsize::new(0));
        storage.set_hook({
            let count = count.clone();
            move |op, _| {
                if matches!(op, Op::Read | Op::List) {
                    return Action::Proceed;
                }
                if count.fetch_add(1, Ordering::SeqCst) == step {
                    Action::CrashAfter
                } else {
                    Action::Proceed
                }
            }
        });
        let four = delta(3, &three, 4);
        let result = runtime.accept_facts("delta", &seal("delta", &four), AT);
        let operations = count.load(Ordering::SeqCst);
        if step >= operations {
            assert_eq!(result.unwrap().version(), 4);
            completed = true;
            break;
        }
        drop(runtime);
        storage.restart();
        // After the crash: the old or the new generation, both usable, and
        // every block published before replays.
        let restarted = open(&storage);
        let version = restarted.feed.latest().unwrap().unwrap().version();
        assert!(
            version == 3 || version == 4,
            "step {step}: restored {version}"
        );
        assert!(restarted.pin_candidate(AT).is_ok(), "step {step}");
        for block in &blocks {
            restarted
                .replay(block)
                .unwrap_or_else(|error| panic!("step {step}: {error}"));
        }
        // The chain continues from what survived.
        if version == 3 {
            restarted
                .accept_facts("delta", &seal("delta", &four), AT)
                .unwrap_or_else(|error| panic!("step {step}: resend: {error}"));
        }
        deltas(&restarted, 4, &digest_of(&four), 5);
        blocks.push(produce(&restarted, 3, 30));
        drop(restarted);
        let reopened = open(&storage);
        assert_eq!(reopened.feed.latest().unwrap().unwrap().version(), 5);
        for block in &blocks {
            reopened
                .replay(block)
                .unwrap_or_else(|error| panic!("step {step}: after resume: {error}"));
        }
    }
    assert!(
        completed,
        "the sweep never reached an ingestion without a crash"
    );
}

#[test]
fn a_list_that_does_not_link_into_its_chain_is_refused() {
    let storage = MemoryStorage::new();
    let runtime = open(&storage);
    runtime
        .accept_facts("snapshot", &seal("snapshot", &snapshot()), AT)
        .unwrap();
    let snapshot_list = runtime
        .feed
        .latest()
        .unwrap()
        .unwrap()
        .checkpoint()
        .unwrap();
    let two = deltas(&runtime, 1, &digest_of(&snapshot()), 2);
    deltas(&runtime, 2, &two, 3);
    let list = runtime
        .feed
        .latest()
        .unwrap()
        .unwrap()
        .checkpoint()
        .unwrap();
    let store = &runtime.archive;
    assert!(FactStream::restore(verifier(), store, 3, list, AT).is_ok());
    let original: Value = serde_json::from_slice(&store.get_list(3, list).unwrap()).unwrap();
    let tampered = |change: &dyn Fn(&mut Value)| -> ArtifactId {
        let mut doc = original.clone();
        change(&mut doc);
        store
            .put_list(3, &serde_json::to_vec(&doc).unwrap())
            .unwrap()
    };
    let snapshot_id = serde_json::to_value(snapshot_list).unwrap();
    // Refused by the walk back, before any record is read or applied.
    let walk = "invalid policy checkpoint";
    // Refused by the forward pass: the restored generation differs.
    let state = "policy checkpoint state mismatch";
    type Change = Box<dyn Fn(&mut Value)>;
    let cases: Vec<(&str, &str, Change)> = vec![
        (
            "skips a generation",
            walk,
            Box::new(move |doc| {
                doc["previous"] = json!({"version": 1, "list": snapshot_id.clone()})
            }),
        ),
        (
            "claims another length",
            walk,
            Box::new(|doc| doc["records"] = json!(5)),
        ),
        (
            "claims another snapshot",
            walk,
            Box::new(|doc| doc["base_version"] = json!(2)),
        ),
        (
            "has no previous list",
            walk,
            Box::new(|doc| doc["previous"] = Value::Null),
        ),
        (
            "names another record version",
            walk,
            Box::new(|doc| doc["record"]["version"] = json!(2)),
        ),
        (
            "claims another digest",
            state,
            Box::new(|doc| doc["facts_digest"] = json!(format!("0x{}", "ab".repeat(32)))),
        ),
    ];
    for (name, expected, change) in cases {
        let id = tampered(&*change);
        let error = FactStream::restore(verifier(), store, 3, id, AT).unwrap_err();
        assert_eq!(error, expected, "a list that {name}");
    }
}

#[test]
fn the_longest_chain_restores_through_its_lists() {
    // A snapshot and 8191 deltas: the walk reaches the snapshot at exactly
    // the chain limit, and a restart restores the tip.
    let storage = MemoryStorage::new();
    let runtime = open(&storage);
    runtime
        .accept_facts("snapshot", &seal("snapshot", &snapshot()), AT)
        .unwrap();
    let last = deltas(&runtime, 1, &digest_of(&snapshot()), 8192);
    let over = delta(8192, &last, 8193);
    let error = runtime
        .accept_facts("delta", &seal("delta", &over), AT)
        .unwrap_err();
    assert!(error.contains("checkpoint limit"), "{error}");
    drop(runtime);
    let restarted = open(&storage);
    assert_eq!(restarted.feed.latest().unwrap().unwrap().version(), 8192);
}
