//! Per-block evidence (plan T4, T5, T20, T25): one compressed manifest per
//! block, durable before the block is returned, replayable from what it embeds.

use alloy_primitives::B256;
use common::{
    Action, MemoryStorage, Op,
    fixture::{AT, descriptor, execute, identity, seal, snapshot, verifier},
};
use ops_reth_policy::{archive::ArtifactStore, archive::BlockDescriptor, runtime::PolicyRuntime};
use sha2::Digest;
use std::{path::Path, sync::Arc};

mod common;

const ROOT: &str = "/state";
const TX: B256 = B256::repeat_byte(1);

fn open(storage: &Arc<MemoryStorage>) -> PolicyRuntime {
    let archive = ArtifactStore::open_with(Path::new(ROOT), storage.clone()).unwrap();
    PolicyRuntime::open(verifier(), Arc::new(archive), 16, AT).unwrap()
}

/// A runtime with fresh facts and the fixture identity for `TX` admitted.
fn ready(storage: &Arc<MemoryStorage>) -> PolicyRuntime {
    let runtime = open(storage);
    runtime
        .accept_facts("snapshot", &seal("snapshot", &snapshot()), AT)
        .unwrap();
    runtime
        .accept_identity(&seal("identity", &identity(TX, "ctx-a")), AT)
        .unwrap();
    runtime
}

fn block(number: u64, hash: u8) -> BlockDescriptor {
    BlockDescriptor {
        number,
        hash: B256::repeat_byte(hash),
        ..descriptor(vec![TX])
    }
}

#[test]
fn manifest_v2_published_before_block_returned() {
    // Fail each storage step of a block's publication in turn: `persist`
    // reports it, so the block is not returned, and after a crash the block's
    // evidence is either absent or complete, never partial.
    let mut completed = false;
    for failing in 0..64 {
        let storage = MemoryStorage::new();
        let runtime = ready(&storage);
        let candidate = runtime.pin_candidate(AT).unwrap();
        assert!(execute(&candidate, TX));
        let count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        storage.set_hook({
            let count = count.clone();
            move |op, _| {
                if matches!(op, Op::Read | Op::List) {
                    return Action::Proceed;
                }
                if count.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == failing {
                    Action::Fail
                } else {
                    Action::Proceed
                }
            }
        });
        let result = runtime.persist(&candidate, &block(1, 10));
        let attempted = count.load(std::sync::atomic::Ordering::SeqCst);
        storage.clear_hook();
        if failing >= attempted {
            result.unwrap();
            completed = true;
            break;
        }
        assert!(
            result.is_err(),
            "failure at step {failing} of {attempted} reported success"
        );
        drop((candidate, runtime));
        storage.crash();
        storage.restart();
        match open(&storage).replay(&block(1, 10)) {
            Ok(replay) => assert!(execute(&replay, TX), "step {failing}"),
            Err(error) => assert!(error.contains("manifest"), "step {failing}: {error}"),
        }
    }
    assert!(
        completed,
        "the sweep never reached a publication without failures"
    );
}

#[test]
fn returned_block_evidence_survives_an_immediate_crash() {
    let storage = MemoryStorage::new();
    let runtime = ready(&storage);
    let candidate = runtime.pin_candidate(AT).unwrap();
    assert!(execute(&candidate, TX));
    runtime.persist(&candidate, &block(1, 10)).unwrap();
    storage.crash();
    drop((candidate, runtime));
    storage.restart();
    assert!(execute(&open(&storage).replay(&block(1, 10)).unwrap(), TX));
}

#[test]
fn replay_uses_embedded_envelopes() {
    let storage = MemoryStorage::new();
    let runtime = ready(&storage);
    for number in 1..=5u64 {
        let candidate = runtime.pin_candidate(AT).unwrap();
        assert!(execute(&candidate, TX));
        runtime
            .persist(&candidate, &block(number, number as u8 * 10))
            .unwrap();
    }
    drop(runtime);
    storage.crash();
    storage.restart();
    // No identity object exists outside the manifests: every object is a fact
    // record or a record list.
    for name in storage.names(Path::new("/state/objects")) {
        let bytes =
            String::from_utf8_lossy(&storage_read(&storage, &format!("/state/objects/{name}")))
                .into_owned();
        assert!(
            !bytes.contains(r#""kind":"identity""#),
            "identity object {name} outside a manifest"
        );
    }
    let restarted = open(&storage);
    for number in 1..=5u64 {
        let replay = restarted.replay(&block(number, number as u8 * 10)).unwrap();
        assert!(execute(&replay, TX), "block {number}");
        assert_eq!(
            restarted
                .status_identity(TX, Some((number, B256::repeat_byte(number as u8 * 10))))
                .unwrap()
                .context_id,
            "ctx-a"
        );
    }
}

fn storage_read(storage: &MemoryStorage, path: &str) -> Vec<u8> {
    use ops_reth_policy::storage::Storage;
    storage.read(Path::new(path), 1 << 26).unwrap().unwrap()
}

fn manifest_file(block: &BlockDescriptor) -> std::path::PathBuf {
    Path::new(ROOT)
        .join("blocks")
        .join(format!("{:08x}", block.number / 4096))
        .join(format!(
            "{:016x}-{}",
            block.number,
            alloy_primitives::hex::encode(block.hash)
        ))
}

/// A two-transaction block (0x01…, 0x02…) published and its manifest.
fn two_transaction_block(
    storage: &Arc<MemoryStorage>,
) -> (BlockDescriptor, ops_reth_policy::manifest::BlockManifest) {
    let runtime = ready(storage);
    let second = B256::repeat_byte(2);
    runtime
        .accept_identity(&seal("identity", &identity(second, "ctx-b")), AT)
        .unwrap();
    let candidate = runtime.pin_candidate(AT).unwrap();
    assert!(execute(&candidate, TX));
    assert!(execute(&candidate, second));
    let block = BlockDescriptor {
        transactions: vec![TX, second],
        ..block(1, 10)
    };
    runtime.persist(&candidate, &block).unwrap();
    let manifest = runtime
        .archive
        .manifest(block.number, block.hash)
        .unwrap()
        .unwrap();
    (block, manifest)
}

#[test]
fn replay_refuses_manifests_that_do_not_match_the_block() {
    use ops_reth_policy::manifest::write_segment;
    let storage = MemoryStorage::new();
    let (block, original) = two_transaction_block(&storage);
    let path = manifest_file(&block);
    let mut reordered = original.clone();
    reordered.entries.reverse();
    let mut short = original.clone();
    short.entries.pop();
    let mut duplicated = original.clone();
    duplicated.entries[1] = duplicated.entries[0].clone();
    let mut parent = original.clone();
    parent.parent_hash = B256::repeat_byte(77);
    let mut timestamp = original.clone();
    timestamp.timestamp += 1;
    for (name, tampered) in [
        ("reordered transactions", reordered),
        ("missing transaction", short),
        ("identity bound to another transaction", duplicated),
        ("parent mismatch", parent),
        ("timestamp mismatch", timestamp),
    ] {
        storage.tamper(&path, &write_segment(&[&tampered]).unwrap());
        assert!(open(&storage).replay(&block).is_err(), "{name} replayed");
    }
    storage.tamper(&path, &write_segment(&[&original]).unwrap());
    let replay = open(&storage).replay(&block).unwrap();
    assert!(execute(&replay, TX), "control: the original replays");
}

#[test]
fn status_answers_from_memory_and_from_disk_agree() {
    let storage = MemoryStorage::new();
    let runtime = ready(&storage);
    let candidate = runtime.pin_candidate(AT).unwrap();
    assert!(execute(&candidate, TX));
    let produced = block(1, 10);
    runtime.persist(&candidate, &produced).unwrap();
    let key = Some((produced.number, produced.hash));
    let cached = (
        runtime.status_identity(TX, key).unwrap(),
        runtime.transaction_status(TX, key).unwrap().unwrap(),
    );
    assert!(
        runtime.status_identity(B256::repeat_byte(3), key).is_err(),
        "a hash outside the block answered from memory"
    );
    drop(runtime);
    let restarted = open(&storage);
    let loaded = (
        restarted.status_identity(TX, key).unwrap(),
        restarted.transaction_status(TX, key).unwrap().unwrap(),
    );
    assert_eq!(cached.0, loaded.0);
    assert_eq!(
        (
            cached.1.facts_version,
            cached.1.reason_code,
            cached.1.created
        ),
        (
            loaded.1.facts_version,
            loaded.1.reason_code,
            loaded.1.created
        )
    );
    assert!(
        restarted
            .status_identity(B256::repeat_byte(3), key)
            .is_err()
    );
}

#[test]
fn a_rebuilt_block_keeps_the_first_published_evidence() {
    let storage = MemoryStorage::new();
    let runtime = ready(&storage);
    let produced = block(1, 10);
    let first = runtime.pin_candidate(AT).unwrap();
    assert!(execute(&first, TX));
    runtime.persist(&first, &produced).unwrap();
    // A renewal between two builds of the same block: same principal, new
    // context. The second build's persist keeps the first manifest.
    let mut renewed = identity(TX, "ctx-renewed");
    renewed["issued_at"] = serde_json::json!(AT);
    renewed["expires_at"] = serde_json::json!(AT + 60);
    runtime
        .accept_identity(&seal("identity", &renewed), AT)
        .unwrap();
    let second = runtime.pin_candidate(AT).unwrap();
    assert!(execute(&second, TX));
    runtime.persist(&second, &produced).unwrap();
    assert_eq!(
        runtime
            .status_identity(TX, Some((produced.number, produced.hash)))
            .unwrap()
            .context_id,
        "ctx-a",
        "status must describe the evidence on disk"
    );
}
#[test]
fn one_manifest_publication_per_block() {
    let storage = MemoryStorage::new();
    let runtime = ready(&storage);
    let first = runtime.pin_candidate(AT).unwrap();
    assert!(execute(&first, TX));
    runtime.persist(&first, &block(1, 10)).unwrap();
    // With a heartbeat installed the lease travels inside the manifest.
    let digest = alloy_primitives::hex::encode(sha2::Sha256::digest(
        serde_json::to_vec(&snapshot()).unwrap(),
    ));
    runtime
        .accept_facts(
            "heartbeat",
            &seal(
                "heartbeat",
                &serde_json::json!({"network":common::fixture::network(),"issued_at":AT,"expires_at":AT + 60,"version":1,"digest":digest}),
            ),
            AT,
        )
        .unwrap();
    for (number, hash) in [(2, 20), (3, 30)] {
        let candidate = runtime.pin_candidate(AT).unwrap();
        assert!(execute(&candidate, TX));
        let before = storage.counts();
        runtime.persist(&candidate, &block(number, hash)).unwrap();
        let used = storage.counts() - before;
        assert_eq!(
            (used.writes, used.syncs),
            (1, 2),
            "block {number}: {used:?}"
        );
    }
}

/// Facts valid 1800000000..1800000060, renewed by a heartbeat to ..110, a
/// block at 1800000070 and its manifest path.
fn heartbeat_block(storage: &Arc<MemoryStorage>) -> BlockDescriptor {
    let runtime = open(storage);
    runtime
        .accept_facts("snapshot", &seal("snapshot", &snapshot()), AT)
        .unwrap();
    let digest = alloy_primitives::hex::encode(sha2::Sha256::digest(
        serde_json::to_vec(&snapshot()).unwrap(),
    ));
    runtime
        .accept_facts(
            "heartbeat",
            &seal(
                "heartbeat",
                &serde_json::json!({"network":common::fixture::network(),"issued_at":1800000050,"expires_at":1800000110,"version":1,"digest":digest}),
            ),
            1800000050,
        )
        .unwrap();
    let mut late = identity(TX, "ctx-late");
    late["issued_at"] = serde_json::json!(1800000065);
    late["expires_at"] = serde_json::json!(1800000125);
    runtime
        .accept_identity(&seal("identity", &late), 1800000070)
        .unwrap();
    let candidate = runtime.pin_candidate(1800000070).unwrap();
    assert!(execute(&candidate, TX));
    let block = BlockDescriptor {
        timestamp: 1800000070,
        ..block(1, 10)
    };
    runtime.persist(&candidate, &block).unwrap();
    block
}

fn manifest_path(block: &BlockDescriptor) -> std::path::PathBuf {
    Path::new(ROOT)
        .join("blocks")
        .join(format!("{:08x}", block.number / 4096))
        .join(format!(
            "{:016x}-{}",
            block.number,
            alloy_primitives::hex::encode(block.hash)
        ))
}

#[test]
fn replay_after_snapshot_expiry_uses_embedded_heartbeat() {
    let storage = MemoryStorage::new();
    let block = heartbeat_block(&storage);
    storage.crash();
    storage.restart();
    let restarted = open(&storage);
    assert!(
        restarted.pin_candidate(1800000070).is_err(),
        "heartbeats are not persisted: current facts are expired after restart"
    );
    assert!(execute(&restarted.replay(&block).unwrap(), TX));
}

#[test]
fn replay_without_valid_lease_evidence_fails_closed() {
    use ops_reth_policy::manifest::{read_entry, write_segment};
    let storage = MemoryStorage::new();
    let block = heartbeat_block(&storage);
    let path = manifest_path(&block);
    let original = {
        use ops_reth_policy::storage::Storage;
        read_entry(
            &storage.read(&path, 1 << 30).unwrap().unwrap(),
            block.number,
            block.hash,
        )
        .unwrap()
        .unwrap()
    };
    let verifier = verifier();
    let digest = alloy_primitives::hex::encode(sha2::Sha256::digest(
        serde_json::to_vec(&snapshot()).unwrap(),
    ));
    let lease = |issued: i64, version: u64, digest: &str| {
        Some(
            verifier
                .open_envelope(
                    "heartbeat",
                    &seal(
                        "heartbeat",
                        &serde_json::json!({"network":common::fixture::network(),"issued_at":issued,"expires_at":issued + 60,"version":version,"digest":digest}),
                    ),
                )
                .unwrap(),
        )
    };
    let cases = [
        ("no lease evidence", None, "validity window"),
        (
            "heartbeat issued after the block",
            lease(1800000076, 1, &digest),
            "future archived",
        ),
        (
            "heartbeat for another version",
            lease(1800000050, 2, &digest),
            "state mismatch",
        ),
        (
            "heartbeat for another digest",
            lease(1800000050, 1, &"00".repeat(32)),
            "state mismatch",
        ),
        (
            "heartbeat that expired before the block",
            lease(1800000005, 1, &digest),
            "validity window",
        ),
    ];
    for (name, lease, reason) in cases {
        let mut tampered = original.clone();
        tampered.lease = lease;
        storage.tamper(&path, &write_segment(&[&tampered]).unwrap());
        let error = open(&storage)
            .replay(&block)
            .err()
            .unwrap_or_else(|| panic!("{name}: replayed"));
        assert!(error.contains(reason), "{name}: {error}");
    }
    storage.tamper(&path, &write_segment(&[&original]).unwrap());
    assert!(
        open(&storage).replay(&block).is_ok(),
        "control: the original replays"
    );
}

/// Storage reads, lists and every path touched while opening a runtime whose
/// archive holds `blocks` manifests.
fn open_cost(blocks: u64) -> (common::Counts, Vec<std::path::PathBuf>) {
    let storage = MemoryStorage::new();
    let runtime = ready(&storage);
    for number in 1..=blocks {
        let candidate = runtime.pin_candidate(AT).unwrap();
        assert!(execute(&candidate, TX));
        runtime
            .persist(
                &candidate,
                &BlockDescriptor {
                    number,
                    hash: B256::from(alloy_primitives::U256::from(number)),
                    ..descriptor(vec![TX])
                },
            )
            .unwrap();
    }
    drop(runtime);
    let paths = Arc::new(std::sync::Mutex::new(Vec::new()));
    storage.set_hook({
        let paths = paths.clone();
        move |_, path| {
            paths.lock().unwrap().push(path.to_owned());
            Action::Proceed
        }
    });
    let before = storage.counts();
    drop(open(&storage));
    let used = storage.counts() - before;
    storage.clear_hook();
    let paths = paths.lock().unwrap().clone();
    (used, paths)
}

#[test]
fn restart_reads_are_independent_of_history() {
    let (small, _) = open_cost(10);
    let (large, paths) = open_cost(200);
    assert_eq!(small, large, "restart work grew with history");
    assert!(
        paths.iter().all(|path| !path.starts_with("/state/blocks")),
        "restart touched block manifests: {paths:?}"
    );
}
