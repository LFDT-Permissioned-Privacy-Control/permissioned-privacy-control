//! Per-block evidence (plan T4, T5, T20, T25): one compressed manifest per
//! block, durable before the block is returned, replayable from what it embeds.

use alloy_primitives::B256;
use common::{
    Action, MemoryStorage, Op,
    fixture::{AT, descriptor, execute, identity, seal, snapshot, verifier},
};
use ops_reth_policy::{archive::ArtifactStore, archive::BlockDescriptor, runtime::PolicyRuntime};
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
