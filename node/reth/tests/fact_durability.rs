//! Fact ingestion: one serialized writer, records durable before install
//! (plan T5 facts, T21, T22, T24).

use alloy_primitives::B256;
use common::{
    Action, Gate, MemoryStorage, Op,
    fixture::{AT, execute, identity, seal, snapshot, verifier},
};
use ops_reth_policy::{archive::ArtifactStore, runtime::PolicyRuntime, stream::FactStream};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{path::Path, sync::Arc};

mod common;

const ROOT: &str = "/state";

fn open(storage: &Arc<MemoryStorage>) -> PolicyRuntime {
    let archive = ArtifactStore::open_with(Path::new(ROOT), storage.clone()).unwrap();
    PolicyRuntime::open(verifier(), Arc::new(archive), 16, AT).unwrap()
}

fn digest_of(payload: &Value) -> String {
    alloy_primitives::hex::encode(Sha256::digest(serde_json::to_vec(payload).unwrap()))
}

/// Delta `version` on top of a generation with `previous`/`digest`.
fn delta(previous: u64, digest: &str, version: u64) -> Value {
    json!({"network":common::fixture::network(),"issued_at":1800000000 + version as i64,"expires_at":1800000060,
    "previous_version":previous,"previous_digest":digest,"version":version,
    "upserts":{"principals":[],"groups":[],"contracts":[],"policies":[],"sanctions":[]},
    "deletes":{"principals":[],"groups":[],"contracts":[],"policies":[],"sanctions":[]}})
}

fn heartbeat(version: u64, digest: &str, issued: i64) -> Value {
    json!({"network":common::fixture::network(),"issued_at":issued,"expires_at":issued + 60,"version":version,"digest":digest})
}

#[test]
fn fact_record_written_once_before_install_independent_of_chain_length() {
    let storage = MemoryStorage::new();
    let runtime = open(&storage);
    let base = snapshot();
    let before = storage.counts();
    runtime
        .accept_facts("snapshot", &seal("snapshot", &base), AT)
        .unwrap();
    let per_snapshot = storage.counts() - before;
    let mut digest = digest_of(&base);
    let mut costs = Vec::new();
    for version in 2..=12 {
        let next = delta(version - 1, &digest, version);
        let before = storage.counts();
        runtime
            .accept_facts("delta", &seal("delta", &next), AT)
            .unwrap();
        costs.push(storage.counts() - before);
        digest = digest_of(&next);
    }
    // One record, one record list, one head pointer: 3 files, 6 syncs, for a
    // chain of 1 or 11 deltas alike.
    assert_eq!(
        (per_snapshot.writes, per_snapshot.syncs),
        (3, 6),
        "{per_snapshot:?}"
    );
    for (index, cost) in costs.iter().enumerate() {
        assert_eq!(
            (cost.writes, cost.syncs),
            (3, 6),
            "delta {}: {cost:?}",
            index + 2
        );
    }
}

#[test]
fn heartbeat_never_written_separately() {
    let storage = MemoryStorage::new();
    let runtime = open(&storage);
    let base = snapshot();
    runtime
        .accept_facts("snapshot", &seal("snapshot", &base), AT)
        .unwrap();
    let before = storage.counts();
    let beat = heartbeat(1, &digest_of(&base), AT);
    let facts = runtime
        .accept_facts("heartbeat", &seal("heartbeat", &beat), AT)
        .unwrap();
    assert_eq!(facts.expires_at(), AT + 60);
    assert_eq!(
        storage.counts() - before,
        Default::default(),
        "no storage operation"
    );
}

#[test]
fn facts_installed_only_after_records_are_durable() {
    let storage = MemoryStorage::new();
    let runtime = Arc::new(open(&storage));
    let base = snapshot();
    runtime
        .accept_facts("snapshot", &seal("snapshot", &base), AT)
        .unwrap();
    let gate = Gate::new();
    // Hold the last durable step, the head pointer's directory sync: nothing
    // may be installed before it completes.
    storage.set_hook({
        let gate = gate.clone();
        move |op, path| {
            if op == Op::SyncDir && path.ends_with("pointers") {
                gate.pass();
            }
            Action::Proceed
        }
    });
    let next = delta(1, &digest_of(&base), 2);
    let writer = std::thread::spawn({
        let runtime = runtime.clone();
        move || runtime.accept_facts("delta", &seal("delta", &next), AT)
    });
    gate.wait_entered();
    assert_eq!(runtime.feed.latest().unwrap().unwrap().version(), 1);
    assert_eq!(
        runtime.pin_candidate(AT).unwrap().facts_version(),
        1,
        "a build pins only durable facts"
    );
    gate.open();
    assert_eq!(writer.join().unwrap().unwrap().version(), 2);
    storage.clear_hook();
    assert_eq!(runtime.pin_candidate(AT).unwrap().facts_version(), 2);
}

/// Ingest delta v2 on a fresh runtime, failing the `failing`-th mutating
/// storage operation. Returns the runtime, the result, the number of mutating
/// operations attempted and the path of the failed one.
fn fail_delta_at(
    storage: &Arc<MemoryStorage>,
    failing: usize,
) -> (
    PolicyRuntime,
    Result<u64, String>,
    usize,
    Option<std::path::PathBuf>,
) {
    let runtime = open(storage);
    let base = snapshot();
    runtime
        .accept_facts("snapshot", &seal("snapshot", &base), AT)
        .unwrap();
    let count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let failed = Arc::new(std::sync::Mutex::new(None));
    storage.set_hook({
        let (count, failed) = (count.clone(), failed.clone());
        move |op, path| {
            if matches!(op, Op::Read | Op::List) {
                return Action::Proceed;
            }
            if count.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == failing {
                *failed.lock().unwrap() = Some(path.to_owned());
                Action::Fail
            } else {
                Action::Proceed
            }
        }
    });
    let result = runtime
        .accept_facts("delta", &seal("delta", &delta(1, &digest_of(&base), 2)), AT)
        .map(|facts| facts.version());
    storage.clear_hook();
    let operations = count.load(std::sync::atomic::Ordering::SeqCst);
    let failed = failed.lock().unwrap().clone();
    (runtime, result, operations, failed)
}

#[test]
fn failed_fact_write_keeps_previous_facts_at_every_step() {
    let base = snapshot();
    let mut completed = false;
    let mut failed_head = false;
    for failing in 0..64 {
        // After the failure: the previous facts stay installed, a retry of the
        // same delta (the publisher retries) installs it.
        let storage = MemoryStorage::new();
        let (runtime, result, operations, failed) = fail_delta_at(&storage, failing);
        if failing >= operations {
            assert_eq!(result.unwrap(), 2, "step {failing} of {operations}");
            completed = true;
            break;
        }
        failed_head |= failed
            .as_ref()
            .is_some_and(|path| path.starts_with("/state/pointers"));
        assert!(
            result.is_err(),
            "failure at step {failing} was reported as success"
        );
        assert_eq!(runtime.feed.latest().unwrap().unwrap().version(), 1);
        assert_eq!(runtime.pin_candidate(AT).unwrap().facts_version(), 1);
        let retried = runtime
            .accept_facts("delta", &seal("delta", &delta(1, &digest_of(&base), 2)), AT)
            .unwrap_or_else(|error| panic!("step {failing}: retry failed: {error}"));
        assert_eq!(retried.version(), 2);
        drop(runtime);
        // After a crash right after the failure: either generation, usable.
        let storage = MemoryStorage::new();
        let (runtime, _, _, _) = fail_delta_at(&storage, failing);
        drop(runtime);
        storage.crash();
        storage.restart();
        let restarted = open(&storage);
        let version = restarted.feed.latest().unwrap().unwrap().version();
        assert!(
            version == 1 || version == 2,
            "step {failing}: restored {version}"
        );
        assert!(
            restarted.pin_candidate(AT).is_ok(),
            "step {failing}: restored facts unusable"
        );
    }
    assert!(
        completed,
        "the sweep never reached an ingestion without failures"
    );
    assert!(failed_head, "the sweep never failed the head pointer");
}

#[test]
fn candidate_pinned_below_identity_minimum_cannot_execute_it() {
    let storage = MemoryStorage::new();
    let runtime = open(&storage);
    let base = snapshot();
    runtime
        .accept_facts("snapshot", &seal("snapshot", &base), AT)
        .unwrap();
    let old = runtime.pin_candidate(AT).unwrap();
    runtime
        .accept_facts("delta", &seal("delta", &delta(1, &digest_of(&base), 2)), AT)
        .unwrap();
    let tx = B256::repeat_byte(1);
    let mut fresh = identity(tx, "ctx-a");
    fresh["min_snapshot_version"] = json!(2);
    runtime
        .accept_identity(&seal("identity", &fresh), AT)
        .unwrap();
    assert!(
        !execute(&old, tx),
        "a v1 candidate executed a v2-minimum identity"
    );
    assert!(execute(&runtime.pin_candidate(AT).unwrap(), tx));
}

#[test]
fn fact_writer_is_serialized_and_never_regresses() {
    // Delta D (v2) is held inside its record write; a heartbeat for v1 and a
    // stale v1 snapshot arrive meanwhile. Whatever their order, the live and
    // restored state end at v2 and every Ok reply's records are durable.
    for heartbeat_first in [true, false] {
        let storage = MemoryStorage::new();
        let runtime = Arc::new(open(&storage));
        let base = snapshot();
        runtime
            .accept_facts("snapshot", &seal("snapshot", &base), AT)
            .unwrap();
        let gate = Gate::new();
        storage.set_hook({
            let gate = gate.clone();
            move |op, _| {
                if op == Op::Write {
                    gate.pass();
                }
                Action::Proceed
            }
        });
        let delta_wire = seal("delta", &delta(1, &digest_of(&base), 2));
        let held = std::thread::spawn({
            let runtime = runtime.clone();
            move || runtime.accept_facts("delta", &delta_wire, AT)
        });
        gate.wait_entered();
        let late = |runtime: Arc<PolicyRuntime>, kind: &'static str, wire: Vec<u8>| {
            std::thread::spawn(move || runtime.accept_facts(kind, &wire, AT).map(|f| f.version()))
        };
        let beat = seal("heartbeat", &heartbeat(1, &digest_of(&base), AT + 1));
        let stale = seal("snapshot", &base);
        let (beat_thread, stale_thread) = if heartbeat_first {
            let beat = late(runtime.clone(), "heartbeat", beat);
            (beat, late(runtime.clone(), "snapshot", stale))
        } else {
            let stale = late(runtime.clone(), "snapshot", stale);
            (late(runtime.clone(), "heartbeat", beat), stale)
        };
        // Both late messages are parked behind the writer holding delta D.
        std::thread::sleep(std::time::Duration::from_millis(100));
        assert!(
            !beat_thread.is_finished() && !stale_thread.is_finished(),
            "a late message ran beside the writer"
        );
        gate.open();
        assert_eq!(held.join().unwrap().unwrap().version(), 2);
        let beat_error = beat_thread.join().unwrap().unwrap_err();
        assert!(
            beat_error.contains("heartbeat state mismatch"),
            "{beat_error}"
        );
        let stale_error = stale_thread.join().unwrap().unwrap_err();
        assert!(
            stale_error.contains("stale policy snapshot"),
            "{stale_error}"
        );
        storage.clear_hook();
        let live = runtime.feed.latest().unwrap().unwrap();
        assert_eq!(live.version(), 2);
        let head = live.checkpoint().expect("installed facts are durable");
        let durable = FactStream::restore(verifier(), &runtime.archive, head, AT).unwrap();
        assert_eq!(durable.latest().unwrap().unwrap().version(), 2);
        drop(runtime);
        storage.crash();
        storage.restart();
        assert_eq!(open(&storage).feed.latest().unwrap().unwrap().version(), 2);
    }
}

#[test]
fn crash_between_head_and_install_restarts_at_the_new_head() {
    let storage = MemoryStorage::new();
    let runtime = open(&storage);
    let base = snapshot();
    runtime
        .accept_facts("snapshot", &seal("snapshot", &base), AT)
        .unwrap();
    // Crash right after the head pointer's directory sync, before install.
    let fired = Arc::new(std::sync::atomic::AtomicBool::new(false));
    storage.set_hook({
        let fired = fired.clone();
        move |op, path| {
            if op == Op::SyncDir && path.ends_with("pointers") {
                fired.store(true, std::sync::atomic::Ordering::SeqCst);
                Action::CrashAfter
            } else {
                Action::Proceed
            }
        }
    });
    let _ = runtime.accept_facts("delta", &seal("delta", &delta(1, &digest_of(&base), 2)), AT);
    assert!(
        fired.load(std::sync::atomic::Ordering::SeqCst),
        "the crash never happened"
    );
    drop(runtime);
    storage.restart();
    let restarted = open(&storage);
    assert_eq!(restarted.feed.latest().unwrap().unwrap().version(), 2);
    assert_eq!(restarted.pin_candidate(AT).unwrap().facts_version(), 2);
}
