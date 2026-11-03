//! Node admission keeps pending identities in memory: no storage I/O per
//! transaction, indexed expiry, and the registry as the only live binding.

use alloy_primitives::{B256, U256};
use common::{
    MemoryStorage,
    fixture::{AT, execute, execute_result, identity, seal, snapshot, verifier},
};
use ops_reth_policy::{archive::ArtifactStore, context::ExecutionBinding, runtime::PolicyRuntime};
use std::{
    path::Path,
    sync::{Arc, Barrier},
    time::{Duration, Instant},
};

mod common;

fn runtime(storage: &Arc<MemoryStorage>, capacity: usize) -> PolicyRuntime {
    let archive = ArtifactStore::open_with(Path::new("/state"), storage.clone()).unwrap();
    let runtime = PolicyRuntime::new(verifier(), Arc::new(archive), capacity);
    runtime
        .accept_facts("snapshot", &seal("snapshot", &snapshot()), AT)
        .unwrap();
    runtime
}

fn hash(index: u64) -> B256 {
    B256::from(U256::from(index + 1))
}

#[test]
fn admission_performs_no_storage_io() {
    let storage = MemoryStorage::new();
    let runtime = runtime(&storage, 2_000);
    let before = storage.counts();
    // Any storage operation at all fails the admission that attempts it.
    storage.set_hook(|_, _| common::Action::Fail);
    for index in 0..1_000 {
        let wire = seal("identity", &identity(hash(index), &format!("ctx-{index}")));
        runtime.accept_identity(&wire, AT).unwrap();
    }
    storage.clear_hook();
    let used = storage.counts() - before;
    assert_eq!(
        used,
        Default::default(),
        "admission must not touch storage: {used:?}"
    );
}

#[test]
fn pooled_transaction_without_identity_never_executes_after_restart() {
    let storage = MemoryStorage::new();
    let tx = hash(1);
    let runtime = runtime(&storage, 16);
    runtime
        .accept_identity(&seal("identity", &identity(tx, "ctx-a")), AT)
        .unwrap();
    assert!(execute(&runtime.pin_candidate(AT).unwrap(), tx));
    drop(runtime);
    // Reth restores the pool from its shutdown backup; the registry starts empty.
    let archive = ArtifactStore::open_with(Path::new("/state"), storage.clone()).unwrap();
    let restarted = PolicyRuntime::open(verifier(), Arc::new(archive), 16, AT).unwrap();
    for build in 0..3 {
        let denied = execute_result(&restarted.pin_candidate(AT).unwrap(), tx)
            .expect_err("a pooled transaction without an identity executed");
        assert!(
            denied.contains("missing execution identity"),
            "build {build}: {denied}"
        );
    }
}

#[test]
fn concurrent_conflicting_bindings_one_wins() {
    let storage = MemoryStorage::new();
    let runtime = Arc::new(runtime(&storage, 64));
    let tx = hash(7);
    let barrier = Arc::new(Barrier::new(16));
    let attempts = (0..16)
        .map(|index| {
            let (runtime, barrier) = (runtime.clone(), barrier.clone());
            std::thread::spawn(move || {
                let mut claim = identity(tx, &format!("ctx-{index}"));
                claim["principal_id"] = format!("principal_{index}").into();
                let wire = seal("identity", &claim);
                barrier.wait();
                runtime.accept_identity(&wire, AT).map(|_| index)
            })
        })
        .collect::<Vec<_>>();
    let winners = attempts
        .into_iter()
        .filter_map(|attempt| attempt.join().unwrap().ok())
        .collect::<Vec<_>>();
    assert_eq!(winners.len(), 1, "{winners:?}");
    let bound = runtime
        .identities
        .lookup(&ExecutionBinding::Transaction(tx), AT)
        .unwrap();
    assert_eq!(bound.principal_id, format!("principal_{}", winners[0]));
}

/// Minimum over repetitions of the time to admit `probes` fresh identities
/// into a registry already holding `filler` live identities.
fn admission_time(filler: u64, probes: u64) -> Duration {
    let storage = MemoryStorage::new();
    let runtime = runtime(&storage, (filler + probes) as usize);
    let verifier = verifier();
    for index in 0..filler {
        let wire = seal("identity", &identity(hash(index), "filler"));
        runtime
            .admit_identity(verifier.verify_identity(&wire, AT).unwrap(), AT)
            .unwrap();
    }
    (0..5u64)
        .map(|repetition| {
            let probes = (0..probes)
                .map(|index| {
                    let hash = hash(1_000_000 * (repetition + 1) + index);
                    let wire = seal("identity", &identity(hash, "probe"));
                    (hash, verifier.verify_identity(&wire, AT).unwrap())
                })
                .collect::<Vec<_>>();
            let started = Instant::now();
            for (_, verified) in &probes {
                runtime.admit_identity(verified.clone(), AT).unwrap();
            }
            let elapsed = started.elapsed();
            for (hash, _) in &probes {
                runtime
                    .identities
                    .finish(&ExecutionBinding::Transaction(*hash))
                    .unwrap();
            }
            elapsed
        })
        .min()
        .unwrap()
}

/// Micro-benchmark companion of the deterministic index tests in
/// `src/identity.rs`: `cargo test --release -- --ignored admission_cost`.
#[test]
#[ignore = "timing benchmark; the deterministic check is identity::tests"]
fn admission_cost_independent_of_registry_size() {
    let small = admission_time(1_000, 500);
    let large = admission_time(20_000, 500);
    // A scan of every live identity per admission is ≈ 20× here; an index is flat.
    assert!(
        large <= small * 8 + Duration::from_millis(2),
        "admission grew with registry size: {small:?} at 1k vs {large:?} at 20k"
    );
}

#[test]
fn node_refuses_rebinding_only_while_the_identity_is_live() {
    // Contract: the node refuses another principal while its entry is live.
    // After expiry or release, OPS's durable submission row refuses it.
    let storage = MemoryStorage::new();
    let runtime = runtime(&storage, 16);
    let tx = hash(9);
    runtime
        .accept_identity(&seal("identity", &identity(tx, "ctx-a")), AT)
        .unwrap();
    let mut other = identity(tx, "ctx-b");
    other["principal_id"] = "another_principal".into();
    assert!(
        runtime
            .accept_identity(&seal("identity", &other), AT)
            .is_err(),
        "rebinding a live identity"
    );
    other["issued_at"] = 1800000055.into();
    other["expires_at"] = 1800000115.into();
    runtime
        .accept_identity(&seal("identity", &other), 1800000061)
        .expect("an expired lease is reclaimed on admission");
    assert_eq!(
        runtime
            .identities
            .lookup(&ExecutionBinding::Transaction(tx), 1800000061)
            .unwrap()
            .principal_id,
        "another_principal"
    );
}
#[test]
fn candidate_execution_writes_nothing_to_disk() {
    let storage = MemoryStorage::new();
    let runtime = runtime(&storage, 16);
    let tx = hash(3);
    runtime
        .accept_identity(&seal("identity", &identity(tx, "ctx-a")), AT)
        .unwrap();
    let before = storage.counts();
    // A storage operation would fail and deny the build's execution.
    storage.set_hook(|_, _| common::Action::Fail);
    for _ in 0..3 {
        assert!(execute(&runtime.pin_candidate(AT).unwrap(), tx));
    }
    storage.clear_hook();
    let used = storage.counts() - before;
    assert_eq!(used, Default::default(), "{used:?}");
    let status = runtime.transaction_status(tx, None).unwrap().unwrap();
    assert_eq!(status.status, "pending", "candidate outcome kept in memory");
}
