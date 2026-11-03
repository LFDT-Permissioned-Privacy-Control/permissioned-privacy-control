//! The node runtime reclaims expired identity leases on admission, in bounded
//! batches under the admission lock.

use alloy_primitives::{B256, U256};
use common::{
    MemoryStorage,
    fixture::{AT, identity, seal, snapshot, verifier},
};
use ops_reth_policy::{archive::ArtifactStore, context::ExecutionBinding, runtime::PolicyRuntime};
use serde_json::json;
use std::{path::Path, sync::Arc};

mod common;

/// After every fixture lease (expires 1800000060) has expired.
const LATER: i64 = 1800000061;
const CAPACITY: u64 = 100;

fn hash(index: u64) -> B256 {
    B256::from(U256::from(index + 1))
}

/// A runtime whose registry is full of fixture leases.
fn full() -> PolicyRuntime {
    let archive = ArtifactStore::open_with(Path::new("/state"), MemoryStorage::new()).unwrap();
    let runtime = PolicyRuntime::new(verifier(), Arc::new(archive), CAPACITY as usize);
    runtime
        .accept_facts("snapshot", &seal("snapshot", &snapshot()), AT)
        .unwrap();
    for index in 0..CAPACITY {
        runtime
            .accept_identity(&seal("identity", &identity(hash(index), "filler")), AT)
            .unwrap();
    }
    runtime
}

/// An identity valid at `LATER`.
fn later(index: u64, context: &str) -> Vec<u8> {
    let mut claim = identity(hash(index), context);
    claim["issued_at"] = json!(LATER - 5);
    claim["expires_at"] = json!(LATER + 55);
    seal("identity", &claim)
}

#[test]
fn full_registry_of_valid_leases_refuses_new_keys_and_stays_unchanged() {
    let runtime = full();
    let error = runtime
        .accept_identity(&seal("identity", &identity(hash(CAPACITY), "new")), AT)
        .unwrap_err();
    assert!(error.contains("capacity"), "{error}");
    for index in 0..CAPACITY {
        runtime
            .identities
            .lookup(&ExecutionBinding::Transaction(hash(index)), AT)
            .unwrap();
    }
    let mut renewal = identity(hash(3), "renewal");
    renewal["expires_at"] = json!(1800000070);
    runtime
        .accept_identity(&seal("identity", &renewal), AT)
        .expect("renewing an existing key needs no new slot");
}

#[test]
fn full_registry_of_expired_leases_admits_a_new_key() {
    let runtime = full();
    runtime
        .accept_identity(&later(CAPACITY, "new"), LATER)
        .expect("expired leases are reclaimed for room");
}

#[test]
fn expired_key_beyond_the_first_batch_can_be_renewed() {
    let runtime = full();
    // Index order is (expiry, hash): the highest hash is released last.
    runtime
        .accept_identity(&later(CAPACITY - 1, "renewed"), LATER)
        .unwrap();
    assert_eq!(
        runtime
            .identities
            .lookup(&ExecutionBinding::Transaction(hash(CAPACITY - 1)), LATER)
            .unwrap()
            .context_id,
        "renewed"
    );
}
