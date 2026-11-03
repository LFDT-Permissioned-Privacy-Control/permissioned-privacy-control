//! Each identity received on the private API is signature-verified exactly once
//! on receipt (plan T9).

use alloy_primitives::B256;
use common::{
    MemoryStorage,
    fixture::{AT, execute, identity, seal, snapshot, verifier},
    golden,
};
use ops_reth_policy::{archive::ArtifactStore, runtime::PolicyRuntime};
use serde_json::json;
use std::{path::Path, sync::Arc};

mod common;

fn runtime() -> PolicyRuntime {
    let archive = ArtifactStore::open_with(Path::new("/state"), MemoryStorage::new()).unwrap();
    let runtime = PolicyRuntime::new(verifier(), Arc::new(archive), 16);
    runtime
        .accept_facts("snapshot", &seal("snapshot", &snapshot()), AT)
        .unwrap();
    runtime
}

#[test]
fn admission_verifies_each_identity_once() {
    let runtime = runtime();
    let before = runtime.verifier().signature_verifications();
    runtime
        .accept_identity(
            &seal("identity", &identity(B256::repeat_byte(5), "ctx-a")),
            AT,
        )
        .unwrap();
    assert_eq!(runtime.verifier().signature_verifications() - before, 1);
}

#[test]
fn candidate_builds_do_not_reverify_identities() {
    let runtime = runtime();
    let tx = B256::repeat_byte(4);
    runtime
        .accept_identity(&seal("identity", &identity(tx, "ctx-a")), AT)
        .unwrap();
    let before = runtime.verifier().signature_verifications();
    for _ in 0..3 {
        assert!(execute(&runtime.pin_candidate(AT).unwrap(), tx));
    }
    assert_eq!(runtime.verifier().signature_verifications(), before);
}

#[tokio::test]
async fn identity_verified_once_per_submission() {
    let (api, verifier) = golden::api(&MemoryStorage::new());
    let gold = golden::envelopes();
    golden::call(
        &api,
        "ops_policyApply",
        json!([gold["transaction_snapshot"]]),
    )
    .await;
    let before = verifier.signature_verifications();
    let submitted = golden::call(
        &api,
        "ops_submitTransaction",
        json!([gold["transaction_identity"], gold["raw_transaction"]]),
    )
    .await;
    assert_eq!(submitted["result"]["status"], "accepted", "{submitted}");
    assert_eq!(verifier.signature_verifications() - before, 1, "submission");
    let before = verifier.signature_verifications();
    let simulated = golden::call(
        &api,
        "ops_simulate",
        json!([gold["simulation_identity"], gold["simulation"]]),
    )
    .await;
    assert_eq!(simulated["result"], "0x1234", "{simulated}");
    assert_eq!(verifier.signature_verifications() - before, 1, "simulation");
}

#[test]
fn admission_rechecks_the_validity_window_and_network() {
    let runtime = runtime();
    let verified = verifier()
        .verify_identity(
            &seal("identity", &identity(B256::repeat_byte(6), "ctx-a")),
            AT,
        )
        .unwrap();
    assert!(
        runtime
            .admit_identity(verified.clone(), 1800000060)
            .is_err(),
        "admitted after the lease expired"
    );
    let other = ops_reth_policy::wire::Verifier::new(
        ops_reth_policy::wire::Network {
            chain_id: 31337,
            deployment_id: "another-deployment".into(),
        },
        std::collections::BTreeMap::from([(
            "ops".into(),
            ed25519_dalek::SigningKey::from_bytes(&[7; 32]).verifying_key(),
        )]),
    );
    let mut foreign = identity(B256::repeat_byte(6), "ctx-b");
    foreign["network"]["deployment_id"] = json!("another-deployment");
    let foreign = other
        .verify_identity(&seal("identity", &foreign), AT)
        .unwrap();
    assert!(
        runtime.admit_identity(foreign, AT).is_err(),
        "admitted an identity for another network"
    );
    runtime.admit_identity(verified, AT).unwrap();
}

#[test]
fn reencoded_evidence_with_another_field_order_still_replays() {
    use ops_reth_policy::archive::BlockDescriptor;
    // The sender's key order and whitespace differ from the node's encoding;
    // the archived evidence is re-encoded but signs the same payload bytes.
    let sealed: serde_json::Value =
        serde_json::from_slice(&seal("identity", &identity(B256::repeat_byte(1), "ctx-a")))
            .unwrap();
    let shuffled = format!(
        "{{ \"signature\": {}, \"payload\": {}, \"key_id\": {}, \"kind\": {}, \"version\": 1 }}",
        sealed["signature"], sealed["payload"], sealed["key_id"], sealed["kind"]
    );
    let storage = MemoryStorage::new();
    let archive = Arc::new(ArtifactStore::open_with(Path::new("/state"), storage).unwrap());
    let runtime = PolicyRuntime::new(verifier(), archive.clone(), 16);
    runtime
        .accept_facts("snapshot", &seal("snapshot", &snapshot()), AT)
        .unwrap();
    let verified = runtime
        .verifier()
        .verify_identity(shuffled.as_bytes(), AT)
        .unwrap();
    let encoded = verified.envelope().to_wire();
    assert_ne!(encoded, shuffled.as_bytes());
    runtime.admit_identity(verified, AT).unwrap();
    let handle = runtime.pin_candidate(AT).unwrap();
    assert!(execute(&handle, B256::repeat_byte(1)));
    let block = BlockDescriptor {
        network: common::fixture::network(),
        hash: B256::repeat_byte(10),
        parent_hash: B256::repeat_byte(9),
        number: 1,
        timestamp: AT as u64,
        transactions: vec![B256::repeat_byte(1)],
    };
    handle.persist(&archive, &block).unwrap();
    let manifest = archive.load_for_block(&block).unwrap();
    assert_eq!(
        archive.get(manifest.identities[0].envelope).unwrap(),
        encoded
    );
    assert!(execute(
        &runtime.replay(&block).unwrap(),
        B256::repeat_byte(1)
    ));
}
