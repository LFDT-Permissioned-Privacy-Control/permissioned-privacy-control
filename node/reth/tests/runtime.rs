use alloy_evm::{
    Evm, EvmEnv, EvmFactory,
    revm::{
        bytecode::Bytecode,
        context::{CfgEnv, TxEnv},
        database::InMemoryDB,
        primitives::hardfork::SpecId,
        state::AccountInfo,
    },
};
use alloy_primitives::{Address, B256, Bytes, U256, keccak256};
use base64::{Engine, engine::general_purpose::STANDARD};
use ed25519_dalek::{Signer, SigningKey};
use ops_reth_policy::{
    archive::{ArtifactStore, BlockDescriptor},
    context::ExecutionBinding,
    runtime::PolicyRuntime,
    transaction::PolicyTx,
    wire::{Network, Verifier},
};
use serde_json::{Value, json};
use std::{collections::BTreeMap, sync::Arc};

fn seal(kind: &str, payload: &Value) -> Vec<u8> {
    let payload = serde_json::to_vec(payload).unwrap();
    let mut bytes = b"OPS_NODE_POLICY_V1\0".to_vec();
    for part in [kind.as_bytes(), b"ops", payload.as_slice()] {
        bytes.extend_from_slice(&(part.len() as u32).to_be_bytes());
        bytes.extend_from_slice(part);
    }
    serde_json::to_vec(&json!({"version":1,"kind":kind,"key_id":"ops","payload":STANDARD.encode(payload),"signature":STANDARD.encode(SigningKey::from_bytes(&[7;32]).sign(&bytes).to_bytes())})).unwrap()
}
fn fixture() -> Value {
    serde_json::from_str(include_str!(
        "../../../internal/policydsl/testdata/lifecycle-v1.json"
    ))
    .unwrap()
}
fn network() -> Network {
    Network {
        chain_id: 31337,
        deployment_id: "compiler-fixture".into(),
    }
}
fn descriptor() -> BlockDescriptor {
    BlockDescriptor {
        network: network(),
        hash: B256::repeat_byte(10),
        parent_hash: B256::repeat_byte(9),
        number: 1,
        timestamp: 1800000010,
        transactions: vec![B256::repeat_byte(1)],
    }
}
fn execute(handle: &ops_reth_policy::runtime::ExecutionHandle) -> bool {
    let case = &fixture()["cases"][0];
    let signer = case["facts"]["signer"]
        .as_str()
        .unwrap()
        .parse::<Address>()
        .unwrap();
    let target = case["call"]["code_address"]
        .as_str()
        .unwrap()
        .parse::<Address>()
        .unwrap();
    let data = case["call"]["data_hex"]
        .as_str()
        .unwrap()
        .parse::<Bytes>()
        .unwrap();
    let mut db = InMemoryDB::default();
    db.insert_account_info(
        signer,
        AccountInfo {
            balance: U256::from(1_000_000_000),
            ..Default::default()
        },
    );
    db.insert_account_info(
        target,
        AccountInfo {
            code_hash: keccak256([0]),
            code: Some(Bytecode::new_raw(Bytes::from_static(&[0]))),
            ..Default::default()
        },
    );
    let mut evm = handle.factory().create_evm(
        db,
        EvmEnv {
            cfg_env: CfgEnv::new_with_spec(SpecId::PRAGUE),
            ..Default::default()
        },
    );
    let tx = TxEnv::builder()
        .caller(signer)
        .to(target)
        .data(data)
        .gas_limit(200_000)
        .gas_price(0)
        .build()
        .unwrap();
    evm.transact_raw(PolicyTx::bound(
        tx,
        ExecutionBinding::Transaction(B256::repeat_byte(1)),
    ))
    .is_ok()
}

#[test]
fn produced_block_replays_original_facts_after_revocation_and_restart() {
    let directory = std::env::temp_dir().join(format!("ops-runtime-replay-{}", std::process::id()));
    let verifier = Verifier::new(
        network(),
        BTreeMap::from([(
            "ops".into(),
            SigningKey::from_bytes(&[7; 32]).verifying_key(),
        )]),
    );
    let runtime = PolicyRuntime::new(
        verifier.clone(),
        Arc::new(ArtifactStore::open(&directory).unwrap()),
        16,
    );
    let mut snapshot = fixture()["snapshot"].clone();
    runtime
        .accept_facts("snapshot", &seal("snapshot", &snapshot), 1800000010)
        .unwrap();
    let identity = json!({"network":network(),"issued_at":1800000000,"expires_at":1800000060,"scope":"transaction","context_id":"ctx-a","principal_id":"fixture_principal","org_id":"org_acme","signer":snapshot["principals"][0]["linked_addresses"][0],"binding_hash":format!("{:#x}",B256::repeat_byte(1)),"min_snapshot_version":1});
    runtime
        .accept_identity(&seal("identity", &identity), 1800000010)
        .unwrap();
    let original = runtime.pin_candidate(1800000010).unwrap();
    assert!(
        original.persist(&runtime.archive, &descriptor()).is_err(),
        "unexecuted transaction has no retained identity"
    );
    assert!(execute(&original));
    let mut renewed = identity.clone();
    renewed["context_id"] = json!("renewed-context");
    renewed["issued_at"] = json!(1800000010);
    renewed["expires_at"] = json!(1800000070);
    runtime
        .accept_identity(&seal("identity", &renewed), 1800000010)
        .unwrap();
    original.persist(&runtime.archive, &descriptor()).unwrap();
    let manifest = runtime
        .archive
        .manifest(1, descriptor().hash)
        .unwrap()
        .unwrap();
    let captured = runtime
        .verifier()
        .open_identity(&manifest.entries[0].envelope.to_wire(), 1800000010)
        .unwrap();
    assert_eq!(
        captured.context_id, "ctx-a",
        "manifest must retain the identity that actually executed, not a concurrent renewal"
    );
    assert_eq!(
        runtime
            .transaction_status(B256::repeat_byte(1), Some((1, descriptor().hash)))
            .unwrap()
            .unwrap()
            .status,
        "produced"
    );
    snapshot["version"] = json!(2);
    snapshot["principals"][0]["banned"] = json!(true);
    runtime
        .accept_facts("snapshot", &seal("snapshot", &snapshot), 1800000020)
        .unwrap();
    assert!(!execute(&runtime.pin_candidate(1800000020).unwrap()));
    let denied = runtime
        .transaction_status(B256::repeat_byte(1), None)
        .unwrap()
        .unwrap();
    assert_eq!(
        (
            denied.status.as_str(),
            denied.reason_code.as_str(),
            denied.facts_version
        ),
        ("denied", "POLICY_DENIED", 2)
    );
    // Replaying the produced block executes the archived identity: it must not
    // overwrite the live candidate outcome.
    assert!(execute(&runtime.replay(&descriptor()).unwrap()));
    assert_eq!(
        runtime
            .transaction_status(B256::repeat_byte(1), None)
            .unwrap()
            .unwrap()
            .status,
        "denied"
    );
    // A renewal keeps the outcome until the next build.
    let mut later = renewed.clone();
    later["issued_at"] = json!(1800000020);
    later["expires_at"] = json!(1800000080);
    runtime
        .accept_identity(&seal("identity", &later), 1800000020)
        .unwrap();
    assert_eq!(
        runtime
            .transaction_status(B256::repeat_byte(1), None)
            .unwrap()
            .unwrap()
            .status,
        "denied"
    );
    drop(runtime);
    let restarted = PolicyRuntime::open(
        verifier.clone(),
        Arc::new(ArtifactStore::open(&directory).unwrap()),
        16,
        1800000020,
    )
    .unwrap();
    assert!(
        !execute(&restarted.pin_candidate(1800000020).unwrap()),
        "replay facts must not become current user permissions"
    );
    assert!(execute(&restarted.replay(&descriptor()).unwrap()));
    assert_eq!(
        restarted
            .status_identity(B256::repeat_byte(1), Some((1, descriptor().hash)))
            .unwrap()
            .context_id,
        "ctx-a",
        "status reports the identity that executed in the block"
    );
    assert!(
        restarted
            .status_identity(B256::repeat_byte(1), None)
            .is_err(),
        "pending identities are not restored"
    );
    assert!(
        restarted
            .status_identity(B256::repeat_byte(2), Some((1, descriptor().hash)))
            .is_err()
    );
    let mut wrong = descriptor();
    wrong.hash = B256::repeat_byte(99);
    assert!(restarted.replay(&wrong).is_err());
    drop(restarted);
    // The same archive opened for another network discloses nothing.
    let foreign = PolicyRuntime::new(
        Verifier::new(
            Network {
                chain_id: 31337,
                deployment_id: "another-deployment".into(),
            },
            BTreeMap::from([(
                "ops".into(),
                SigningKey::from_bytes(&[7; 32]).verifying_key(),
            )]),
        ),
        Arc::new(ArtifactStore::open(&directory).unwrap()),
        16,
    );
    assert!(
        foreign
            .status_identity(B256::repeat_byte(1), Some((1, descriptor().hash)))
            .is_err()
    );
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn finalized_release_frees_the_slot_and_the_manifest_keeps_the_executed_binding() {
    let directory =
        std::env::temp_dir().join(format!("ops-runtime-terminal-{}", std::process::id()));
    let verifier = Verifier::new(
        network(),
        BTreeMap::from([(
            "ops".into(),
            SigningKey::from_bytes(&[7; 32]).verifying_key(),
        )]),
    );
    let archive = Arc::new(ArtifactStore::open(&directory).unwrap());
    let runtime = PolicyRuntime::new(verifier.clone(), archive.clone(), 1);
    let snapshot = fixture()["snapshot"].clone();
    runtime
        .accept_facts("snapshot", &seal("snapshot", &snapshot), 1800000010)
        .unwrap();
    let mut identity = json!({"network":network(),"issued_at":1800000000,"expires_at":1800000060,"scope":"transaction","context_id":"ctx-a","principal_id":"fixture_principal","org_id":"org_acme","signer":snapshot["principals"][0]["linked_addresses"][0],"binding_hash":format!("{:#x}",B256::repeat_byte(1)),"min_snapshot_version":1});
    runtime
        .accept_identity(&seal("identity", &identity), 1800000010)
        .unwrap();
    let handle = runtime.pin_candidate(1800000010).unwrap();
    assert!(execute(&handle));
    handle.persist(&archive, &descriptor()).unwrap();
    assert!(
        runtime
            .canonical_status(
                B256::repeat_byte(1),
                (1, B256::repeat_byte(99)),
                true,
                final_evidence()
            )
            .is_err(),
        "release requires the including block's evidence"
    );
    runtime
        .canonical_status(
            B256::repeat_byte(1),
            (1, descriptor().hash),
            true,
            final_evidence(),
        )
        .unwrap();
    assert!(
        runtime
            .identities
            .lookup(
                &ExecutionBinding::Transaction(B256::repeat_byte(1)),
                1800000010
            )
            .is_err()
    );
    identity["binding_hash"] = json!(format!("{:#x}", B256::repeat_byte(2)));
    runtime
        .accept_identity(&seal("identity", &identity), 1800000010)
        .expect("the released slot is free for another transaction");
    drop(runtime);
    let restarted = PolicyRuntime::open(verifier, archive, 1, 1800000100).unwrap();
    assert!(
        restarted.pin_candidate(1800000100).is_err(),
        "expired retained facts must not become fresh"
    );
    assert_eq!(
        restarted
            .status_identity(B256::repeat_byte(1), Some((1, descriptor().hash)))
            .unwrap()
            .principal_id,
        "fixture_principal"
    );
    assert!(
        restarted
            .transaction_status(B256::repeat_byte(1), Some((1, descriptor().hash)))
            .unwrap()
            .is_some()
    );
    std::fs::remove_dir_all(directory).unwrap();
}

/// The descriptor block (1, 0x0a…) canonical and finalized by block 2.
fn final_evidence() -> Option<ops_reth_policy::runtime::FinalityEvidence> {
    Some(ops_reth_policy::runtime::FinalityEvidence {
        canonical_at_inclusion: descriptor().hash,
        finalized_number: 2,
        finalized_hash: B256::repeat_byte(20),
    })
}

/// A runtime with the fixture identity for 0x01… executed in the descriptor
/// block and its manifest published.
fn included(name: &str) -> (PolicyRuntime, std::path::PathBuf) {
    let directory = std::env::temp_dir().join(format!("ops-runtime-{name}-{}", std::process::id()));
    let verifier = Verifier::new(
        network(),
        BTreeMap::from([(
            "ops".into(),
            SigningKey::from_bytes(&[7; 32]).verifying_key(),
        )]),
    );
    let archive = Arc::new(ArtifactStore::open(&directory).unwrap());
    let runtime = PolicyRuntime::new(verifier, archive.clone(), 4);
    let snapshot = fixture()["snapshot"].clone();
    runtime
        .accept_facts("snapshot", &seal("snapshot", &snapshot), 1800000010)
        .unwrap();
    let identity = json!({"network":network(),"issued_at":1800000000,"expires_at":1800000060,"scope":"transaction","context_id":"ctx-a","principal_id":"fixture_principal","org_id":"org_acme","signer":snapshot["principals"][0]["linked_addresses"][0],"binding_hash":format!("{:#x}",B256::repeat_byte(1)),"min_snapshot_version":1});
    runtime
        .accept_identity(&seal("identity", &identity), 1800000010)
        .unwrap();
    let candidate = runtime.pin_candidate(1800000010).unwrap();
    assert!(execute(&candidate));
    candidate.persist(&archive, &descriptor()).unwrap();
    (runtime, directory)
}

fn live(runtime: &PolicyRuntime) -> bool {
    runtime
        .identities
        .lookup(
            &ExecutionBinding::Transaction(B256::repeat_byte(1)),
            1800000010,
        )
        .is_ok()
}

#[test]
fn identity_released_at_finality_not_inclusion() {
    let (runtime, directory) = included("finality");
    let tx = B256::repeat_byte(1);
    let block = (1, descriptor().hash);
    let provisional = runtime.canonical_status(tx, block, true, None).unwrap();
    assert_eq!(
        (provisional.status.as_str(), provisional.finalized),
        ("included", false)
    );
    assert!(live(&runtime), "released at inclusion, before finality");
    let rival = Some(ops_reth_policy::runtime::FinalityEvidence {
        canonical_at_inclusion: B256::repeat_byte(77),
        ..final_evidence().unwrap()
    });
    assert!(
        !runtime
            .canonical_status(tx, block, true, rival)
            .unwrap()
            .finalized
    );
    assert!(
        live(&runtime),
        "released although another block is canonical at the height"
    );
    let early = Some(ops_reth_policy::runtime::FinalityEvidence {
        finalized_number: 0,
        ..final_evidence().unwrap()
    });
    assert!(
        !runtime
            .canonical_status(tx, block, true, early)
            .unwrap()
            .finalized
    );
    assert!(live(&runtime), "released below the finalized height");
    let reverted = runtime
        .canonical_status(tx, block, false, final_evidence())
        .unwrap();
    assert_eq!(
        (reverted.status.as_str(), reverted.finalized),
        ("reverted", true)
    );
    assert!(!live(&runtime), "a finalized outcome must release the slot");
    assert!(
        !execute(&runtime.pin_candidate(1800000010).unwrap()),
        "executed without an identity after release"
    );
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn reorg_before_finality_reexecutes_without_ops() {
    let (runtime, directory) = included("reorg");
    runtime
        .canonical_status(B256::repeat_byte(1), (1, descriptor().hash), true, None)
        .unwrap();
    // A reorg drops the block and the transaction returns to the pool: a new
    // candidate executes it again with the still-live identity, no OPS call.
    assert!(execute(&runtime.pin_candidate(1800000010).unwrap()));
    std::fs::remove_dir_all(directory).unwrap();
}
