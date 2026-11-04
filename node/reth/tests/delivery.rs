//! The node side of the delivery contract (plan T16, T17, T18, T23): a response-bound
//! boot id, idempotent success for a dominated identity, definitive pool
//! rejections with a reason, and cleanup that never removes a newer identity.

use alloy_primitives::{Address, Bytes};
use async_trait::async_trait;
use common::{
    MemoryStorage,
    local::{NOW, identity, identity_with, raw, snapshot, tx_hash, verifier},
};
use ops_reth_policy::{
    api::{ExecutionBackend, PoolRejection, PoolSubmission, PrivateApi},
    archive::ArtifactStore,
    context::ExecutionBinding,
    runtime::PolicyRuntime,
    wire::{Identity, SimulationRequest},
};
use serde_json::{Value, json};
use std::{
    collections::VecDeque,
    path::Path,
    sync::{Arc, Mutex},
};

mod common;

/// A pool that answers each submission from a script (then "inserted"), and
/// records the context it was sent for.
#[derive(Default)]
struct Pool {
    answers: Mutex<VecDeque<Result<PoolSubmission, String>>>,
    sent: Mutex<Vec<String>>,
    gate: Option<Arc<common::Gate>>,
}

#[async_trait]
impl ExecutionBackend for Pool {
    fn capabilities(&self) -> Vec<String> {
        common::golden::Backend.capabilities()
    }
    async fn submit(
        &self,
        identity: Identity,
        _raw: Bytes,
        _signer: Address,
    ) -> Result<PoolSubmission, String> {
        self.sent.lock().unwrap().push(identity.context_id.clone());
        let answer = self.answers.lock().unwrap().pop_front();
        if let Some(gate) = &self.gate
            && identity.context_id == "held"
        {
            let gate = gate.clone();
            tokio::task::spawn_blocking(move || gate.pass())
                .await
                .unwrap();
        }
        answer.unwrap_or(Ok(PoolSubmission::Inserted(tx_hash())))
    }
    fn transaction_status(&self, _hash: alloy_primitives::B256) -> Result<Value, String> {
        Ok(
            json!({"status":"pending","facts_version":7,"block_hash":null,"block_number":null,"reason_code":"","created":[]}),
        )
    }
    async fn simulate(
        &self,
        _identity: Identity,
        _request: SimulationRequest,
        _exact: Bytes,
    ) -> Result<Value, String> {
        Err("unused".into())
    }
}

fn runtime(storage: &Arc<MemoryStorage>) -> Arc<PolicyRuntime> {
    let archive = ArtifactStore::open_with(Path::new("/state"), storage.clone()).unwrap();
    Arc::new(PolicyRuntime::open(verifier(), Arc::new(archive), 16, NOW).unwrap())
}

fn api(runtime: &Arc<PolicyRuntime>, pool: Arc<Pool>) -> PrivateApi {
    PrivateApi::new(
        runtime.clone(),
        pool,
        "private-test-token".into(),
        Arc::new(|| NOW),
    )
    .unwrap()
}

async fn call(api: &PrivateApi, method: &str, params: Value) -> Value {
    common::golden::call(api, method, params).await
}

async fn submit(api: &PrivateApi, identity: Value) -> Value {
    call(api, "ops_submitTransaction", json!([identity, raw()])).await
}

fn installed(runtime: &PolicyRuntime) -> Option<String> {
    runtime
        .identities
        .live(&ExecutionBinding::Transaction(tx_hash()))
        .map(|identity| identity.context_id)
}

/// A node with the golden facts applied.
async fn node(storage: &Arc<MemoryStorage>, pool: Arc<Pool>) -> (PrivateApi, Arc<PolicyRuntime>) {
    let runtime = runtime(storage);
    let api = api(&runtime, pool);
    let applied = call(&api, "ops_policyApply", json!([snapshot()])).await;
    assert_eq!(applied["result"]["version"], 7, "{applied}");
    (api, runtime)
}

fn boot_id(response: &Value) -> String {
    let boot = response["result"]["boot_id"]
        .as_str()
        .unwrap_or_else(|| panic!("no boot id: {response}"))
        .to_owned();
    assert_eq!(boot.len(), 32, "{boot}");
    assert!(boot.bytes().all(|b| b.is_ascii_hexdigit()), "{boot}");
    boot
}

#[tokio::test]
async fn boot_id_changes_on_restart_and_resent_envelope_is_admitted() {
    let storage = MemoryStorage::new();
    let envelope = identity("tx-1", 1000, 1100, 7);
    let (first, first_runtime) = node(&storage, Arc::default()).await;
    let status = call(&first, "ops_policyStatus", json!([])).await;
    let boot = boot_id(&status);
    assert!(
        status["result"]["capabilities"]
            .as_array()
            .unwrap()
            .contains(&json!("boot_id_v1")),
        "{status}"
    );
    let submitted = submit(&first, envelope.clone()).await;
    assert_eq!(submitted["result"]["status"], "accepted", "{submitted}");
    assert_eq!(boot_id(&submitted), boot, "a response names another boot");
    let pending = call(
        &first,
        "ops_transactionStatus",
        json!([format!("{:#x}", tx_hash())]),
    )
    .await;
    assert_eq!(boot_id(&pending), boot, "{pending}");
    drop((first, first_runtime));

    // Restart on the same state directory: a new boot, no pending identities.
    let runtime = runtime(&storage);
    let second = api(&runtime, Arc::default());
    let status = call(&second, "ops_policyStatus", json!([])).await;
    let restarted = boot_id(&status);
    assert_ne!(restarted, boot, "the boot id survived a restart");
    assert_eq!(installed(&runtime), None);
    let resent = submit(&second, envelope).await;
    assert_eq!(resent["result"]["status"], "accepted", "{resent}");
    assert_eq!(boot_id(&resent), restarted);
    assert_eq!(installed(&runtime).as_deref(), Some("tx-1"));
    let applied = call(
        &second,
        "ops_policyApply",
        json!([common::local::snapshot_at(8, 1010)]),
    )
    .await;
    assert_eq!(boot_id(&applied), restarted, "{applied}");
}

#[tokio::test]
async fn expired_resend_is_rejected() {
    let storage = MemoryStorage::new();
    let (api, runtime) = node(&storage, Arc::default()).await;
    // Valid 900..1020: expired at the node's clock (1020).
    let expired = submit(&api, identity("tx-old", 900, 1020, 7)).await;
    assert!(expired.get("result").is_none(), "{expired}");
    assert_eq!(installed(&runtime), None);
}

#[tokio::test]
async fn older_identity_for_same_principal_and_binding_is_idempotent_success() {
    let storage = MemoryStorage::new();
    let pool = Arc::new(Pool::default());
    let (api, runtime) = node(&storage, pool.clone()).await;
    // A renewal (newer issue time, expiry and floor) lands first.
    let renewal = submit(&api, identity("tx-2", 1010, 1110, 7)).await;
    assert_eq!(renewal["result"]["context_id"], "tx-2", "{renewal}");
    // The live client's older request arrives late: dominated, so a success
    // under its own context, and the renewal stays installed.
    let late = submit(&api, identity("tx-1", 1000, 1100, 7)).await;
    assert_eq!(late["result"]["status"], "accepted", "{late}");
    assert_eq!(late["result"]["context_id"], "tx-1", "{late}");
    assert_eq!(installed(&runtime).as_deref(), Some("tx-2"));
    // Equal expiry and floor, older issue time: still dominated.
    let equal = submit(&api, identity("tx-3", 1005, 1110, 7)).await;
    assert_eq!(equal["result"]["status"], "accepted", "{equal}");
    assert_eq!(installed(&runtime).as_deref(), Some("tx-2"));

    // Newer facts, so an attempt with a higher floor passes the facts check
    // and reaches the registry.
    let applied = call(
        &api,
        "ops_policyApply",
        json!([common::local::snapshot_at(8, 1010)]),
    )
    .await;
    assert_eq!(applied["result"]["version"], 8, "{applied}");
    for (name, attempt) in [
        // A higher floor than the installed one cannot be a duplicate.
        (
            "higher floor, lower expiry",
            identity("tx-4", 1000, 1100, 8),
        ),
        (
            "another principal",
            identity_with("tx-5", 1000, 1100, 7, |identity| {
                identity["principal_id"] = json!("user-c")
            }),
        ),
        (
            "another organization",
            identity_with("tx-6", 1000, 1100, 7, |identity| {
                identity["org_id"] = json!("org-b")
            }),
        ),
    ] {
        let refused = submit(&api, attempt).await;
        assert_eq!(refused["error"]["code"], -32000, "{name}: {refused}");
        assert_eq!(installed(&runtime).as_deref(), Some("tx-2"), "{name}");
    }
    assert_eq!(
        pool.sent.lock().unwrap().as_slice(),
        ["tx-2", "tx-1", "tx-3"],
        "only admitted attempts reach the pool"
    );
}

#[tokio::test]
async fn pool_rejection_releases_slot_and_reports_reason() {
    for (answer, reason) in [
        (PoolRejection::NonceUsed, "nonce_used"),
        (PoolRejection::Replaced, "replaced"),
    ] {
        let storage = MemoryStorage::new();
        let pool = Arc::new(Pool::default());
        pool.answers
            .lock()
            .unwrap()
            .push_back(Ok(PoolSubmission::Rejected(answer)));
        let (api, runtime) = node(&storage, pool.clone()).await;
        let rejected = submit(&api, identity("tx-1", 1000, 1100, 7)).await;
        assert_eq!(rejected["error"]["code"], -32013, "{rejected}");
        assert_eq!(rejected["error"]["data"]["reason"], reason, "{rejected}");
        assert_eq!(installed(&runtime), None, "{reason}: the slot was kept");
        assert_eq!(runtime.identities.occupancy().unwrap(), 0);
    }

    // Already known: the pool holds it, the identity lets it execute.
    let storage = MemoryStorage::new();
    let pool = Arc::new(Pool::default());
    pool.answers
        .lock()
        .unwrap()
        .push_back(Ok(PoolSubmission::AlreadyKnown));
    let (api, runtime) = node(&storage, pool.clone()).await;
    let known = submit(&api, identity("tx-1", 1000, 1100, 7)).await;
    assert_eq!(known["result"]["status"], "accepted", "{known}");
    assert_eq!(installed(&runtime).as_deref(), Some("tx-1"));

    // A transient or ambiguous pool failure keeps the registration.
    let storage = MemoryStorage::new();
    let pool = Arc::new(Pool::default());
    pool.answers
        .lock()
        .unwrap()
        .push_back(Err("txpool is full".into()));
    let (api, runtime) = node(&storage, pool.clone()).await;
    let failed = submit(&api, identity("tx-1", 1000, 1100, 7)).await;
    assert_eq!(failed["error"]["code"], -32000, "{failed}");
    assert!(failed["error"].get("data").is_none(), "{failed}");
    assert_eq!(installed(&runtime).as_deref(), Some("tx-1"));
}

#[tokio::test]
async fn failed_send_never_removes_newer_identity() {
    let storage = MemoryStorage::new();
    let gate = common::Gate::new();
    let pool = Arc::new(Pool {
        gate: Some(gate.clone()),
        ..Default::default()
    });
    let (api, runtime) = node(&storage, pool.clone()).await;
    let api = Arc::new(api);
    // The first send is held in the pool, then rejected ("nonce too low").
    pool.answers
        .lock()
        .unwrap()
        .push_back(Ok(PoolSubmission::Rejected(PoolRejection::NonceUsed)));
    let held = {
        let api = api.clone();
        tokio::spawn(async move { submit(&api, identity("held", 1000, 1100, 7)).await })
    };
    tokio::task::spawn_blocking({
        let gate = gate.clone();
        move || gate.wait_entered()
    })
    .await
    .unwrap();
    // Meanwhile a newer identity is installed and its send succeeds.
    let newer = submit(&api, identity("tx-2", 1010, 1110, 7)).await;
    assert_eq!(newer["result"]["status"], "accepted", "{newer}");
    gate.open();
    let held = held.await.unwrap();
    assert_eq!(held["error"]["data"]["reason"], "nonce_used", "{held}");
    assert_eq!(
        installed(&runtime).as_deref(),
        Some("tx-2"),
        "a delayed failed send removed the newer identity"
    );
}

#[tokio::test]
async fn failed_renewal_keeps_prior_identity_needed_for_reorg() {
    let storage = MemoryStorage::new();
    let pool = Arc::new(Pool::default());
    let (api, runtime) = node(&storage, pool.clone()).await;
    let first = submit(&api, identity("tx-1", 1000, 1100, 7)).await;
    assert_eq!(first["result"]["status"], "accepted", "{first}");
    // The renewal's send is refused: the nonce was used by another
    // transaction of the signer (an own receipt would make it `Included`).
    pool.answers
        .lock()
        .unwrap()
        .push_back(Ok(PoolSubmission::Rejected(PoolRejection::NonceUsed)));
    let renewal = submit(&api, identity("tx-2", 1010, 1110, 7)).await;
    assert_eq!(renewal["error"]["code"], -32013, "{renewal}");
    assert_eq!(
        installed(&runtime).as_deref(),
        Some("tx-1"),
        "the prior identity a reorg needs was dropped"
    );
    assert!(
        runtime
            .identities
            .lookup(&ExecutionBinding::Transaction(tx_hash()), NOW)
            .is_ok()
    );
}

#[tokio::test]
async fn resend_of_an_included_transaction_keeps_its_identity() {
    // After a restart the registry is empty; OPS renews a transaction that is
    // already in an unfinalized block. The pool says "nonce too low", but the
    // own receipt exists: a success, and the identity stays for a reorg.
    let storage = MemoryStorage::new();
    let pool = Arc::new(Pool::default());
    pool.answers
        .lock()
        .unwrap()
        .push_back(Ok(PoolSubmission::Included));
    let (api, runtime) = node(&storage, pool).await;
    let included = submit(&api, identity("tx-9", 1010, 1110, 7)).await;
    assert_eq!(included["result"]["status"], "accepted", "{included}");
    assert_eq!(installed(&runtime).as_deref(), Some("tx-9"));
}
