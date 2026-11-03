//! A submission or simulation whose fact floor is above the installed facts
//! waits, bounded, for publication and then answers -32012 (plan T14).

use alloy_primitives::{Address, Bytes};
use async_trait::async_trait;
use common::{
    MemoryStorage,
    local::{NOW, identity, payload, raw, seal, snapshot, snapshot_at, tx_hash, verifier},
};
use ops_reth_policy::{
    api::{ExecutionBackend, PoolSubmission, PrivateApi},
    archive::ArtifactStore,
    runtime::PolicyRuntime,
    wire::{Identity, SimulationRequest},
};
use serde_json::{Value, json};
use std::{
    path::Path,
    sync::Arc,
    time::{Duration, Instant},
};

mod common;

const TOKEN: &str = "private-test-token";

struct Pool;

#[async_trait]
impl ExecutionBackend for Pool {
    fn capabilities(&self) -> Vec<String> {
        common::golden::Backend.capabilities()
    }
    async fn submit(
        &self,
        _identity: Identity,
        _raw: Bytes,
        _signer: Address,
    ) -> Result<PoolSubmission, String> {
        Ok(PoolSubmission::Inserted(tx_hash()))
    }
    async fn simulate(
        &self,
        _identity: Identity,
        _request: SimulationRequest,
        _exact: Bytes,
    ) -> Result<Value, String> {
        Ok(json!("0x1234"))
    }
}

fn node(clock: i64, wait: Duration) -> (Arc<PrivateApi>, Arc<PolicyRuntime>) {
    let archive = ArtifactStore::open_with(Path::new("/state"), MemoryStorage::new()).unwrap();
    let runtime = Arc::new(PolicyRuntime::open(verifier(), Arc::new(archive), 16, NOW).unwrap());
    runtime
        .accept_facts("snapshot", &serde_json::to_vec(&snapshot()).unwrap(), NOW)
        .unwrap();
    let api = PrivateApi::new(
        runtime.clone(),
        Arc::new(Pool),
        TOKEN.into(),
        Arc::new(move || clock),
    )
    .unwrap()
    .with_fact_wait(wait);
    (Arc::new(api), runtime)
}

async fn call(api: &PrivateApi, method: &str, params: Value) -> Value {
    let body =
        serde_json::to_vec(&json!({"jsonrpc":"2.0","id":"ops-1","method":method,"params":params}))
            .unwrap();
    let response = api.process(&format!("Bearer {TOKEN}"), &body).await;
    assert_eq!(response.status, 200);
    serde_json::from_slice(&response.body).unwrap()
}

fn submission(context: &str, minimum: u64) -> Value {
    json!([identity(context, 1000, 1100, minimum), raw()])
}

#[tokio::test]
async fn admission_waits_for_min_version_then_fails_with_32012() {
    let (api, runtime) = node(NOW, Duration::from_millis(400));
    let status = call(&api, "ops_policyStatus", json!([])).await;
    assert!(
        status["result"]["capabilities"]
            .as_array()
            .unwrap()
            .contains(&json!("fact_wait_v1")),
        "{status}"
    );
    // Floor 8 with facts at 7: the request waits, and version 8 arriving
    // meanwhile admits it.
    let waiting = tokio::spawn({
        let api = api.clone();
        async move { call(&api, "ops_submitTransaction", submission("tx-1", 8)).await }
    });
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(!waiting.is_finished(), "refused instead of waiting");
    let applied = call(&api, "ops_policyApply", json!([snapshot_at(8, 1010)])).await;
    assert_eq!(applied["result"]["version"], 8, "{applied}");
    let admitted = waiting.await.unwrap();
    assert_eq!(admitted["result"]["status"], "accepted", "{admitted}");

    // Floor 9 never arrives: -32012 after the bounded wait, and nothing was
    // registered for it (OPS releases its row on -32012).
    let before = runtime.identities.occupancy().unwrap();
    let started = Instant::now();
    let pending = call(&api, "ops_submitTransaction", submission("tx-2", 9)).await;
    let waited = started.elapsed();
    assert_eq!(pending["error"]["code"], -32012, "{pending}");
    assert_eq!(pending["error"]["message"], "policy facts pending");
    assert!(
        waited >= Duration::from_millis(400) && waited < Duration::from_secs(3),
        "{waited:?}"
    );
    assert_eq!(runtime.identities.occupancy().unwrap(), before);
}

#[tokio::test]
async fn stale_or_missing_facts_fail_at_once_without_waiting() {
    // At 1099 the facts (valid 1000..1100) are still fresh; at 1100 they are
    // stale: no wait, the generic refusal.
    let (api, _) = node(1100, Duration::from_secs(2));
    let started = Instant::now();
    let refused = call(
        &api,
        "ops_submitTransaction",
        json!([identity("tx-1", 1050, 1150, 8), raw()]),
    )
    .await;
    assert_eq!(refused["error"]["code"], -32000, "{refused}");
    assert!(started.elapsed() < Duration::from_millis(500));
    // No facts at all.
    let archive = ArtifactStore::open_with(Path::new("/state"), MemoryStorage::new()).unwrap();
    let runtime = Arc::new(PolicyRuntime::open(verifier(), Arc::new(archive), 16, NOW).unwrap());
    let api = PrivateApi::new(runtime, Arc::new(Pool), TOKEN.into(), Arc::new(|| NOW))
        .unwrap()
        .with_fact_wait(Duration::from_secs(2));
    let started = Instant::now();
    let refused = call(&api, "ops_submitTransaction", submission("tx-1", 8)).await;
    assert_eq!(refused["error"]["code"], -32000, "{refused}");
    assert!(started.elapsed() < Duration::from_millis(500));
}

#[tokio::test]
async fn waiters_are_bounded_and_zero_wait_refuses_at_once() {
    let archive = ArtifactStore::open_with(Path::new("/state"), MemoryStorage::new()).unwrap();
    let runtime = Arc::new(PolicyRuntime::open(verifier(), Arc::new(archive), 16, NOW).unwrap());
    runtime
        .accept_facts("snapshot", &serde_json::to_vec(&snapshot()).unwrap(), NOW)
        .unwrap();
    let api = Arc::new(
        PrivateApi::new(runtime, Arc::new(Pool), TOKEN.into(), Arc::new(|| NOW))
            .unwrap()
            .with_fact_wait(Duration::from_secs(2))
            .with_fact_waiters(1),
    );
    let first = tokio::spawn({
        let api = api.clone();
        async move { call(&api, "ops_submitTransaction", submission("tx-1", 8)).await }
    });
    tokio::time::sleep(Duration::from_millis(100)).await;
    let started = Instant::now();
    let second = call(&api, "ops_submitTransaction", submission("tx-2", 8)).await;
    assert_eq!(second["error"]["code"], -32012, "{second}");
    assert!(
        started.elapsed() < Duration::from_millis(500),
        "the second request waited"
    );
    call(&api, "ops_policyApply", json!([snapshot_at(8, 1010)])).await;
    assert_eq!(first.await.unwrap()["result"]["status"], "accepted");

    let (zero, _) = node(NOW, Duration::ZERO);
    let status = call(&zero, "ops_policyStatus", json!([])).await;
    assert!(
        !status["result"]["capabilities"]
            .as_array()
            .unwrap()
            .contains(&json!("fact_wait_v1")),
        "{status}"
    );
    let refused = call(&zero, "ops_submitTransaction", submission("tx-1", 8)).await;
    assert_eq!(refused["error"]["code"], -32012, "{refused}");
}

#[tokio::test]
async fn simulation_waits_for_its_floor_too() {
    let (api, _) = node(NOW, Duration::from_millis(300));
    let gold = common::golden::envelopes();
    let mut simulation = payload("simulation_identity");
    simulation["min_snapshot_version"] = json!(8);
    let params = json!([seal("identity", &simulation), gold["simulation"]]);
    let started = Instant::now();
    let pending = call(&api, "ops_simulate", params.clone()).await;
    assert_eq!(pending["error"]["code"], -32012, "{pending}");
    assert!(started.elapsed() >= Duration::from_millis(300));
    call(&api, "ops_policyApply", json!([snapshot_at(8, 1010)])).await;
    let answered = call(&api, "ops_simulate", params).await;
    assert_eq!(answered["result"], "0x1234", "{answered}");
}
