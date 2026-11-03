//! Resubmitting a transaction the pool already holds, for example restored
//! from its backup after a clean node restart, while the node holds no
//! identity for it (plan T16).

use alloy_primitives::{B256, Bytes};
use async_trait::async_trait;
use common::{MemoryStorage, golden};
use ops_reth_policy::{
    api::{ExecutionBackend, PoolSubmission, PrivateApi},
    archive::ArtifactStore,
    context::ExecutionBinding,
    runtime::PolicyRuntime,
    wire::{Identity, SimulationRequest},
};
use serde_json::{Value, json};
use std::{path::Path, sync::Arc};

mod common;

/// A pool that gives every submission the same answer.
struct Pool(PoolSubmission);
#[async_trait]
impl ExecutionBackend for Pool {
    fn capabilities(&self) -> Vec<String> {
        golden::Backend.capabilities()
    }
    async fn submit(&self, _identity: Identity, _raw: Bytes) -> Result<PoolSubmission, String> {
        Ok(self.0)
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

/// Submit the golden transaction to a fresh node whose pool answers `pool`.
async fn submit_golden(pool: PoolSubmission) -> (Value, Arc<PolicyRuntime>) {
    let gold = golden::envelopes();
    let archive = ArtifactStore::open_with(Path::new("/state"), MemoryStorage::new()).unwrap();
    let runtime = Arc::new(PolicyRuntime::new(
        golden::verifier(),
        Arc::new(archive),
        16,
    ));
    let api = PrivateApi::new(
        runtime.clone(),
        Arc::new(Pool(pool)),
        "private-test-token".into(),
        Arc::new(|| 1020),
    )
    .unwrap();
    golden::call(
        &api,
        "ops_policyApply",
        json!([gold["transaction_snapshot"]]),
    )
    .await;
    let submitted = golden::call(
        &api,
        "ops_submitTransaction",
        json!([gold["transaction_identity"], gold["raw_transaction"]]),
    )
    .await;
    (submitted, runtime)
}

#[tokio::test]
async fn already_pooled_resend_counts_as_accepted() {
    let (submitted, runtime) = submit_golden(PoolSubmission::AlreadyKnown).await;
    assert_eq!(submitted["result"]["status"], "accepted", "{submitted}");
    let hash: B256 = submitted["result"]["transaction_hash"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();
    assert!(
        runtime
            .identities
            .lookup(&ExecutionBinding::Transaction(hash), 1020)
            .is_ok(),
        "the pooled transaction has no identity to execute with"
    );
}

#[tokio::test]
async fn pool_answer_for_another_hash_is_refused() {
    let (submitted, _) = submit_golden(PoolSubmission::Inserted(B256::ZERO)).await;
    assert!(submitted.get("result").is_none(), "{submitted}");
    assert_eq!(
        submitted["error"]["message"], "private execution request rejected",
        "{submitted}"
    );
}
