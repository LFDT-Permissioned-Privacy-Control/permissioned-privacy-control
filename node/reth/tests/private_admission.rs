//! The private API admits exact Go-signed submissions with one signature
//! verification and no storage I/O.

use common::{
    MemoryStorage,
    golden::{api, call, envelopes},
};
use serde_json::json;

mod common;

#[tokio::test]
async fn submission_performs_no_storage_io_and_verifies_once() {
    let storage = MemoryStorage::new();
    let (api, verifier) = api(&storage);
    let gold = envelopes();
    call(
        &api,
        "ops_policyApply",
        json!([gold["transaction_snapshot"]]),
    )
    .await;
    for attempt in ["first", "retry"] {
        let (before, verified) = (storage.counts(), verifier.signature_verifications());
        storage.set_hook(|_, _| common::Action::Fail);
        let submitted = call(
            &api,
            "ops_submitTransaction",
            json!([gold["transaction_identity"], gold["raw_transaction"]]),
        )
        .await;
        storage.clear_hook();
        assert_eq!(submitted["result"]["status"], "accepted", "{submitted}");
        let used = storage.counts() - before;
        assert_eq!(used, Default::default(), "{attempt}: {used:?}");
        assert_eq!(
            verifier.signature_verifications() - verified,
            1,
            "{attempt} submission"
        );
    }
    let verified = verifier.signature_verifications();
    let simulated = call(
        &api,
        "ops_simulate",
        json!([gold["simulation_identity"], gold["simulation"]]),
    )
    .await;
    assert_eq!(simulated["result"], "0x1234", "{simulated}");
    assert_eq!(verifier.signature_verifications() - verified, 1);
}
