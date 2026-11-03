//! No blocking work on async workers: identity verification, transaction
//! decoding and admission run in the CPU pool, fact persistence on its own
//! blocking lane, so `ops_policyStatus` answers meanwhile even on a
//! single-threaded runtime.

use alloy_primitives::B256;
use common::{Action, Gate, MemoryStorage, Op, golden};
use ops_reth_policy::{api::CpuPool, context::ExecutionBinding};
use serde_json::json;
use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread::JoinHandle,
    time::Duration,
};

mod common;

/// Yield until `gate` is reached, failing if it never is.
async fn reached(gate: &Gate, what: &str) {
    for _ in 0..2_000 {
        if gate.entered() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    panic!("{what} never left the async worker");
}

type Threads = Arc<Mutex<Vec<JoinHandle<()>>>>;

/// A pool whose jobs each wait on `hold`; job threads are kept for joining.
fn held_pool(hold: &Arc<Gate>, threads: &Threads) -> CpuPool {
    let (hold, threads) = (hold.clone(), threads.clone());
    CpuPool::with_spawner(4, move |job| {
        let hold = hold.clone();
        threads.lock().unwrap().push(std::thread::spawn(move || {
            hold.pass();
            job();
        }));
    })
}

fn current_thread() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

#[test]
fn verification_and_admission_run_off_the_async_worker() {
    current_thread().block_on(async {
        let gold = golden::envelopes();
        let (hold, threads) = (Gate::new(), Threads::default());
        let (api, verifier, runtime) = golden::api_with_runtime(&MemoryStorage::new());
        let api = Arc::new(api.with_cpu_pool(held_pool(&hold, &threads)));
        // Fact ingestion uses its own lane, not the held pool.
        golden::call(
            &api,
            "ops_policyApply",
            json!([gold["transaction_snapshot"]]),
        )
        .await;
        let verified = verifier.signature_verifications();
        let submit = tokio::spawn({
            let (api, gold) = (api.clone(), gold.clone());
            async move {
                golden::call(
                    &api,
                    "ops_submitTransaction",
                    json!([gold["transaction_identity"], gold["raw_transaction"]]),
                )
                .await
            }
        });
        reached(&hold, "identity verification").await;
        let status = golden::call(&api, "ops_policyStatus", json!([])).await;
        assert_eq!(status["result"]["version"], 7, "{status}");
        assert_eq!(
            verifier.signature_verifications(),
            verified,
            "the identity was verified before the pool job ran"
        );
        assert_eq!(
            runtime.identities.occupancy().unwrap(),
            0,
            "admitted before the pool job ran"
        );
        hold.open();
        let submitted = submit.await.unwrap();
        assert_eq!(submitted["result"]["status"], "accepted", "{submitted}");
        assert_eq!(verifier.signature_verifications() - verified, 1);
        assert_eq!(runtime.identities.occupancy().unwrap(), 1);
    });
}

#[test]
fn fact_persistence_runs_off_the_async_worker() {
    current_thread().block_on(async {
        let gold = golden::envelopes();
        let storage = MemoryStorage::new();
        let (api, _) = golden::api(&storage);
        let api = Arc::new(api);
        let write = Gate::new();
        // If persistence blocked the only worker, this opens the gate (and says
        // so) so the test fails instead of hanging.
        let (stop, stopped) = std::sync::mpsc::channel::<()>();
        let fired = Arc::new(AtomicBool::new(false));
        let watchdog = {
            let (write, fired) = (write.clone(), fired.clone());
            std::thread::spawn(move || {
                if stopped.recv_timeout(Duration::from_secs(5)).is_err() {
                    fired.store(true, Ordering::SeqCst);
                    write.open();
                }
            })
        };
        storage.set_hook({
            let write = write.clone();
            move |op, _| {
                if op == Op::Write {
                    write.pass();
                }
                Action::Proceed
            }
        });
        let apply = tokio::spawn({
            let api = api.clone();
            async move { golden::call(&api, "ops_policyApply", json!([gold["snapshot"]])).await }
        });
        reached(&write, "fact persistence").await;
        let status = golden::call(&api, "ops_policyStatus", json!([])).await;
        assert!(
            !fired.load(Ordering::SeqCst) && !apply.is_finished(),
            "status waited for the fact write: {status}"
        );
        write.open();
        assert_eq!(apply.await.unwrap()["result"]["version"], 7);
        storage.clear_hook();
        let _ = stop.send(());
        watchdog.join().unwrap();
    });
}

#[test]
fn cancelled_simulation_never_leaks_a_registry_slot() {
    current_thread().block_on(async {
        let gold = golden::envelopes();
        let (hold, threads) = (Gate::new(), Threads::default());
        let (api, verifier, runtime) = golden::api_with_runtime(&MemoryStorage::new());
        let api = Arc::new(api.with_cpu_pool(held_pool(&hold, &threads)));
        golden::call(&api, "ops_policyApply", json!([gold["snapshot"]])).await;
        let verified = verifier.signature_verifications();
        let request = tokio::spawn({
            let (api, gold) = (api.clone(), gold.clone());
            async move {
                golden::call(
                    &api,
                    "ops_simulate",
                    json!([gold["simulation_identity"], gold["simulation"]]),
                )
                .await
            }
        });
        reached(&hold, "simulation admission").await;
        request.abort();
        assert!(request.await.unwrap_err().is_cancelled());
        hold.open();
        for thread in threads.lock().unwrap().drain(..) {
            thread.join().unwrap();
        }
        assert_eq!(
            verifier.signature_verifications() - verified,
            1,
            "the cancelled job still ran and admitted"
        );
        let binding = ExecutionBinding::Simulation {
            context_id: "sim-1".into(),
            digest: gold["simulation_hash"]
                .as_str()
                .unwrap()
                .parse::<B256>()
                .unwrap(),
        };
        assert!(
            runtime.identities.lookup(&binding, 1020).is_err(),
            "a cancelled simulation left its identity registered"
        );
        assert_eq!(runtime.identities.occupancy().unwrap(), 0);
    });
}
