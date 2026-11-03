//! The private listeners (plan T15, T19): a listener over its cap still
//! serves fact publication and status and answers anything else 503 with
//! Retry-After; connections are recycled at a response boundary; fact changes
//! apply while every execution connection waits for them, on a separate
//! control listener and over the main listener's cap.

use alloy_primitives::{Address, Bytes};
use async_trait::async_trait;
use common::{
    MemoryStorage,
    local::{NOW, identity, raw, snapshot, snapshot_at, tx_hash, verifier},
};
use ops_reth_policy::{
    api::{ExecutionBackend, Lane, ListenerConfig, PoolSubmission, PrivateApi, serve_with},
    archive::ArtifactStore,
    runtime::PolicyRuntime,
    wire::{Identity, SimulationRequest},
};
use serde_json::{Value, json};
use std::{
    net::SocketAddr,
    path::Path,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

mod common;

const TOKEN: &str = "private-test-token";

/// A pool that inserts, after an optional delay.
#[derive(Default)]
struct Pool {
    delay: Duration,
}

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
        tokio::time::sleep(self.delay).await;
        Ok(PoolSubmission::Inserted(tx_hash()))
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

fn node(pool: Pool) -> (Arc<PrivateApi>, Arc<PolicyRuntime>) {
    let archive = ArtifactStore::open_with(Path::new("/state"), MemoryStorage::new()).unwrap();
    let runtime = Arc::new(PolicyRuntime::open(verifier(), Arc::new(archive), 16, NOW).unwrap());
    runtime
        .accept_facts("snapshot", &serde_json::to_vec(&snapshot()).unwrap(), NOW)
        .unwrap();
    let api = PrivateApi::new(
        runtime.clone(),
        Arc::new(pool),
        TOKEN.into(),
        Arc::new(|| NOW),
    )
    .unwrap()
    .with_fact_wait(Duration::from_secs(4));
    (Arc::new(api), runtime)
}

fn body(method: &str, params: Value) -> Vec<u8> {
    serde_json::to_vec(&json!({"jsonrpc":"2.0","id":"ops-1","method":method,"params":params}))
        .unwrap()
}

fn submission(context: &str, minimum: u64) -> Vec<u8> {
    body(
        "ops_submitTransaction",
        json!([identity(context, 1000, 1100, minimum), raw()]),
    )
}

/// One HTTP/1.1 exchange on `stream`: (status, lowercase head, body).
async fn exchange(stream: &mut TcpStream, payload: &[u8]) -> (u16, String, Vec<u8>) {
    let request = format!(
        "POST / HTTP/1.1\r\nHost: node\r\nAuthorization: Bearer {TOKEN}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
        payload.len()
    );
    stream.write_all(request.as_bytes()).await.unwrap();
    stream.write_all(payload).await.unwrap();
    let mut buffer = Vec::new();
    let header_end = loop {
        if let Some(end) = buffer.windows(4).position(|w| w == b"\r\n\r\n") {
            break end + 4;
        }
        let mut chunk = [0u8; 4096];
        let read = stream.read(&mut chunk).await.unwrap();
        assert!(read > 0, "connection closed before a response");
        buffer.extend_from_slice(&chunk[..read]);
    };
    let head = String::from_utf8_lossy(&buffer[..header_end]).to_lowercase();
    let status = head[9..12].parse().unwrap();
    let length: usize = head
        .lines()
        .find_map(|line| line.strip_prefix("content-length: "))
        .map(|value| value.trim().parse().unwrap())
        .unwrap_or(0);
    while buffer.len() < header_end + length {
        let mut chunk = [0u8; 4096];
        let read = stream.read(&mut chunk).await.unwrap();
        assert!(read > 0, "connection closed inside a response");
        buffer.extend_from_slice(&chunk[..read]);
    }
    (
        status,
        head,
        buffer[header_end..header_end + length].to_vec(),
    )
}

async fn send(address: SocketAddr, payload: Vec<u8>) -> (u16, String, Value) {
    let mut stream = TcpStream::connect(address).await.unwrap();
    let (status, head, body) = exchange(&mut stream, &payload).await;
    (
        status,
        head,
        serde_json::from_slice(&body).unwrap_or(Value::Null),
    )
}

async fn closed(stream: &mut TcpStream) -> bool {
    let mut byte = [0u8; 1];
    matches!(
        tokio::time::timeout(Duration::from_secs(2), stream.read(&mut byte)).await,
        Ok(Ok(0)) | Ok(Err(_))
    )
}

async fn listen(
    api: Arc<PrivateApi>,
    config: ListenerConfig,
) -> (SocketAddr, tokio::sync::oneshot::Sender<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(serve_with(listener, api, config, async move {
        let _ = stopped.await;
    }));
    (address, stop)
}

fn lane(lane: Lane, max_connections: usize) -> ListenerConfig {
    ListenerConfig {
        lane,
        max_connections,
        ..ListenerConfig::default()
    }
}

#[tokio::test]
async fn listener_over_capacity_returns_503() {
    let (api, _) = node(Pool {
        delay: Duration::from_millis(800),
    });
    let (address, _stop) = listen(api, lane(Lane::Execution, 2)).await;
    let held: Vec<_> = ["tx-1", "tx-2"]
        .into_iter()
        .map(|context| tokio::spawn(send(address, submission(context, 7))))
        .collect();
    tokio::time::sleep(Duration::from_millis(200)).await;
    // Over the cap: a submission is refused with 503 and Retry-After, and the
    // connection is closed after that answer.
    let mut over = TcpStream::connect(address).await.unwrap();
    let (status, head, _) = exchange(&mut over, &submission("tx-3", 7)).await;
    assert_eq!(status, 503, "{head}");
    assert!(head.contains("retry-after: 1"), "{head}");
    assert!(
        closed(&mut over).await,
        "an over-capacity connection stayed open"
    );
    // Status (and fact publication) are still served over the cap.
    let (status, head, answer) = send(address, body("ops_policyStatus", json!([]))).await;
    assert_eq!(status, 200, "{head}");
    assert_eq!(answer["result"]["version"], 7, "{answer}");
    for exchange in held {
        let (status, _, answer) = exchange.await.unwrap();
        assert_eq!(status, 200);
        assert_eq!(answer["result"]["status"], "accepted", "{answer}");
    }
}

#[tokio::test]
async fn connections_are_recycled_after_a_complete_response() {
    let (api, _) = node(Pool {
        delay: Duration::from_millis(600),
    });
    let config = ListenerConfig {
        connection_lifetime: Duration::from_millis(300),
        ..lane(Lane::Execution, 8)
    };
    let (address, _stop) = listen(api, config).await;
    let mut stream = TcpStream::connect(address).await.unwrap();
    let (status, head, _) = exchange(&mut stream, &body("ops_policyStatus", json!([]))).await;
    assert_eq!(status, 200);
    assert!(!head.contains("connection: close"), "{head}");
    // A submission in flight past the connection's lifetime completes, and
    // only then is the connection closed.
    let (status, head, answer) = exchange(&mut stream, &submission("tx-1", 7)).await;
    assert_eq!(status, 200, "{head}");
    let answer: Value = serde_json::from_slice(&answer).unwrap();
    assert_eq!(answer["result"]["status"], "accepted", "{answer}");
    assert!(head.contains("connection: close"), "{head}");
    assert!(closed(&mut stream).await);
}

#[tokio::test]
async fn control_lane_applies_facts_while_execution_lane_is_saturated() {
    let (api, runtime) = node(Pool::default());
    let (execution, _stop) = listen(api.clone(), lane(Lane::Execution, 2)).await;
    let (control, _stop_control) = listen(api.clone(), lane(Lane::Control, 1)).await;
    // Every execution connection holds a submission waiting for version 8.
    let waiting = |minimum: u64| -> Vec<_> {
        ["tx-1", "tx-2"]
            .into_iter()
            .map(|context| tokio::spawn(send(execution, submission(context, minimum))))
            .collect()
    };
    let waiters = waiting(8);
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(send(execution, submission("tx-3", 7)).await.0, 503);
    // The control listener applies the change at once.
    let started = Instant::now();
    let (status, _, applied) = send(
        control,
        body("ops_policyApply", json!([snapshot_at(8, 1010)])),
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(applied["result"]["version"], 8, "{applied}");
    assert!(
        started.elapsed() < Duration::from_millis(500),
        "{:?}",
        started.elapsed()
    );
    for waiter in waiters {
        let (status, _, answer) = waiter.await.unwrap();
        assert_eq!(status, 200);
        assert_eq!(answer["result"]["status"], "accepted", "{answer}");
    }
    // With a single URL, publication over the main listener's cap applies too.
    let waiters = waiting(9);
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(
        send(execution, submission("tx-3", 7)).await.0,
        503,
        "not saturated"
    );
    let (status, _, applied) = send(
        execution,
        body("ops_policyApply", json!([snapshot_at(9, 1011)])),
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(applied["result"]["version"], 9, "{applied}");
    for waiter in waiters {
        assert_eq!(waiter.await.unwrap().2["result"]["status"], "accepted");
    }
    // The control listener serves only control methods: a valid submission
    // is refused there (it would be accepted on the execution listener).
    let (status, _, refused) = send(control, submission("tx-4", 9)).await;
    assert_eq!(status, 200);
    assert_eq!(refused["error"]["code"], -32000, "{refused}");
    // Whichever waiter installed last holds the slot; never the refused one.
    let installed = runtime
        .identities
        .live(&ops_reth_policy::context::ExecutionBinding::Transaction(
            tx_hash(),
        ))
        .unwrap()
        .context_id;
    assert!(
        installed == "tx-1" || installed == "tx-2",
        "the refused submission was registered: {installed}"
    );
}
