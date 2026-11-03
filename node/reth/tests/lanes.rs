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
    node_on(pool, MemoryStorage::new())
}

fn node_on(pool: Pool, storage: Arc<MemoryStorage>) -> (Arc<PrivateApi>, Arc<PolicyRuntime>) {
    let archive = ArtifactStore::open_with(Path::new("/state"), storage).unwrap();
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
    exchange_as(stream, TOKEN, payload).await
}

/// `exchange` with another bearer token.
async fn exchange_as(
    stream: &mut TcpStream,
    token: &str,
    payload: &[u8],
) -> (u16, String, Vec<u8>) {
    let request = format!(
        "POST / HTTP/1.1\r\nHost: node\r\nAuthorization: Bearer {token}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
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

#[tokio::test]
async fn unauthorized_request_closes_the_connection() {
    let (api, _) = node(Pool::default());
    let (address, _stop) = listen(api, lane(Lane::Execution, 8)).await;
    let mut stream = TcpStream::connect(address).await.unwrap();
    let (status, head, _) = exchange_as(
        &mut stream,
        "wrong-token-value",
        &body("ops_policyStatus", json!([])),
    )
    .await;
    assert_eq!(status, 401, "{head}");
    assert!(head.contains("connection: close"), "{head}");
    assert!(
        closed(&mut stream).await,
        "a connection stayed open after a 401"
    );
}

#[tokio::test]
async fn silent_connection_is_closed_at_the_first_request_deadline() {
    let (api, _) = node(Pool::default());
    let config = ListenerConfig {
        first_request_time: Duration::from_millis(800),
        ..lane(Lane::Execution, 8)
    };
    let (address, _stop) = listen(api, config).await;
    let mut silent = TcpStream::connect(address).await.unwrap();
    let mut active = TcpStream::connect(address).await.unwrap();
    assert_eq!(
        exchange(&mut active, &body("ops_policyStatus", json!([])))
            .await
            .0,
        200
    );
    let started = Instant::now();
    assert!(
        closed(&mut silent).await,
        "a connection without a request stayed open"
    );
    assert!(
        started.elapsed() < Duration::from_millis(1800),
        "{:?}",
        started.elapsed()
    );
    // An authenticated connection is kept alive past the deadline.
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert_eq!(
        exchange(&mut active, &body("ops_policyStatus", json!([])))
            .await
            .0,
        200
    );
}

#[tokio::test]
async fn unauthenticated_connections_never_take_the_cap() {
    let (api, _) = node(Pool {
        delay: Duration::from_millis(1200),
    });
    let config = ListenerConfig {
        first_request_time: Duration::from_secs(10),
        ..lane(Lane::Execution, 2)
    };
    let (address, _stop) = listen(api, config).await;
    // More silent connections than the cap and the overflow together, and
    // peers that keep failing authentication.
    let mut silent = Vec::new();
    for _ in 0..(2 + 64 + 16) {
        silent.push(TcpStream::connect(address).await.unwrap());
    }
    for _ in 0..8 {
        let mut failing = TcpStream::connect(address).await.unwrap();
        let (status, _, _) = exchange_as(
            &mut failing,
            "wrong-token-value",
            &body("ops_policyStatus", json!([])),
        )
        .await;
        assert_eq!(status, 401);
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
    // Both slots of the cap are still free for authenticated submissions.
    let held: Vec<_> = ["tx-1", "tx-2"]
        .into_iter()
        .map(|context| tokio::spawn(send(address, submission(context, 7))))
        .collect();
    tokio::time::sleep(Duration::from_millis(200)).await;
    // And the overflow still answers: a third submission is refused 503 with
    // Retry-After (nothing ran), fact status is served.
    let (status, head, _) = send(address, submission("tx-3", 7)).await;
    assert_eq!(status, 503, "{head}");
    assert!(head.contains("retry-after: 1"), "{head}");
    let (status, head, answer) = send(address, body("ops_policyStatus", json!([]))).await;
    assert_eq!(status, 200, "{head}");
    assert_eq!(answer["result"]["version"], 7, "{answer}");
    for exchange in held {
        let (status, _, answer) = exchange.await.unwrap();
        assert_eq!(status, 200);
        assert_eq!(answer["result"]["status"], "accepted", "{answer}");
    }
    drop(silent);
}

#[tokio::test]
async fn authenticated_connection_beyond_the_overflow_is_answered_503() {
    let (api, _) = node(Pool::default());
    let (address, _stop) = listen(api, lane(Lane::Execution, 1)).await;
    // The cap and every overflow slot are held by authenticated connections.
    let mut held = Vec::new();
    let mut main = TcpStream::connect(address).await.unwrap();
    assert_eq!(
        exchange(&mut main, &body("ops_policyStatus", json!([])))
            .await
            .0,
        200
    );
    held.push(main);
    for _ in 0..64 {
        // An overflow connection answers status once, then closes; send only
        // the head so each one keeps its slot while its body is pending.
        let mut stream = TcpStream::connect(address).await.unwrap();
        let payload = body("ops_policyStatus", json!([]));
        let head = format!(
            "POST / HTTP/1.1\r\nHost: node\r\nAuthorization: Bearer {TOKEN}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
            payload.len()
        );
        stream.write_all(head.as_bytes()).await.unwrap();
        held.push(stream);
    }
    tokio::time::sleep(Duration::from_millis(200)).await;
    let mut beyond = TcpStream::connect(address).await.unwrap();
    let (status, head, _) = exchange(&mut beyond, &body("ops_policyStatus", json!([]))).await;
    assert_eq!(status, 503, "{head}");
    assert!(head.contains("retry-after: 1"), "{head}");
    assert!(head.contains("connection: close"), "{head}");
    assert!(closed(&mut beyond).await);
    drop(held);
}

#[tokio::test]
async fn timed_out_answer_on_an_overflow_connection_has_no_retry_after() {
    let storage = MemoryStorage::new();
    let (api, _) = node_on(Pool::default(), storage.clone());
    let config = ListenerConfig {
        request_time: Duration::from_millis(300),
        ..lane(Lane::Execution, 1)
    };
    let (address, _stop) = listen(api, config).await;
    // The cap is held by an authenticated, idle connection.
    let mut main = TcpStream::connect(address).await.unwrap();
    assert_eq!(
        exchange(&mut main, &body("ops_policyStatus", json!([])))
            .await
            .0,
        200
    );
    // Fact publication over the cap is served, but its record write is held
    // past the processing bound: the answer is 503 and may have run.
    let gate = common::Gate::new();
    storage.set_hook({
        let gate = gate.clone();
        move |op, _| {
            if op == common::Op::Write {
                gate.pass();
            }
            common::Action::Proceed
        }
    });
    let (status, head, _) = send(
        address,
        body("ops_policyApply", json!([snapshot_at(8, 1010)])),
    )
    .await;
    gate.open();
    storage.clear_hook();
    assert_eq!(status, 503, "{head}");
    assert!(
        !head.contains("retry-after"),
        "a timed-out request may have run: {head}"
    );
    drop(main);
}

/// Send a request whose body arrives in `chunks` writes 50 ms apart, then
/// read the answer: every write must succeed (the node reads the body before
/// answering and closing, so the client never hits a reset mid-request).
async fn slow_exchange(
    stream: &mut TcpStream,
    token: &str,
    payload: &[u8],
    chunks: usize,
) -> (u16, String) {
    let head = format!(
        "POST / HTTP/1.1\r\nHost: node\r\nAuthorization: Bearer {token}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
        payload.len()
    );
    stream.write_all(head.as_bytes()).await.unwrap();
    for chunk in payload.chunks(payload.len().div_ceil(chunks)) {
        tokio::time::sleep(Duration::from_millis(50)).await;
        stream
            .write_all(chunk)
            .await
            .expect("the node closed the connection before reading the request body");
    }
    let mut buffer = Vec::new();
    stream.read_to_end(&mut buffer).await.unwrap();
    let head = String::from_utf8_lossy(&buffer).to_lowercase();
    (head[9..12].parse().unwrap(), head)
}

/// A request body of `bytes` bytes (JSON padding inside the id).
fn padded(bytes: usize) -> Vec<u8> {
    body("ops_policyStatus", json!([]))
        .into_iter()
        .chain(std::iter::repeat_n(b' ', bytes))
        .collect()
}

#[tokio::test]
async fn refusals_before_admission_read_the_body_first() {
    let (api, _) = node(Pool::default());
    let (address, _stop) = listen(api, lane(Lane::Execution, 1)).await;
    // A wrong token with a body still arriving: answered 401 after the body.
    let mut stream = TcpStream::connect(address).await.unwrap();
    let (status, head) =
        slow_exchange(&mut stream, "wrong-token-value", &padded(32 << 10), 4).await;
    assert_eq!(status, 401, "{head}");
    // Beyond the cap and the overflow: the 503 (nothing ran) also follows
    // the body.
    let mut held = Vec::new();
    let mut main = TcpStream::connect(address).await.unwrap();
    assert_eq!(
        exchange(&mut main, &body("ops_policyStatus", json!([])))
            .await
            .0,
        200
    );
    held.push(main);
    for _ in 0..64 {
        let mut stream = TcpStream::connect(address).await.unwrap();
        let payload = body("ops_policyStatus", json!([]));
        let head = format!(
            "POST / HTTP/1.1\r\nHost: node\r\nAuthorization: Bearer {TOKEN}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
            payload.len()
        );
        stream.write_all(head.as_bytes()).await.unwrap();
        held.push(stream);
    }
    tokio::time::sleep(Duration::from_millis(200)).await;
    let mut beyond = TcpStream::connect(address).await.unwrap();
    let (status, head) = slow_exchange(&mut beyond, TOKEN, &padded(32 << 10), 4).await;
    assert_eq!(status, 503, "{head}");
    assert!(head.contains("retry-after: 1"), "{head}");
    drop(held);
}

#[tokio::test]
async fn evicting_unauthenticated_connections_never_cuts_an_admitted_one() {
    let (api, _) = node(Pool {
        delay: Duration::from_millis(1500),
    });
    let (address, _stop) = listen(api, lane(Lane::Execution, 2)).await;
    // An idle admitted keep-alive connection and a submission in flight.
    let mut idle = TcpStream::connect(address).await.unwrap();
    assert_eq!(
        exchange(&mut idle, &body("ops_policyStatus", json!([])))
            .await
            .0,
        200
    );
    let in_flight = tokio::spawn(send(address, submission("tx-1", 7)));
    tokio::time::sleep(Duration::from_millis(200)).await;
    // More silent connections than may wait (the cap plus 64): the oldest
    // waiting ones are closed, the admitted ones never.
    let mut silent = Vec::new();
    for _ in 0..(2 + 64 + 10) {
        silent.push(TcpStream::connect(address).await.unwrap());
    }
    assert!(
        closed(&mut silent[0]).await,
        "the oldest waiting connection was kept beyond the bound"
    );
    let (status, _, answer) = in_flight.await.unwrap();
    assert_eq!(status, 200);
    assert_eq!(answer["result"]["status"], "accepted", "{answer}");
    assert_eq!(
        exchange(&mut idle, &body("ops_policyStatus", json!([])))
            .await
            .0,
        200,
        "an admitted keep-alive connection was closed"
    );
    drop(silent);
}
