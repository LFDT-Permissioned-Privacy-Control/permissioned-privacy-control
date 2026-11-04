//! The public RPC guard (independent review, finding 1): Reth's own public
//! server stack with the guard as its RPC middleware refuses every method
//! that replays blocks through the guarded executor, over HTTP and WS, alone
//! and inside batches, as calls or notifications, before the method runs;
//! every other method runs. At startup an unreviewed public method refuses
//! the node.
#![cfg(feature = "reth-sdk")]

use jsonrpsee::{
    RpcModule,
    core::{
        client::{BatchResponse, ClientT},
        params::{ArrayParams, BatchRequestBuilder},
    },
    server::ServerConfig,
    ws_client::WsClientBuilder,
};
use ops_reth_policy::public_rpc::{
    REFUSED_CODE, REFUSED_MESSAGE, REFUSED_METHODS, REVIEWED_METHODS, RefuseReplayLayer,
    guard_configured,
};
use reth_ethereum::rpc::builder::{RpcServerConfig, RpcServerHandle, TransportRpcModules};
use serde_json::{Value, json};
use std::{
    net::SocketAddr,
    sync::{Arc, Mutex},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

/// Ordinary public methods, which must keep running.
const ORDINARY: [&str; 3] = [
    "eth_getBlockByNumber",
    "eth_getTransactionReceipt",
    "eth_call",
];

type Calls = Arc<Mutex<Vec<&'static str>>>;

/// A module answering every refused and ordinary name, recording each run.
fn module(calls: &Calls) -> RpcModule<()> {
    let mut module = RpcModule::new(());
    for name in REFUSED_METHODS.into_iter().chain(ORDINARY) {
        let calls = calls.clone();
        module
            .register_method(name, move |_, _, _| {
                calls.lock().unwrap().push(name);
                "ran"
            })
            .unwrap();
    }
    module
}

/// Reth's public server with the guard: HTTP and WS on separate servers, or
/// both on one port.
async fn start(calls: &Calls, same_port: bool) -> (Vec<RpcServerHandle>, SocketAddr, SocketAddr) {
    let modules = TransportRpcModules::default()
        .with_http(module(calls))
        .with_ws(module(calls));
    let local: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let configs = if same_port {
        vec![
            RpcServerConfig::http(ServerConfig::builder())
                .with_ws(ServerConfig::builder())
                .with_http_address(local)
                .with_ws_address(local),
        ]
    } else {
        vec![
            RpcServerConfig::http(ServerConfig::builder()).with_http_address(local),
            RpcServerConfig::ws(ServerConfig::builder()).with_ws_address(local),
        ]
    };
    let mut handles = Vec::new();
    for config in configs {
        handles.push(
            config
                .set_rpc_middleware(RefuseReplayLayer)
                .start(&modules)
                .await
                .unwrap(),
        );
    }
    let http = handles.iter().find_map(|h| h.http_local_addr()).unwrap();
    let ws = handles.iter().find_map(|h| h.ws_local_addr()).unwrap();
    (handles, http, ws)
}

/// One HTTP POST: the response body as JSON.
async fn post(address: SocketAddr, body: &Value) -> Value {
    serde_json::from_slice(&post_raw(address, body).await).unwrap()
}

/// One HTTP POST: the response body.
async fn post_raw(address: SocketAddr, body: &Value) -> Vec<u8> {
    let body = serde_json::to_vec(body).unwrap();
    let mut stream = TcpStream::connect(address).await.unwrap();
    let head = format!(
        "POST / HTTP/1.1\r\nHost: node\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes()).await.unwrap();
    stream.write_all(&body).await.unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.unwrap();
    let start = response
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("an HTTP response")
        + 4;
    response[start..].to_vec()
}

fn request(id: usize, method: &str) -> Value {
    json!({"jsonrpc":"2.0","id":id,"method":method,"params":[]})
}

fn assert_refused(answer: &Value, method: &str) {
    assert_eq!(answer["error"]["code"], REFUSED_CODE, "{method}: {answer}");
    assert_eq!(
        answer["error"]["message"], REFUSED_MESSAGE,
        "{method}: {answer}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn refused_methods_never_run_over_http() {
    for same_port in [false, true] {
        let calls = Calls::default();
        let (_handle, http, _) = start(&calls, same_port).await;
        for (id, method) in REFUSED_METHODS.into_iter().enumerate() {
            assert_refused(&post(http, &request(id, method)).await, method);
        }
        for (id, method) in ORDINARY.into_iter().enumerate() {
            assert_eq!(
                post(http, &request(id, method)).await["result"],
                "ran",
                "{method}"
            );
        }
        // A batch mixing both: each refused entry answered with the refusal
        // in place, the others run.
        let batch: Vec<Value> = REFUSED_METHODS
            .into_iter()
            .zip(ORDINARY.into_iter().cycle())
            .flat_map(|(refused, ordinary)| [refused, ordinary])
            .enumerate()
            .map(|(id, method)| request(id, method))
            .collect();
        let answers = post(http, &Value::Array(batch.clone())).await;
        let answers = answers.as_array().expect("a batch answer");
        assert_eq!(answers.len(), batch.len());
        for sent in &batch {
            let answer = answers
                .iter()
                .find(|answer| answer["id"] == sent["id"])
                .expect("every entry answered");
            let method = sent["method"].as_str().unwrap();
            if REFUSED_METHODS.contains(&method) {
                assert_refused(answer, method);
            } else {
                assert_eq!(answer["result"], "ran", "{method}");
            }
        }
        let ran = calls.lock().unwrap().clone();
        assert!(
            ran.iter().all(|method| ORDINARY.contains(method)),
            "a refused method ran (same port: {same_port}): {ran:?}"
        );
        assert_eq!(ran.len(), ORDINARY.len() + REFUSED_METHODS.len());
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn refused_methods_never_run_over_ws() {
    for same_port in [false, true] {
        let calls = Calls::default();
        let (_handle, _, ws) = start(&calls, same_port).await;
        let client = WsClientBuilder::default()
            .build(format!("ws://{ws}"))
            .await
            .unwrap();
        for method in REFUSED_METHODS {
            let error = client
                .request::<String, _>(method, ArrayParams::new())
                .await
                .unwrap_err();
            match error {
                jsonrpsee::core::client::Error::Call(error) => {
                    assert_eq!(error.code(), REFUSED_CODE, "{method}");
                    assert_eq!(error.message(), REFUSED_MESSAGE, "{method}");
                }
                other => panic!("{method}: {other}"),
            }
        }
        for method in ORDINARY {
            let answer: String = client.request(method, ArrayParams::new()).await.unwrap();
            assert_eq!(answer, "ran", "{method}");
        }
        let mut batch = BatchRequestBuilder::new();
        for (refused, ordinary) in REFUSED_METHODS
            .into_iter()
            .zip(ORDINARY.into_iter().cycle())
        {
            batch.insert(refused, ArrayParams::new()).unwrap();
            batch.insert(ordinary, ArrayParams::new()).unwrap();
        }
        let answers: BatchResponse<String> = client.batch_request(batch).await.unwrap();
        for (index, answer) in answers.into_iter().enumerate() {
            match answer {
                Ok(ran) if index % 2 == 1 => assert_eq!(ran, "ran"),
                Err(error) if index % 2 == 0 => {
                    assert_eq!(error.code(), REFUSED_CODE);
                    assert_eq!(error.message(), REFUSED_MESSAGE);
                }
                other => panic!("entry {index}: {other:?}"),
            }
        }
        let ran = calls.lock().unwrap().clone();
        assert!(
            ran.iter().all(|method| ORDINARY.contains(method)),
            "a refused method ran over WS (same port: {same_port}): {ran:?}"
        );
    }
}

/// A request without an id: no answer (an empty or `null` body), or the
/// refusal; either way a refused one never runs.
fn refusals_or_nothing(body: &[u8], method: &str) {
    if body.is_empty() {
        return;
    }
    let answer: Value = serde_json::from_slice(body).unwrap();
    if answer.is_null() {
        return;
    }
    for answer in answer.as_array().cloned().unwrap_or_else(|| vec![answer]) {
        assert_refused(&answer, method);
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn refused_notifications_never_run() {
    let calls = Calls::default();
    let (_handles, http, _) = start(&calls, false).await;
    let notification = |method: &str| json!({"jsonrpc":"2.0","method":method,"params":[]});
    for method in REFUSED_METHODS {
        refusals_or_nothing(&post_raw(http, &notification(method)).await, method);
        let batch = json!([notification(method), notification(method)]);
        refusals_or_nothing(&post_raw(http, &batch).await, method);
        // Beside a call: the call runs.
        let batch = json!([notification(method), request(1, ORDINARY[0])]);
        let answers = post(http, &batch).await;
        let answers = answers.as_array().expect("a batch answer");
        assert!(
            answers.iter().any(|answer| answer["result"] == "ran"),
            "{answers:?}"
        );
        for answer in answers.iter().filter(|answer| answer["result"] != "ran") {
            assert_refused(answer, method);
        }
    }
    let ran = calls.lock().unwrap().clone();
    assert_eq!(ran, vec![ORDINARY[0]; REFUSED_METHODS.len()], "{ran:?}");
}

#[test]
fn startup_guard_refuses_unreviewed_methods_and_removes_refused_ones() {
    let calls = Calls::default();
    let mut extra = module(&calls);
    extra
        .register_method("eth_someFutureMethod", |_, _, _| "ran")
        .unwrap();
    let mut modules = TransportRpcModules::default()
        .with_http(extra)
        .with_ws(module(&calls));
    let error = guard_configured(&mut modules).unwrap_err();
    assert!(error.contains("eth_someFutureMethod"), "{error}");
    let mut modules = TransportRpcModules::default()
        .with_http(module(&calls))
        .with_ws(module(&calls));
    guard_configured(&mut modules).unwrap();
    for methods in [
        modules.http_methods(|_| true).unwrap(),
        modules.ws_methods(|_| true).unwrap(),
    ] {
        let served: Vec<&str> = methods.method_names().collect();
        assert!(
            served
                .iter()
                .all(|method| !REFUSED_METHODS.contains(method)),
            "{served:?}"
        );
        assert!(ORDINARY.iter().all(|method| served.contains(method)));
    }
}

#[test]
fn reviewed_and_refused_methods_are_disjoint() {
    for method in REFUSED_METHODS {
        assert!(!REVIEWED_METHODS.contains(&method), "{method}");
    }
    for method in ORDINARY {
        assert!(REVIEWED_METHODS.contains(&method), "{method}");
    }
}
