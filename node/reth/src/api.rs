//! Authenticated private listener. This module never registers an `ops_*`
//! method on Reth's public RPC server.

use crate::{
    context::ExecutionBinding,
    identity::IdentityRegistry,
    runtime::PolicyRuntime,
    wire::{Identity, MAX_ENVELOPE_BYTES, SimulationRequest, decode_strict, parse_simulation},
};
use alloy_consensus::{Transaction, TxEnvelope, transaction::SignerRecoverable};
use alloy_eips::eip2718::Decodable2718;
use alloy_primitives::{B256, Bytes, hex};
use async_trait::async_trait;
use base64::{Engine, engine::general_purpose::STANDARD};
use http_body_util::{BodyExt, Full, Limited};
use hyper::{
    Request, Response, StatusCode, body::Incoming, server::conn::http1, service::service_fn,
};
use hyper_util::rt::{TokioIo, TokioTimer};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{convert::Infallible, future::Future, io, sync::Arc, time::Duration};
use subtle::ConstantTimeEq;
use tokio::{net::TcpListener, sync::Semaphore, task::JoinSet};

const MAX_REQUEST_BYTES: usize = MAX_ENVELOPE_BYTES + 4096;
/// Request bodies parsed on the async worker; larger ones are parsed on a
/// blocking thread.
const INLINE_PARSE_BYTES: usize = 64 << 10;
/// Raw transactions accepted, in hex characters after `0x`.
const MAX_RAW_TRANSACTION_HEX: usize = 16 << 20;
/// Default concurrent CPU-pool jobs.
pub const DEFAULT_CPU_WORKERS: usize = 4;
const REQUIRED_CAPABILITIES: [&str; 8] = [
    "per_frame_a5",
    "signed_identity_v1",
    "fact_stream_v1",
    "simulation_v1",
    "archive_v1",
    "candidate_simulation_v1",
    "scoped_diagnostics_v1",
    "finalized_status_v1",
];

#[async_trait]
pub trait ExecutionBackend: Send + Sync {
    /// Advertise a capability only after its production path is wired.
    fn capabilities(&self) -> Vec<String>;
    async fn submit(&self, identity: Identity, raw: Bytes) -> Result<B256, String>;
    async fn transaction_status(&self, _hash: B256) -> Result<Value, String> {
        Err("transaction status is unavailable".into())
    }
    async fn simulate(
        &self,
        identity: Identity,
        request: SimulationRequest,
        exact: Bytes,
    ) -> Result<Value, String>;
}

pub struct PrivateApi {
    runtime: Arc<PolicyRuntime>,
    backend: Arc<dyn ExecutionBackend>,
    bearer: Vec<u8>,
    clock: Arc<dyn Fn() -> i64 + Send + Sync>,
    cpu: CpuPool,
}

type Job = Box<dyn FnOnce() + Send>;

/// Bounded pool for the private API's admission work (identity
/// serialization and signature verification, raw-transaction decoding, signer
/// recovery, registry admission), so none of it runs on an async worker. Fact
/// ingestion and status lookups have their own blocking lanes and never queue
/// here. Reth's own pool insertion (`send_raw_transaction`) still decodes and
/// recovers the signer once more on its RPC path.
#[derive(Clone)]
pub struct CpuPool {
    permits: Arc<Semaphore>,
    spawn: Arc<dyn Fn(Job) + Send + Sync>,
}

impl CpuPool {
    /// `workers` concurrent jobs on Tokio's blocking threads.
    pub fn new(workers: usize) -> Self {
        Self::with_spawner(workers, |job| {
            tokio::task::spawn_blocking(job);
        })
    }

    /// The same bound with a custom spawner (tests hold jobs on a gate).
    pub fn with_spawner(workers: usize, spawn: impl Fn(Job) + Send + Sync + 'static) -> Self {
        Self {
            permits: Arc::new(Semaphore::new(workers.max(1))),
            spawn: Arc::new(spawn),
        }
    }

    /// Run `job` off the async workers. If the caller is cancelled meanwhile,
    /// the job still completes and its undelivered result is dropped.
    pub async fn run<T: Send + 'static>(
        &self,
        job: impl FnOnce() -> T + Send + 'static,
    ) -> Result<T, String> {
        let permit = self
            .permits
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| "verification pool unavailable")?;
        let (sender, receiver) = tokio::sync::oneshot::channel();
        (self.spawn)(Box::new(move || {
            let _permit = permit;
            let _ = sender.send(job());
        }));
        receiver
            .await
            .map_err(|_| "verification pool unavailable".into())
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RpcRequest {
    jsonrpc: String,
    id: String,
    method: String,
    params: Vec<Value>,
}

pub struct ApiResponse {
    pub status: u16,
    pub body: Vec<u8>,
}

/// Simulations have no pending-pool lifecycle. Release their capacity even if
/// the backend errors or the HTTP task is cancelled while awaiting execution.
struct SimulationRegistration {
    identities: Arc<IdentityRegistry>,
    binding: ExecutionBinding,
}

impl Drop for SimulationRegistration {
    fn drop(&mut self) {
        let _ = self.identities.finish(&self.binding);
    }
}

impl PrivateApi {
    pub fn new(
        runtime: Arc<PolicyRuntime>,
        backend: Arc<dyn ExecutionBackend>,
        bearer: String,
        clock: Arc<dyn Fn() -> i64 + Send + Sync>,
    ) -> Result<Self, String> {
        if bearer.len() < 16
            || bearer
                .bytes()
                .any(|c| c.is_ascii_whitespace() || c.is_ascii_control())
        {
            return Err("private RPC requires a service credential of at least 16 bytes".into());
        }
        Ok(Self {
            runtime,
            backend,
            bearer: format!("Bearer {bearer}").into_bytes(),
            clock,
            cpu: CpuPool::new(DEFAULT_CPU_WORKERS),
        })
    }

    /// Replace the CPU pool (sizing, or a test spawner).
    pub fn with_cpu_pool(mut self, cpu: CpuPool) -> Self {
        self.cpu = cpu;
        self
    }

    fn authenticated(&self, authorization: &str) -> bool {
        bool::from(authorization.as_bytes().ct_eq(&self.bearer))
    }

    pub async fn process(&self, authorization: &str, body: &[u8]) -> ApiResponse {
        if !self.authenticated(authorization) {
            return ApiResponse {
                status: 401,
                body: br#"{"error":"unauthorized"}"#.to_vec(),
            };
        }
        if body.len() > MAX_REQUEST_BYTES {
            return ApiResponse {
                status: 413,
                body: br#"{"error":"request too large"}"#.to_vec(),
            };
        }
        // Large bodies (fact snapshots) are parsed off the async worker.
        let parsed = if body.len() > INLINE_PARSE_BYTES {
            let body = body.to_vec();
            tokio::task::spawn_blocking(move || decode_strict::<RpcRequest>(&body))
                .await
                .unwrap_or_else(|_| Err("invalid private request".into()))
        } else {
            decode_strict(body)
        };
        let request: RpcRequest = match parsed {
            Ok(request) => request,
            Err(_) => return rpc_error(Value::Null, -32600, "invalid private request"),
        };
        if request.jsonrpc != "2.0" || request.id.is_empty() || request.id.len() > 128 {
            return rpc_error(Value::Null, -32600, "invalid private request");
        }
        let id = json!(request.id);
        match self.dispatch(request, (self.clock)()).await {
            Ok(result) => ApiResponse {
                status: 200,
                body: serde_json::to_vec(&json!({"jsonrpc":"2.0","id":id,"result":result}))
                    .expect("serializable RPC result"),
            },
            Err(error) if error.starts_with("resynchronisation required") => {
                rpc_error(id, -32011, "policy resynchronisation required")
            }
            Err(_) => rpc_error(id, -32000, "private execution request rejected"),
        }
    }

    async fn dispatch(&self, mut request: RpcRequest, now: i64) -> Result<Value, String> {
        match request.method.as_str() {
            "ops_policyStatus" => {
                require_count(&request.params, 0)?;
                let latest = self.runtime.feed.latest()?;
                let mut capabilities = self.backend.capabilities();
                capabilities.sort();
                capabilities.dedup();
                let complete = REQUIRED_CAPABILITIES
                    .iter()
                    .all(|required| capabilities.iter().any(|value| value == required));
                let fresh = self.runtime.feed.pin(now, 1).is_ok();
                let (version, digest, expires) = latest
                    .as_ref()
                    .map(|facts| {
                        (
                            facts.version(),
                            hex::encode(facts.digest()),
                            facts.expires_at(),
                        )
                    })
                    .unwrap_or((0, String::new(), 0));
                Ok(
                    json!({"protocol_version":1,"network":self.runtime.network(),"capabilities":capabilities,"version":version,"digest":digest,"expires_at":expires,"ready":fresh&&complete,"reason":if !complete{"runtime_incomplete"}else if !fresh{"facts_unavailable"}else{""}}),
                )
            }
            "ops_policyApply" => {
                require_count(&request.params, 1)?;
                let kind = request.params[0]
                    .get("kind")
                    .and_then(Value::as_str)
                    .ok_or("missing policy kind")?
                    .to_owned();
                if !matches!(kind.as_str(), "snapshot" | "delta" | "heartbeat") {
                    return Err("invalid policy kind".into());
                }
                let envelope = request.params.pop().ok_or("invalid policy envelope")?;
                // Fact ingestion has its own blocking lane: it never queues
                // behind identity verification in the CPU pool.
                let runtime = self.runtime.clone();
                let facts = tokio::task::spawn_blocking(move || {
                    let wire =
                        serde_json::to_vec(&envelope).map_err(|_| "invalid policy envelope")?;
                    runtime.accept_facts(&kind, &wire, now)
                })
                .await
                .map_err(|_| "policy ingestion unavailable")??;
                Ok(
                    json!({"version":facts.version(),"digest":hex::encode(facts.digest()),"expires_at":facts.expires_at()}),
                )
            }
            "ops_transactionStatus" => {
                require_count(&request.params, 1)?;
                let hash = request.params[0]
                    .as_str()
                    .ok_or("invalid transaction hash")?
                    .parse::<B256>()
                    .map_err(|_| "invalid transaction hash")?;
                // Expiry limits execution authority, not later status access on
                // this authenticated service listener. The identity comes from
                // the including block's manifest, or else the live registry; an
                // unknown hash is an error and discloses nothing.
                let execution = self.backend.transaction_status(hash).await?;
                let block = match execution.get("status").and_then(Value::as_str) {
                    Some("included" | "reverted") => Some((
                        execution
                            .get("block_number")
                            .and_then(Value::as_u64)
                            .ok_or("invalid execution status")?,
                        execution
                            .get("block_hash")
                            .and_then(Value::as_str)
                            .and_then(|block| block.parse::<B256>().ok())
                            .ok_or("invalid execution status")?,
                    )),
                    _ => None,
                };
                let runtime = self.runtime.clone();
                // Status has its own blocking lane: archive reads never hold
                // the admission pool's permits.
                let identity =
                    tokio::task::spawn_blocking(move || runtime.status_identity(hash, block))
                        .await
                        .map_err(|_| "status lookup failed")??;
                Ok(
                    json!({"transaction_hash":format!("{hash:#x}"),"principal_id":identity.principal_id,
                    "org_id":identity.org_id,"context_id":identity.context_id,"execution":execution}),
                )
            }
            "ops_submitTransaction" => {
                require_count(&request.params, 2)?;
                let Some(Value::String(raw)) = request.params.pop() else {
                    return Err("invalid raw transaction".into());
                };
                if raw.len() > MAX_RAW_TRANSACTION_HEX + 2 {
                    return Err("raw transaction too large".into());
                }
                let identity = request.params.pop().ok_or("invalid identity envelope")?;
                let (runtime, clock) = (self.runtime.clone(), self.clock.clone());
                // Verification, decoding, signer recovery and admission are CPU
                // work: one pool job, with the clock read when it runs.
                let (identity, raw, hash, context_id) = self
                    .cpu
                    .run(move || admit_transaction(&runtime, &identity, &raw, clock()))
                    .await??;
                let accepted = self.backend.submit(identity, raw.into()).await?;
                if accepted != hash {
                    return Err("transaction pool returned a different hash".into());
                }
                Ok(
                    json!({"transaction_hash":format!("{hash:#x}"),"context_id":context_id,"status":"accepted"}),
                )
            }
            "ops_simulate" => {
                require_count(&request.params, 2)?;
                let Some(Value::String(encoded)) = request.params.pop() else {
                    return Err("invalid simulation encoding".into());
                };
                let identity = request.params.pop().ok_or("invalid identity envelope")?;
                let (runtime, clock) = (self.runtime.clone(), self.clock.clone());
                // The registration is created inside the job, so a request
                // cancelled while the job runs still releases its slot: the
                // undelivered result is dropped with it.
                let (identity, request, exact, _registration) = self
                    .cpu
                    .run(move || admit_simulation(&runtime, &identity, &encoded, clock()))
                    .await??;
                self.backend.simulate(identity, request, exact.into()).await
            }
            _ => Err("unknown private method".into()),
        }
    }
}

type AdmittedTransaction = (Identity, Vec<u8>, B256, String);

/// Pool job: verify the identity once, decode the raw transaction, recover its
/// signer, check the binding and facts, then register the identity.
fn admit_transaction(
    runtime: &PolicyRuntime,
    identity: &Value,
    raw: &str,
    now: i64,
) -> Result<AdmittedTransaction, String> {
    let wire = serde_json::to_vec(identity).map_err(|_| "invalid identity envelope")?;
    let verified = runtime.verifier().verify_identity(&wire, now)?;
    let identity = verified.identity();
    if identity.scope != "transaction" {
        return Err("invalid identity scope".into());
    }
    let raw = raw.strip_prefix("0x").ok_or("invalid raw transaction")?;
    if raw.len() > MAX_RAW_TRANSACTION_HEX {
        return Err("raw transaction too large".into());
    }
    let raw = hex::decode(raw).map_err(|_| "invalid raw transaction")?;
    let mut remaining = raw.as_slice();
    let tx = TxEnvelope::decode_2718(&mut remaining).map_err(|_| "invalid signed transaction")?;
    if !remaining.is_empty()
        || tx.chain_id() != Some(runtime.network().chain_id)
        || matches!(tx, TxEnvelope::Eip7702(_))
    {
        return Err("unsupported transaction envelope".into());
    }
    let recovered = tx
        .recover_signer()
        .map_err(|_| "invalid transaction signature")?;
    // Blob sidecars wrap the consensus envelope and are validated by the pool.
    // Their bytes are not part of the transaction hash.
    let hash = *tx.tx_hash();
    if identity.binding_hash != format!("{hash:#x}") || identity.signer != format!("{recovered:#x}")
    {
        return Err("transaction identity mismatch".into());
    }
    runtime.feed.pin(now, identity.min_snapshot_version)?;
    let context_id = identity.context_id.clone();
    // The identity is registered before pool insertion, so a pooled
    // transaction never runs without it. An ambiguous pool result keeps the
    // registration; rebinding is refused by OPS's durable submission row, saved
    // before transport. A request cancelled after this point
    // leaves an identity without a pooled transaction: harmless, it expires.
    let identity = runtime.admit_identity(verified, now)?;
    Ok((identity, raw, hash, context_id))
}

type AdmittedSimulation = (Identity, SimulationRequest, Vec<u8>, SimulationRegistration);

/// Pool job for a signed simulation; the returned registration owns the slot.
fn admit_simulation(
    runtime: &PolicyRuntime,
    identity: &Value,
    encoded: &str,
    now: i64,
) -> Result<AdmittedSimulation, String> {
    let wire = serde_json::to_vec(identity).map_err(|_| "invalid identity envelope")?;
    let verified = runtime.verifier().verify_identity(&wire, now)?;
    let identity = verified.identity();
    if identity.scope != "simulation" {
        return Err("invalid identity scope".into());
    }
    let exact = STANDARD
        .decode(encoded)
        .map_err(|_| "invalid simulation encoding")?;
    if STANDARD.encode(&exact) != encoded {
        return Err("noncanonical simulation encoding".into());
    }
    let digest = identity
        .binding_hash
        .parse::<B256>()
        .map_err(|_| "invalid simulation hash")?;
    let request = parse_simulation(&exact, digest.as_ref())?;
    if request.params[0].get("from").and_then(Value::as_str) != Some(identity.signer.as_str()) {
        return Err("simulation signer mismatch".into());
    }
    runtime.feed.pin(now, identity.min_snapshot_version)?;
    let identity = runtime.admit_identity(verified, now)?;
    let registration = SimulationRegistration {
        identities: runtime.identities.clone(),
        binding: ExecutionBinding::Simulation {
            context_id: identity.context_id.clone(),
            digest,
        },
    };
    Ok((identity, request, exact, registration))
}

fn require_count(params: &[Value], count: usize) -> Result<(), String> {
    if params.len() != count {
        return Err("invalid private parameters".into());
    }
    Ok(())
}
fn rpc_error(id: Value, code: i32, message: &str) -> ApiResponse {
    ApiResponse {
        status: 200,
        body: serde_json::to_vec(
            &json!({"jsonrpc":"2.0","id":id,"error":{"code":code,"message":message}}),
        )
        .expect("serializable RPC error"),
    }
}

/// Dedicated private HTTP listener with bounded bodies, connections and time.
/// Shutdown stops acceptance and drains existing requests for at most 10 sec.
pub async fn serve(
    listener: TcpListener,
    api: Arc<PrivateApi>,
    shutdown: impl Future<Output = ()> + Send,
) -> io::Result<()> {
    let limit = Arc::new(Semaphore::new(128));
    let mut requests = JoinSet::new();
    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            _=&mut shutdown=>break,
            Some(_)=requests.join_next(),if !requests.is_empty()=>{},
            incoming=listener.accept()=>{
                let (stream,_)=incoming?;
                let Ok(permit)=limit.clone().try_acquire_owned() else {drop(stream);continue;};
                let api=api.clone();
                requests.spawn(async move {
                    let _permit=permit;
                    let service=service_fn(move |req|handle_http(api.clone(),req));
                    let mut builder=http1::Builder::new();
                    builder.timer(TokioTimer::new()).header_read_timeout(Duration::from_secs(10));
                    let connection=builder.serve_connection(TokioIo::new(stream),service);
                    let _=tokio::time::timeout(Duration::from_secs(60),connection).await;
                });
            }
        }
    }
    let drained = async { while requests.join_next().await.is_some() {} };
    if tokio::time::timeout(Duration::from_secs(10), drained)
        .await
        .is_err()
    {
        requests.abort_all();
    }
    Ok(())
}
async fn handle_http(
    api: Arc<PrivateApi>,
    request: Request<Incoming>,
) -> Result<Response<Full<bytes::Bytes>>, Infallible> {
    let authorization = request
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let response = if !api.authenticated(&authorization) {
        ApiResponse {
            status: 401,
            body: br#"{"error":"unauthorized"}"#.to_vec(),
        }
    } else if request.method() != hyper::Method::POST
        || request.uri().path() != "/"
        || request.uri().query().is_some()
    {
        ApiResponse {
            status: 404,
            body: br#"{"error":"not found"}"#.to_vec(),
        }
    } else {
        match tokio::time::timeout(
            Duration::from_secs(15),
            Limited::new(request.into_body(), MAX_REQUEST_BYTES).collect(),
        )
        .await
        {
            Ok(Ok(body)) => match tokio::time::timeout(
                Duration::from_secs(30),
                api.process(&authorization, &body.to_bytes()),
            )
            .await
            {
                Ok(response) => response,
                Err(_) => ApiResponse {
                    status: 503,
                    body: br#"{"error":"execution node unavailable"}"#.to_vec(),
                },
            },
            _ => ApiResponse {
                status: 413,
                body: br#"{"error":"invalid request body"}"#.to_vec(),
            },
        }
    };
    let mut result = Response::new(Full::new(bytes::Bytes::from(response.body)));
    *result.status_mut() =
        StatusCode::from_u16(response.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    result.headers_mut().insert(
        "content-type",
        hyper::header::HeaderValue::from_static("application/json"),
    );
    result.headers_mut().insert(
        "cache-control",
        hyper::header::HeaderValue::from_static("no-store"),
    );
    Ok(result)
}
