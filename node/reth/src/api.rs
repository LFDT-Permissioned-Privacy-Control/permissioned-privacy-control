//! Authenticated private listener. This module never registers an `ops_*`
//! method on Reth's public RPC server.

use crate::{
    context::ExecutionBinding,
    identity::{Admission, IdentityRegistry},
    runtime::{BatchedAnswer, MAX_STATUS_BATCH, PolicyRuntime, StatusBatch, TRANSACTION_NOT_FOUND},
    wire::{Identity, MAX_ENVELOPE_BYTES, SimulationRequest, decode_strict, parse_simulation},
};
use alloy_consensus::{Transaction, TxEnvelope, transaction::SignerRecoverable};
use alloy_eips::eip2718::Decodable2718;
use alloy_primitives::{Address, B256, Bytes, hex};
use async_trait::async_trait;
use base64::{Engine, engine::general_purpose::STANDARD};
use http_body_util::{BodyExt, Full, Limited};
use hyper::{
    Request, Response, StatusCode, body::Incoming, server::conn::http1, service::service_fn,
};
use hyper_util::rt::{TokioIo, TokioTimer};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    convert::Infallible,
    future::Future,
    io,
    net::IpAddr,
    sync::{Arc, PoisonError},
    time::{Duration, Instant},
};
use subtle::ConstantTimeEq;
use tokio::{
    net::TcpListener,
    sync::{OwnedSemaphorePermit, Semaphore, oneshot},
    task::JoinSet,
};

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

/// Capabilities the private API itself implements, advertised with the
/// backend's (`fact_wait_v1` only while a fact wait is configured).
const API_CAPABILITIES: [&str; 1] = ["boot_id_v1"];
const FACT_WAIT_CAPABILITY: &str = "fact_wait_v1";
/// Default and largest bounded wait for a request's fact floor.
pub const DEFAULT_FACT_WAIT: Duration = Duration::from_secs(1);
pub const MAX_FACT_WAIT: Duration = Duration::from_secs(5);
/// Requests waiting for facts at once by default: each holds a connection,
/// so waiters alone can never fill the listener and block the publication
/// they wait for.
pub const DEFAULT_FACT_WAITERS: usize = 32;
/// Status calls (single and batched together) worked on at once; more wait
/// (holding only their connection). Loading a block's evidence verifies
/// every identity in it.
const STATUS_JOBS: usize = 4;

/// What the transaction pool did with a submitted transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PoolSubmission {
    /// Inserted under this hash.
    Inserted(B256),
    /// The pool already holds a transaction with the submitted hash, for
    /// example one restored from the pool's backup after a restart.
    AlreadyKnown,
    /// The pool refused it because its nonce is used, and the chain holds this
    /// transaction's own canonical receipt: it is already included. Like
    /// "already known", a success; the identity is kept, because a reorg
    /// before finality can return the transaction to the pool.
    Included,
    /// A definitive answer for these bytes now (not final for OPS: a used
    /// nonce is final only once finalized, a competing transaction can leave
    /// the pool). Any other pool failure is an `Err` (transient or ambiguous).
    Rejected(PoolRejection),
}

/// Why the pool definitively rejected a transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PoolRejection {
    /// Its nonce is already used by another transaction of the signer, at the
    /// node's current head (not necessarily final): no own receipt exists.
    NonceUsed,
    /// Another pooled transaction holds its nonce and the fee bump is too low.
    Replaced,
}

impl PoolRejection {
    /// The reason in the error response.
    pub fn reason(self) -> &'static str {
        match self {
            Self::NonceUsed => "nonce_used",
            Self::Replaced => "replaced",
        }
    }
}

#[async_trait]
pub trait ExecutionBackend: Send + Sync {
    /// Advertise a capability only after its production path is wired.
    fn capabilities(&self) -> Vec<String>;
    /// Insert `raw`, whose signer the caller already recovered and checked
    /// against the identity (`signer`), into the pool.
    async fn submit(
        &self,
        identity: Identity,
        raw: Bytes,
        signer: Address,
    ) -> Result<PoolSubmission, String>;
    /// The execution status of `hash`. Blocking: called on the status lane's
    /// blocking threads, at most `STATUS_JOBS` at once with the batched call.
    fn transaction_status(&self, _hash: B256) -> Result<Value, String> {
        Err("transaction status is unavailable".into())
    }
    /// Whether the transaction pool holds each hash, in order (cheap, in
    /// memory). A backend without a pool view cannot answer
    /// `ops_transactionStatuses`.
    fn pooled(&self, _hashes: &[B256]) -> Result<Vec<bool>, String> {
        Err("transaction pool view is unavailable".into())
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
    /// How long a submission or simulation whose fact floor is above the
    /// installed facts waits for publication before `-32012`.
    fact_wait: Duration,
    /// Bounds concurrent waiters; beyond it a lagging request gets `-32012`
    /// at once.
    waiters: Arc<Semaphore>,
    /// Bounds concurrent status jobs, single and batched (recovery and
    /// reconciliation traffic), apart from the admission pool.
    status_jobs: Arc<Semaphore>,
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
    /// Only the over-capacity answer: nothing ran, the request may be resent
    /// (`Retry-After: 1`). Never set on an answer after processing started.
    retry: bool,
}

impl ApiResponse {
    fn new(status: u16, body: &[u8]) -> Self {
        Self {
            status,
            body: body.to_vec(),
            retry: false,
        }
    }

    /// The over-capacity answer: 503, nothing ran.
    fn at_capacity() -> Self {
        Self {
            retry: true,
            ..Self::new(503, br#"{"error":"private listener at capacity"}"#)
        }
    }

    /// Whether this answer means nothing ran and the request may be resent.
    pub fn retry(&self) -> bool {
        self.retry
    }
}

/// Why a private request failed. Plain messages stay in the node's own
/// errors; a response carries only the code and, for a pool rejection, the
/// reason.
#[derive(Debug)]
enum Failure {
    Message(String),
    PoolRejected(PoolRejection),
    /// The request's fact floor did not arrive within the bounded wait.
    FactsPending,
}

impl From<String> for Failure {
    fn from(message: String) -> Self {
        Self::Message(message)
    }
}

impl From<&str> for Failure {
    fn from(message: &str) -> Self {
        Self::Message(message.to_owned())
    }
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
            fact_wait: DEFAULT_FACT_WAIT,
            waiters: Arc::new(Semaphore::new(DEFAULT_FACT_WAITERS)),
            status_jobs: Arc::new(Semaphore::new(STATUS_JOBS)),
        })
    }

    /// Set how many requests may wait for facts at once (at least 1).
    pub fn with_fact_waiters(mut self, waiters: usize) -> Self {
        self.waiters = Arc::new(Semaphore::new(waiters.max(1)));
        self
    }

    /// Set the bounded fact wait (at most `MAX_FACT_WAIT`; zero refuses a
    /// lagging request at once, still with `-32012`).
    pub fn with_fact_wait(mut self, wait: Duration) -> Self {
        self.fact_wait = wait.min(MAX_FACT_WAIT);
        self
    }

    /// Wait, holding no worker or lock, until the installed facts reach
    /// `minimum`, at most the configured fact wait.
    async fn wait_for_facts(&self, minimum: u64) -> Result<(), Failure> {
        let Ok(_waiting) = self.waiters.clone().try_acquire_owned() else {
            return Err(Failure::FactsPending);
        };
        let mut versions = self.runtime.feed.versions();
        match tokio::time::timeout(
            self.fact_wait,
            versions.wait_for(|version| *version >= minimum),
        )
        .await
        {
            Ok(Ok(_)) => Ok(()),
            // Facts that went stale meanwhile are refused, not pending.
            _ if self.runtime.feed.pin((self.clock)(), 0).is_err() => {
                Err("policy facts are stale".into())
            }
            _ => Err(Failure::FactsPending),
        }
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
        self.process_on(Lane::Execution, authorization, body).await
    }

    /// `process` for a listener serving `lane`.
    pub async fn process_on(&self, lane: Lane, authorization: &str, body: &[u8]) -> ApiResponse {
        self.process_serving(Serving::Lane(lane), authorization, body)
            .await
    }

    async fn process_serving(
        &self,
        serving: Serving,
        authorization: &str,
        body: &[u8],
    ) -> ApiResponse {
        if !self.authenticated(authorization) {
            return ApiResponse::new(401, br#"{"error":"unauthorized"}"#);
        }
        if body.len() > MAX_REQUEST_BYTES {
            return ApiResponse::new(413, br#"{"error":"request too large"}"#);
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
        if !serving.serves(&request.method) {
            if serving == Serving::Overflow {
                return ApiResponse::at_capacity();
            }
            return rpc_error(
                json!(request.id),
                -32000,
                "private execution request rejected",
            );
        }
        let id = json!(request.id);
        match self.dispatch(request, (self.clock)()).await {
            Ok(result) => ApiResponse::new(
                200,
                &serde_json::to_vec(&json!({"jsonrpc":"2.0","id":id,"result":result}))
                    .expect("serializable RPC result"),
            ),
            Err(Failure::FactsPending) => rpc_error(id, -32012, "policy facts pending"),
            Err(Failure::PoolRejected(rejection)) => rpc_error_data(
                id,
                -32013,
                "transaction pool rejected",
                json!({"reason":rejection.reason()}),
            ),
            Err(Failure::Message(error)) if error.starts_with("resynchronisation required") => {
                rpc_error(id, -32011, "policy resynchronisation required")
            }
            // Only the status call: a definitive canonical miss
            // (`transaction_not_found_v1`).
            Err(Failure::Message(error)) if error == TRANSACTION_NOT_FOUND => {
                rpc_error(id, -32014, TRANSACTION_NOT_FOUND)
            }
            Err(Failure::Message(_)) => rpc_error(id, -32000, "private execution request rejected"),
        }
    }

    async fn dispatch(&self, mut request: RpcRequest, now: i64) -> Result<Value, Failure> {
        let boot_id = self.runtime.boot_id();
        match request.method.as_str() {
            "ops_policyStatus" => {
                require_count(&request.params, 0)?;
                let latest = self.runtime.feed.latest()?;
                let mut capabilities = self.backend.capabilities();
                capabilities.extend(API_CAPABILITIES.map(str::to_owned));
                if !self.fact_wait.is_zero() {
                    capabilities.push(FACT_WAIT_CAPABILITY.to_owned());
                }
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
                    json!({"protocol_version":1,"network":self.runtime.network(),"capabilities":capabilities,"version":version,"digest":digest,"expires_at":expires,"ready":fresh&&complete,"reason":if !complete{"runtime_incomplete"}else if !fresh{"facts_unavailable"}else{""},"boot_id":boot_id}),
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
                    json!({"version":facts.version(),"digest":hex::encode(facts.digest()),"expires_at":facts.expires_at(),"boot_id":boot_id}),
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
                // The status lane, shared with the batched call: archive reads
                // never hold the admission pool's permits, and at most
                // `STATUS_JOBS` status jobs load block evidence at once. The
                // permit travels with the job, so a cancelled request cannot
                // let more run. A block named as the inclusion block counts
                // for the canonical epoch.
                let permit = self
                    .status_jobs
                    .clone()
                    .acquire_owned()
                    .await
                    .map_err(|_| "status lookup unavailable")?;
                let (runtime, backend) = (self.runtime.clone(), self.backend.clone());
                let (execution, identity) = tokio::task::spawn_blocking(move || {
                    let _permit = permit;
                    let execution = backend.transaction_status(hash)?;
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
                    let identity = runtime.status_identity(hash, block)?;
                    // A block that left the chain meanwhile is never named.
                    if !runtime.note_reported(block.as_slice())?.1.is_empty() {
                        return Err("canonical chain changed during the lookup".to_owned());
                    }
                    Ok((execution, identity))
                })
                .await
                .map_err(|_| "status lookup failed")??;
                Ok(
                    json!({"transaction_hash":format!("{hash:#x}"),"principal_id":identity.principal_id,
                    "org_id":identity.org_id,"context_id":identity.context_id,"execution":execution,"boot_id":boot_id}),
                )
            }
            "ops_transactionStatuses" => {
                if !matches!(request.params.len(), 1 | 2) {
                    return Err("invalid private parameters".into());
                }
                let hashes = status_hashes(&request.params[0])?;
                // Optional: senders whose nonce after the finalized block is
                // wanted, with each hash's receipt presence (dropped evidence).
                let senders = request.params.get(1).map(status_senders).transpose()?;
                // The status lane, shared with the single call: never the admission pool's
                // permits. The permit travels with the job, so a cancelled
                // request cannot let more jobs run than the bound.
                let permit = self
                    .status_jobs
                    .clone()
                    .acquire_owned()
                    .await
                    .map_err(|_| "status lookup unavailable")?;
                let (runtime, backend) = (self.runtime.clone(), self.backend.clone());
                let batch = tokio::task::spawn_blocking(move || {
                    let _permit = permit;
                    // The pool is read before any inclusion: a transaction
                    // leaves the pool only after its block is canonical.
                    let pooled = backend.pooled(&hashes)?;
                    if pooled.len() != hashes.len() {
                        return Err("transaction pool view unavailable".to_owned());
                    }
                    runtime
                        .transaction_statuses(&hashes, &pooled, senders.as_deref(), now)
                        .map(|batch| (batch, senders.is_some()))
                })
                .await
                .map_err(|_| "status lookup failed")??;
                Ok(status_batch_json(&batch.0, batch.1, boot_id))
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
                let first = self
                    .cpu
                    .run({
                        let (runtime, clock) = (runtime.clone(), clock.clone());
                        move || admit_transaction(&runtime, &identity, &raw, clock())
                    })
                    .await??;
                // A floor above the installed (fresh) facts waits for
                // publication without holding a worker, then admits once.
                let (admission, raw, hash, signer) = match first {
                    Admit::Done(admitted) => admitted,
                    Admit::Behind(prepared) => {
                        self.wait_for_facts(prepared.minimum()).await?;
                        match self
                            .cpu
                            .run(move || readmit_transaction(&runtime, prepared, clock()))
                            .await??
                        {
                            Admit::Done(admitted) => admitted,
                            Admit::Behind(_) => return Err(Failure::FactsPending),
                        }
                    }
                };
                let (identity, registration) = match admission {
                    Admission::Installed {
                        identity,
                        registration,
                    } => (identity, Some(registration)),
                    // A newer identity for this binding is installed (a
                    // renewal won the race): this attempt is a duplicate. The
                    // transaction is still offered to the pool.
                    Admission::Dominated(identity) => (identity, None),
                };
                let context_id = identity.context_id.clone();
                match self.backend.submit(identity, raw.into(), signer).await? {
                    PoolSubmission::Inserted(inserted) if inserted != hash => {
                        return Err("transaction pool returned a different hash".into());
                    }
                    PoolSubmission::Inserted(_) => {}
                    // The pool already holds this transaction: restored from
                    // its backup after a restart, when the node held no
                    // identity for it, or sent before by a retry. The identity
                    // admitted above lets it execute, so the resend is
                    // accepted and retries are idempotent.
                    PoolSubmission::AlreadyKnown => {}
                    // Already included (own canonical receipt): the identity
                    // stays for a reorg before finality.
                    PoolSubmission::Included => {}
                    // The pool refused these bytes definitively for now: undo
                    // exactly this installation (never a newer one), so the
                    // slot is released or the identity it replaced, which a
                    // reorg may still need, is restored. Ambiguous or transient
                    // failures (an `Err` above) keep the registration: an
                    // identity without a pooled transaction executes nothing.
                    PoolSubmission::Rejected(rejection) => {
                        if let Some(registration) = registration {
                            self.runtime.identities.revert(registration)?;
                        }
                        return Err(Failure::PoolRejected(rejection));
                    }
                }
                Ok(
                    json!({"transaction_hash":format!("{hash:#x}"),"context_id":context_id,"status":"accepted","boot_id":boot_id}),
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
                let first = self
                    .cpu
                    .run({
                        let (runtime, clock) = (runtime.clone(), clock.clone());
                        move || admit_simulation(&runtime, &identity, &encoded, clock())
                    })
                    .await??;
                let (identity, request, exact, _registration) = match first {
                    Admit::Done(admitted) => admitted,
                    Admit::Behind(prepared) => {
                        self.wait_for_facts(prepared.minimum()).await?;
                        match self
                            .cpu
                            .run(move || readmit_simulation(&runtime, prepared, clock()))
                            .await??
                        {
                            Admit::Done(admitted) => admitted,
                            Admit::Behind(_) => return Err(Failure::FactsPending),
                        }
                    }
                };
                Ok(self
                    .backend
                    .simulate(identity, request, exact.into())
                    .await?)
            }
            _ => Err("unknown private method".into()),
        }
    }
}

type AdmittedTransaction = (Admission, Vec<u8>, B256, Address);

/// An admission job's result: done, or verified but waiting for facts.
enum Admit<T, P> {
    Done(T),
    Behind(P),
}

/// A verified transaction whose fact floor is above the installed facts.
struct PreparedTransaction {
    verified: crate::wire::VerifiedIdentity,
    raw: Vec<u8>,
    hash: B256,
    signer: Address,
}

impl PreparedTransaction {
    fn minimum(&self) -> u64 {
        self.verified.identity().min_snapshot_version
    }
}

/// Second admission job, once the awaited facts are installed: the identity
/// is not verified again, only its validity window at `now`.
fn readmit_transaction(
    runtime: &PolicyRuntime,
    prepared: PreparedTransaction,
    now: i64,
) -> Result<Admit<AdmittedTransaction, PreparedTransaction>, String> {
    let minimum = prepared.minimum();
    if runtime.feed.behind(now, minimum) {
        return Ok(Admit::Behind(prepared));
    }
    runtime.feed.pin(now, minimum)?;
    let PreparedTransaction {
        verified,
        raw,
        hash,
        signer,
    } = prepared;
    // The identity is registered before pool insertion, so a pooled
    // transaction never runs without it. An ambiguous pool result keeps the
    // registration; rebinding is refused by OPS's durable submission row, saved
    // before transport. A request cancelled after this point
    // leaves an identity without a pooled transaction: harmless, it expires.
    let admission = runtime.admit_transaction(verified, now)?;
    Ok(Admit::Done((admission, raw, hash, signer)))
}

/// Pool job: verify the identity once, decode the raw transaction, recover its
/// signer, check the binding and facts, then register the identity.
fn admit_transaction(
    runtime: &PolicyRuntime,
    identity: &Value,
    raw: &str,
    now: i64,
) -> Result<Admit<AdmittedTransaction, PreparedTransaction>, String> {
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
    readmit_transaction(
        runtime,
        PreparedTransaction {
            verified,
            raw,
            hash,
            signer: recovered,
        },
        now,
    )
}

type AdmittedSimulation = (Identity, SimulationRequest, Vec<u8>, SimulationRegistration);

/// A verified simulation whose fact floor is above the installed facts.
struct PreparedSimulation {
    verified: crate::wire::VerifiedIdentity,
    request: SimulationRequest,
    exact: Vec<u8>,
    digest: B256,
}

impl PreparedSimulation {
    fn minimum(&self) -> u64 {
        self.verified.identity().min_snapshot_version
    }
}

/// Second simulation job, once the awaited facts are installed.
fn readmit_simulation(
    runtime: &PolicyRuntime,
    prepared: PreparedSimulation,
    now: i64,
) -> Result<Admit<AdmittedSimulation, PreparedSimulation>, String> {
    let minimum = prepared.minimum();
    if runtime.feed.behind(now, minimum) {
        return Ok(Admit::Behind(prepared));
    }
    runtime.feed.pin(now, minimum)?;
    let PreparedSimulation {
        verified,
        request,
        exact,
        digest,
    } = prepared;
    let identity = runtime.admit_identity(verified, now)?;
    let registration = SimulationRegistration {
        identities: runtime.identities.clone(),
        binding: ExecutionBinding::Simulation {
            context_id: identity.context_id.clone(),
            digest,
        },
    };
    Ok(Admit::Done((identity, request, exact, registration)))
}

/// Pool job for a signed simulation; the returned registration owns the slot.
fn admit_simulation(
    runtime: &PolicyRuntime,
    identity: &Value,
    encoded: &str,
    now: i64,
) -> Result<Admit<AdmittedSimulation, PreparedSimulation>, String> {
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
    readmit_simulation(
        runtime,
        PreparedSimulation {
            verified,
            request,
            exact,
            digest,
        },
        now,
    )
}

/// `[hash, …]`: 1 to `MAX_STATUS_BATCH` transaction hashes, each `0x` and 64
/// lowercase hex characters, exactly as OPS stores them.
fn status_hashes(param: &Value) -> Result<Vec<B256>, String> {
    lowercase_hex_list(param, 32)?
        .iter()
        .map(|hash| hash.parse().map_err(|_| "invalid transaction hash".into()))
        .collect()
}

/// `[address, …]`: 1 to `MAX_STATUS_BATCH` sender addresses, each `0x` and 40
/// lowercase hex characters.
fn status_senders(param: &Value) -> Result<Vec<Address>, String> {
    lowercase_hex_list(param, 20)?
        .iter()
        .map(|sender| sender.parse().map_err(|_| "invalid sender".into()))
        .collect()
}

/// A JSON array of 1 to `MAX_STATUS_BATCH` strings, each `0x` and exactly
/// `bytes` bytes as lowercase hex.
fn lowercase_hex_list(param: &Value, bytes: usize) -> Result<Vec<&str>, String> {
    let values = param.as_array().ok_or("invalid status parameters")?;
    if values.is_empty() || values.len() > MAX_STATUS_BATCH {
        return Err("invalid status parameters".into());
    }
    values
        .iter()
        .map(|value| {
            value
                .as_str()
                .filter(|value| {
                    value.len() == 2 + 2 * bytes
                        && value.starts_with("0x")
                        && value[2..]
                            .bytes()
                            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                })
                .ok_or_else(|| "invalid status parameters".to_owned())
        })
        .collect()
}

/// The wire form of a batched status answer. Each entry is the single
/// status call's result without `boot_id` (named once for the batch), with
/// the pool's view. With requested senders, also each hash's receipt
/// presence and the senders' nonces after the finalized block.
fn status_batch_json(batch: &StatusBatch, evidence: bool, boot_id: &str) -> Value {
    let statuses: Vec<Value> = batch
        .statuses
        .iter()
        .map(|entry| match entry {
            BatchedAnswer::Unknown => Value::Null,
            BatchedAnswer::NotFound => json!("not_found"),
            BatchedAnswer::Status(entry) => json!({
                "transaction_hash": format!("{:#x}", entry.hash),
                "principal_id": entry.identity.principal_id,
                "org_id": entry.identity.org_id,
                "context_id": entry.identity.context_id,
                "execution": entry.execution,
                "pooled": entry.pooled,
            }),
        })
        .collect();
    let finalized = batch.finalized.map(|head| {
        json!({"number": head.number, "hash": format!("{:#x}", head.hash), "timestamp": head.timestamp})
    });
    let mut answer = json!({
        "boot_id": boot_id,
        "finalized": finalized,
        "canonical_epoch": batch.canonical_epoch,
        "statuses": statuses,
    });
    if evidence {
        answer["receipts"] = json!(batch.receipts);
        answer["sender_nonces"] = json!(batch.sender_nonces);
    }
    answer
}

fn require_count(params: &[Value], count: usize) -> Result<(), String> {
    if params.len() != count {
        return Err("invalid private parameters".into());
    }
    Ok(())
}
fn rpc_error_data(id: Value, code: i32, message: &str, data: Value) -> ApiResponse {
    ApiResponse::new(
        200,
        &serde_json::to_vec(
            &json!({"jsonrpc":"2.0","id":id,"error":{"code":code,"message":message,"data":data}}),
        )
        .expect("serializable RPC error"),
    )
}
fn rpc_error(id: Value, code: i32, message: &str) -> ApiResponse {
    ApiResponse::new(
        200,
        &serde_json::to_vec(
            &json!({"jsonrpc":"2.0","id":id,"error":{"code":code,"message":message}}),
        )
        .expect("serializable RPC error"),
    )
}

/// Which private methods a listener serves.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Lane {
    /// Every private method (the main listener).
    Execution,
    /// Only fact publication and node status, so fact changes apply while
    /// the execution listener is saturated.
    Control,
}

/// How a connection is served: within the listener's cap, or above it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Serving {
    Lane(Lane),
    /// Above the cap: fact publication and status are still served, so a
    /// full listener never blocks the facts its waiting requests need;
    /// anything else is answered 503 with `Retry-After: 1`.
    Overflow,
}

impl Serving {
    fn serves(self, method: &str) -> bool {
        match self {
            Self::Lane(Lane::Execution) => true,
            Self::Lane(Lane::Control) | Self::Overflow => {
                matches!(method, "ops_policyApply" | "ops_policyStatus")
            }
        }
    }
}

/// A private listener's bounds.
#[derive(Clone, Copy, Debug)]
pub struct ListenerConfig {
    pub lane: Lane,
    /// Authenticated connections served at once. Above it 64 more are still
    /// served for fact publication and status, and answered 503 with
    /// `Retry-After: 1` otherwise, then closed; beyond those an authenticated
    /// connection gets that 503 at once.
    pub max_connections: usize,
    /// After this long a connection is closed at its next response boundary
    /// (`Connection: close`): an in-flight request always completes. One
    /// that is still open a minute later (a peer that stopped reading) is
    /// closed.
    pub connection_lifetime: Duration,
    /// A new connection must send the complete head of a request with the
    /// right token within this long, or it is closed. At least OPS's idle
    /// timeout (5 s), so OPS always closes an unused pooled connection first.
    pub first_request_time: Duration,
    /// How long one request may be processed before it is answered 503
    /// (the request may still complete).
    pub request_time: Duration,
}

impl Default for ListenerConfig {
    fn default() -> Self {
        Self {
            lane: Lane::Execution,
            max_connections: DEFAULT_MAX_CONNECTIONS,
            connection_lifetime: Duration::from_secs(60),
            first_request_time: IDLE_TIME,
            request_time: Duration::from_secs(30),
        }
    }
}

/// Default connections per private listener.
pub const DEFAULT_MAX_CONNECTIONS: usize = 128;
/// Authenticated connections served above the cap at once; beyond them an
/// authenticated connection is answered 503 (nothing ran) and closed.
const OVERFLOW: usize = 64;
/// How long a connection may wait for its next request's head.
const IDLE_TIME: Duration = Duration::from_secs(10);
/// How long a request body may take to arrive.
const BODY_TIME: Duration = Duration::from_secs(15);
/// Added to the sum of a connection's bounds for its backstop.
const BACKSTOP_MARGIN: Duration = Duration::from_secs(5);
/// Request body read and discarded before a 401, so the answer is not lost
/// to a reset when the connection closes with unread data.
const UNAUTHORIZED_BODY: usize = 64 << 10;
const UNAUTHORIZED_BODY_TIME: Duration = Duration::from_secs(1);

/// A connection's place, decided at its first authenticated request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Place {
    /// No authenticated request yet: no place in the cap or the overflow.
    Pending,
    Admitted(Serving),
    /// The cap and the overflow are full: answered 503, then closed.
    Refused,
}

/// Connections that have not sent an authenticated request yet. They hold no
/// place in the cap; at most `capacity` wait at once. A new connection beyond
/// that closes the oldest waiting connection of the peer address with the
/// most waiting ones, so a flood from some peers mostly closes their own
/// connections, and an authenticated connection (whose request follows at
/// once) is admitted unless the flood outpaces it.
struct Unauthenticated {
    capacity: usize,
    waiting: std::sync::Mutex<Waiting>,
}

#[derive(Default)]
struct Waiting {
    next: u64,
    connections: BTreeMap<u64, (IpAddr, oneshot::Sender<()>)>,
    peers: BTreeMap<IpAddr, BTreeSet<u64>>,
}

impl Waiting {
    fn remove(&mut self, id: u64) -> Option<oneshot::Sender<()>> {
        let (peer, close) = self.connections.remove(&id)?;
        if let Some(ids) = self.peers.get_mut(&peer) {
            ids.remove(&id);
            if ids.is_empty() {
                self.peers.remove(&peer);
            }
        }
        Some(close)
    }
}

impl Unauthenticated {
    /// A new connection's id, and the signal that closes it to make room.
    fn join(&self, peer: IpAddr) -> (u64, oneshot::Receiver<()>) {
        let (close, closed) = oneshot::channel();
        let mut waiting = self.waiting.lock().unwrap_or_else(PoisonError::into_inner);
        while waiting.connections.len() >= self.capacity {
            let Some(oldest) = waiting
                .peers
                .values()
                .max_by_key(|ids| ids.len())
                .and_then(|ids| ids.first().copied())
            else {
                break;
            };
            if let Some(close) = waiting.remove(oldest) {
                let _ = close.send(());
            }
        }
        waiting.next += 1;
        let id = waiting.next;
        waiting.connections.insert(id, (peer, close));
        waiting.peers.entry(peer).or_default().insert(id);
        (id, closed)
    }

    fn leave(&self, id: u64) {
        self.waiting
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(id);
    }
}

/// One connection's admission, shared by its requests and its task.
struct Slot {
    id: u64,
    lane: Lane,
    place: tokio::sync::watch::Sender<Place>,
    permit: std::sync::Mutex<Option<OwnedSemaphorePermit>>,
    cap: Arc<Semaphore>,
    overflow: Arc<Semaphore>,
    unauthenticated: Arc<Unauthenticated>,
}

impl Slot {
    /// At an authenticated request: the connection's place, taken at its
    /// first one (the cap, else the overflow, else refused) and kept.
    fn admit(&self) -> Place {
        let current = *self.place.borrow();
        if current != Place::Pending {
            return current;
        }
        self.unauthenticated.leave(self.id);
        let (place, permit) = match self.cap.clone().try_acquire_owned() {
            Ok(permit) => (Place::Admitted(Serving::Lane(self.lane)), Some(permit)),
            Err(_) => match self.overflow.clone().try_acquire_owned() {
                Ok(permit) => (Place::Admitted(Serving::Overflow), Some(permit)),
                Err(_) => (Place::Refused, None),
            },
        };
        *self.permit.lock().unwrap_or_else(PoisonError::into_inner) = permit;
        self.place.send_replace(place);
        place
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        self.unauthenticated.leave(self.id);
    }
}

/// The main private listener with default bounds.
pub async fn serve(
    listener: TcpListener,
    api: Arc<PrivateApi>,
    shutdown: impl Future<Output = ()> + Send,
) -> io::Result<()> {
    serve_with(listener, api, ListenerConfig::default(), shutdown).await
}

/// Dedicated private HTTP listener with bounded bodies, connections and time.
/// A connection takes a place in the cap (or the overflow) only at its first
/// authenticated request; before that it must send one's head within
/// `first_request_time`, and a failed authentication closes it.
/// Shutdown stops acceptance, lets in-flight requests finish (connections
/// close at their response boundary) for at most 10 s, then aborts.
pub async fn serve_with(
    listener: TcpListener,
    api: Arc<PrivateApi>,
    config: ListenerConfig,
    shutdown: impl Future<Output = ()> + Send,
) -> io::Result<()> {
    let cap = Arc::new(Semaphore::new(config.max_connections.max(1)));
    let overflow = Arc::new(Semaphore::new(OVERFLOW));
    let unauthenticated = Arc::new(Unauthenticated {
        capacity: config.max_connections.max(1) + OVERFLOW,
        waiting: std::sync::Mutex::new(Waiting::default()),
    });
    let (stopping, stop) = tokio::sync::watch::channel(false);
    let mut requests = JoinSet::new();
    let mut last_accept_error: Option<Instant> = None;
    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            _=&mut shutdown=>break,
            Some(_)=requests.join_next(),if !requests.is_empty()=>{},
            incoming=listener.accept()=>{
                // A failed accept (descriptor limits, an aborted handshake)
                // never stops the listener.
                let stream=match incoming {
                    Ok(accepted)=>accepted,
                    Err(error)=>{
                        // Rate-limited: a persistent error (descriptor
                        // exhaustion) clears when descriptors free up.
                        if last_accept_error.is_none_or(|at:Instant|at.elapsed()>=Duration::from_secs(10)) {
                            eprintln!("ops policy private listener: accept failed: {error}");
                            last_accept_error=Some(Instant::now());
                        }
                        tokio::time::sleep(Duration::from_millis(50)).await;
                        continue;
                    }
                };
                let (stream,peer)=stream;
                let (id,evicted)=unauthenticated.join(peer.ip());
                let slot=Arc::new(Slot {
                    id,
                    lane:config.lane,
                    place:tokio::sync::watch::Sender::new(Place::Pending),
                    permit:std::sync::Mutex::new(None),
                    cap:cap.clone(),
                    overflow:overflow.clone(),
                    unauthenticated:unauthenticated.clone(),
                });
                requests.spawn(connection(stream,api.clone(),slot,evicted,config,stop.clone()));
            }
        }
    }
    let _ = stopping.send(true);
    let drained = async { while requests.join_next().await.is_some() {} };
    if tokio::time::timeout(Duration::from_secs(10), drained)
        .await
        .is_err()
    {
        requests.abort_all();
    }
    Ok(())
}

/// Serve one accepted connection until it closes, its backstop, or shutdown.
async fn connection(
    stream: tokio::net::TcpStream,
    api: Arc<PrivateApi>,
    slot: Arc<Slot>,
    evicted: oneshot::Receiver<()>,
    config: ListenerConfig,
    mut stop: tokio::sync::watch::Receiver<bool>,
) {
    let opened = Instant::now();
    let lifetime = config.connection_lifetime;
    let request_time = config.request_time;
    let mut place = slot.place.subscribe();
    let service = service_fn(move |request: Request<Incoming>| {
        let (api, slot) = (api.clone(), slot.clone());
        async move {
            // A failed authentication closes the connection, and never
            // takes a place in the cap. Refusals before any work read the
            // body first: an answer followed by a close with unread data
            // would reach the client as a reset.
            if !api.authenticated(authorization(&request)) {
                discard(
                    request.into_body(),
                    UNAUTHORIZED_BODY,
                    UNAUTHORIZED_BODY_TIME,
                )
                .await;
                return Ok::<_, Infallible>(closing(http_response(ApiResponse::new(
                    401,
                    br#"{"error":"unauthorized"}"#,
                ))));
            }
            let serving = match slot.admit() {
                Place::Admitted(serving) => serving,
                _ => {
                    discard(request.into_body(), MAX_REQUEST_BYTES, BODY_TIME).await;
                    return Ok(closing(http_response(ApiResponse::at_capacity())));
                }
            };
            let response = handle_http(api, serving, request_time, request).await?;
            // Recycle at a response boundary, never mid-request.
            Ok(
                if serving == Serving::Overflow
                    || opened.elapsed() >= lifetime
                    || matches!(response.status().as_u16(), 401 | 404 | 413)
                {
                    closing(response)
                } else {
                    response
                },
            )
        }
    });
    let mut builder = http1::Builder::new();
    builder
        .timer(TokioTimer::new())
        .header_read_timeout(IDLE_TIME);
    let connection = builder.serve_connection(TokioIo::new(stream), service);
    tokio::pin!(connection);
    // Until its first authenticated request a connection is closed at the
    // first-request deadline, when a newer unauthenticated connection needs
    // its place, or at shutdown. None of these cuts an admitted connection.
    {
        let unadmitted_exit = async {
            tokio::select! {
                _ = tokio::time::sleep(config.first_request_time) => {},
                Ok(()) = evicted => {},
                _ = stop.wait_for(|stopping| *stopping) => {},
            }
        };
        tokio::select! {
            biased;
            _ = connection.as_mut() => return,
            _ = place.wait_for(|place| *place != Place::Pending) => {},
            _ = unadmitted_exit => {},
        }
    }
    // From the accept, the sum of the bounds of what may still run, with a
    // margin: an in-flight request is never cut, only a peer that stopped
    // reading. The lane: the lifetime, then one more idle wait, body and
    // processing. The overflow (and a refusal): its one exchange.
    let backstop = match *place.borrow() {
        Place::Pending => return,
        Place::Admitted(Serving::Lane(_)) => {
            lifetime + IDLE_TIME + BODY_TIME + request_time + BACKSTOP_MARGIN
        }
        Place::Admitted(Serving::Overflow) | Place::Refused => {
            config.first_request_time + BODY_TIME + request_time + BACKSTOP_MARGIN
        }
    };
    let _ = tokio::time::timeout(backstop.saturating_sub(opened.elapsed()), async {
        tokio::select! {
            _ = connection.as_mut() => {},
            _ = async { let _ = stop.wait_for(|stopping| *stopping).await; } => {
                connection.as_mut().graceful_shutdown();
                let _ = connection.await;
            }
        }
    })
    .await;
}

/// Read and drop at most `limit` bytes of a request body, for at most `time`.
async fn discard(mut body: Incoming, limit: usize, time: Duration) {
    let _ = tokio::time::timeout(time, async {
        let mut read = 0usize;
        while let Some(Ok(frame)) = body.frame().await {
            read += frame.data_ref().map_or(0, |data| data.len());
            if read > limit {
                break;
            }
        }
    })
    .await;
}

fn authorization(request: &Request<Incoming>) -> &str {
    request
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
}

/// The answer closes its connection after it is sent.
fn closing(mut response: Response<Full<bytes::Bytes>>) -> Response<Full<bytes::Bytes>> {
    response.headers_mut().insert(
        hyper::header::CONNECTION,
        hyper::header::HeaderValue::from_static("close"),
    );
    response
}

/// The HTTP form of an answer. Only the over-capacity answer carries
/// `Retry-After` ("nothing ran, resend"): a timed-out request may have run.
fn http_response(response: ApiResponse) -> Response<Full<bytes::Bytes>> {
    let retry = response.retry;
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
    if retry {
        result.headers_mut().insert(
            hyper::header::RETRY_AFTER,
            hyper::header::HeaderValue::from_static("1"),
        );
    }
    result
}

async fn handle_http(
    api: Arc<PrivateApi>,
    serving: Serving,
    request_time: Duration,
    request: Request<Incoming>,
) -> Result<Response<Full<bytes::Bytes>>, Infallible> {
    let authorization = authorization(&request).to_owned();
    let response = if !api.authenticated(&authorization) {
        ApiResponse::new(401, br#"{"error":"unauthorized"}"#)
    } else if request.method() != hyper::Method::POST
        || request.uri().path() != "/"
        || request.uri().query().is_some()
    {
        ApiResponse::new(404, br#"{"error":"not found"}"#)
    } else {
        match tokio::time::timeout(
            BODY_TIME,
            Limited::new(request.into_body(), MAX_REQUEST_BYTES).collect(),
        )
        .await
        {
            Ok(Ok(body)) => match tokio::time::timeout(
                request_time,
                api.process_serving(serving, &authorization, &body.to_bytes()),
            )
            .await
            {
                Ok(response) => response,
                // The request may still complete: no Retry-After.
                Err(_) => ApiResponse::new(503, br#"{"error":"execution node unavailable"}"#),
            },
            _ => ApiResponse::new(413, br#"{"error":"invalid request body"}"#),
        }
    };
    Ok(http_response(response))
}
