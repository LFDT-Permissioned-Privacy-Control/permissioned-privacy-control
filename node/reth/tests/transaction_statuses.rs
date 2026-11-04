//! Batched transaction status (`ops_transactionStatuses`, capability
//! `transaction_statuses_v1`): request order, unknown hashes as null, at most
//! 256 hashes, the effective finalized head (final and written), pool
//! presence for eviction detection, a canonical epoch that changes when a
//! reported block leaves the chain, the node's boot id, and, on request,
//! dropped evidence: each hash's receipt presence and senders' nonces at
//! exactly the finalized block.

use alloy_primitives::{Address, B256, Bytes};
use async_trait::async_trait;
use common::{
    MemoryStorage,
    fixture::{AT, descriptor, execute, identity, seal, signer, snapshot, verifier},
    golden::call,
};
use ops_reth_policy::{
    api::{CpuPool, ExecutionBackend, Lane, PoolSubmission, PrivateApi},
    archive::{ArtifactStore, BlockDescriptor},
    chain::{ChainState, Inclusion},
    runtime::PolicyRuntime,
    wire::{Identity, SimulationRequest},
};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    fmt,
    path::Path,
    sync::{Arc, Mutex},
};

mod common;

const A: B256 = B256::repeat_byte(1);
const B: B256 = B256::repeat_byte(2);
const C: B256 = B256::repeat_byte(3);
const P: B256 = B256::repeat_byte(4);
const UNKNOWN: B256 = B256::repeat_byte(0xcd);
const OTHER: Address = Address::repeat_byte(0xee);

#[derive(Clone, Debug)]
struct Block {
    hash: B256,
    transactions: Vec<B256>,
    timestamp: u64,
}

type Hook = Box<dyn Fn(&Chain) + Send>;

/// A canonical chain model with receipts' success, account nonces by block
/// hash, a log of nonce reads, lookups that fail, headers that cannot be
/// read, and a hook that changes the chain during one inclusion lookup.
#[derive(Default)]
struct Chain {
    finalized: Mutex<Option<u64>>,
    persisted: Mutex<Option<u64>>,
    canonical: Mutex<BTreeMap<u64, Block>>,
    reverted: Mutex<HashSet<B256>>,
    failing: Mutex<HashSet<B256>>,
    headerless: Mutex<HashSet<B256>>,
    nonces: Mutex<HashMap<(B256, Address), u64>>,
    nonce_reads: Mutex<Vec<(B256, Vec<Address>)>>,
    during: Mutex<Option<(B256, Hook)>>,
}

impl fmt::Debug for Chain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Chain")
    }
}

impl Chain {
    fn block(&self, number: u64, hash: B256, transactions: Vec<B256>) {
        self.canonical.lock().unwrap().insert(
            number,
            Block {
                hash,
                transactions,
                timestamp: 1_000 + number,
            },
        );
    }
    fn set(&self, finalized: Option<u64>, persisted: Option<u64>) {
        *self.finalized.lock().unwrap() = finalized;
        *self.persisted.lock().unwrap() = persisted;
    }
    fn nonce(&self, block: B256, account: Address, nonce: u64) {
        self.nonces.lock().unwrap().insert((block, account), nonce);
    }
}

impl ChainState for Chain {
    fn finalized(&self) -> Option<(u64, B256)> {
        let number = (*self.finalized.lock().unwrap())?;
        Some((number, self.canonical_hash(number)?))
    }
    fn persisted(&self) -> Option<u64> {
        *self.persisted.lock().unwrap()
    }
    fn canonical_hash(&self, number: u64) -> Option<B256> {
        Some(self.canonical.lock().unwrap().get(&number)?.hash)
    }
    fn transactions(&self, number: u64) -> Option<Vec<B256>> {
        Some(
            self.canonical
                .lock()
                .unwrap()
                .get(&number)?
                .transactions
                .clone(),
        )
    }
    fn inclusion(&self, hash: B256) -> Result<Option<Inclusion>, String> {
        let during = self.during.lock().unwrap().take();
        match during {
            Some((target, hook)) if target == hash => hook(self),
            other => *self.during.lock().unwrap() = other,
        }
        if self.failing.lock().unwrap().contains(&hash) {
            return Err("lookup failed".into());
        }
        let reverted = self.reverted.lock().unwrap().contains(&hash);
        Ok(self
            .canonical
            .lock()
            .unwrap()
            .iter()
            .find(|(_, block)| block.transactions.contains(&hash))
            .map(|(number, block)| Inclusion {
                number: *number,
                hash: block.hash,
                success: !reverted,
            }))
    }
    fn block_timestamp(&self, hash: B256) -> Option<u64> {
        if self.headerless.lock().unwrap().contains(&hash) {
            return None;
        }
        self.canonical
            .lock()
            .unwrap()
            .values()
            .find(|block| block.hash == hash)
            .map(|block| block.timestamp)
    }
    fn nonces_at(&self, block: B256, accounts: &[Address]) -> Result<Vec<u64>, String> {
        self.nonce_reads
            .lock()
            .unwrap()
            .push((block, accounts.to_vec()));
        let nonces = self.nonces.lock().unwrap();
        Ok(accounts
            .iter()
            .map(|account| nonces.get(&(block, *account)).copied().unwrap_or(0))
            .collect())
    }
}

/// A pool view (which hashes the pool holds); single status is answered by
/// the runtime, as the production backend does.
struct Pool {
    pooled: Mutex<HashSet<B256>>,
    runtime: Arc<PolicyRuntime>,
    view: bool,
}

#[async_trait]
impl ExecutionBackend for Pool {
    fn capabilities(&self) -> Vec<String> {
        let mut capabilities = common::golden::Backend.capabilities();
        capabilities.push("transaction_statuses_v1".into());
        capabilities
    }
    async fn submit(
        &self,
        _identity: Identity,
        _raw: Bytes,
        _signer: Address,
    ) -> Result<PoolSubmission, String> {
        Err("unused".into())
    }
    fn transaction_status(&self, hash: B256) -> Result<Value, String> {
        Ok(serde_json::to_value(self.runtime.status(hash, AT)?).unwrap())
    }
    async fn simulate(
        &self,
        _identity: Identity,
        _request: SimulationRequest,
        _exact: Bytes,
    ) -> Result<Value, String> {
        Err("unused".into())
    }
    fn pooled(&self, hashes: &[B256]) -> Result<Vec<bool>, String> {
        if !self.view {
            return Err("no pool view".into());
        }
        let pooled = self.pooled.lock().unwrap();
        Ok(hashes.iter().map(|hash| pooled.contains(hash)).collect())
    }
}

struct Node {
    api: PrivateApi,
    runtime: Arc<PolicyRuntime>,
    chain: Arc<Chain>,
    pool: Arc<Pool>,
}

fn sender() -> Address {
    signer().parse().unwrap()
}

fn block(number: u64, hash: B256, transactions: Vec<B256>) -> BlockDescriptor {
    BlockDescriptor {
        number,
        hash,
        timestamp: AT as u64,
        ..descriptor(transactions)
    }
}

/// Heights 0..=4 canonical, final and written.
fn base_chain() -> Arc<Chain> {
    let chain = Arc::new(Chain::default());
    for number in 0..=4 {
        chain.block(number, B256::repeat_byte(100 + number as u8), Vec::new());
    }
    chain.set(Some(4), Some(4));
    chain
}

fn api(runtime: &Arc<PolicyRuntime>, view: bool) -> (PrivateApi, Arc<Pool>) {
    let pool = Arc::new(Pool {
        pooled: Mutex::new(HashSet::from([P])),
        runtime: runtime.clone(),
        view,
    });
    let api = PrivateApi::new(
        runtime.clone(),
        pool.clone(),
        "private-test-token".into(),
        Arc::new(|| AT),
    )
    .unwrap();
    (api, pool)
}

/// A and B (reverted) produced in block 5, C in block 6 (both canonical, not
/// final); P registered and pooled.
fn node_with(view: bool, attach: bool) -> Node {
    let chain = base_chain();
    let archive = ArtifactStore::open_with(Path::new("/state"), MemoryStorage::new()).unwrap();
    let runtime = Arc::new(PolicyRuntime::new(verifier(), Arc::new(archive), 64));
    runtime
        .accept_facts("snapshot", &seal("snapshot", &snapshot()), AT)
        .unwrap();
    if attach {
        runtime.attach_chain(chain.clone());
    }
    for (hash, context) in [(A, "ctx-a"), (B, "ctx-b"), (C, "ctx-c"), (P, "ctx-p")] {
        runtime
            .accept_identity(&seal("identity", &identity(hash, context)), AT)
            .unwrap();
    }
    let five = runtime.pin_candidate(AT).unwrap();
    assert!(execute(&five, A) && execute(&five, B));
    runtime
        .persist(&five, &block(5, B256::repeat_byte(50), vec![A, B]))
        .unwrap();
    let six = runtime.pin_candidate(AT).unwrap();
    assert!(execute(&six, C));
    runtime
        .persist(&six, &block(6, B256::repeat_byte(60), vec![C]))
        .unwrap();
    chain.block(5, B256::repeat_byte(50), vec![A, B]);
    chain.block(6, B256::repeat_byte(60), vec![C]);
    chain.reverted.lock().unwrap().insert(B);
    let (api, pool) = api(&runtime, view);
    Node {
        api,
        runtime,
        chain,
        pool,
    }
}

fn node() -> Node {
    node_with(true, true)
}

fn hex(hash: B256) -> String {
    format!("{hash:#x}")
}

fn hexes(hashes: &[B256]) -> Vec<String> {
    hashes.iter().copied().map(hex).collect()
}

async fn statuses(api: &PrivateApi, params: Value) -> Value {
    call(api, "ops_transactionStatuses", params).await
}

/// The result of a successful batched call for `hashes`.
async fn answer(api: &PrivateApi, hashes: &[B256]) -> Value {
    succeeded(statuses(api, json!([hexes(hashes)])).await)
}

/// As `answer`, asking for dropped evidence for `senders`.
async fn evidence(api: &PrivateApi, hashes: &[B256], senders: &[Address]) -> Value {
    let senders: Vec<String> = senders.iter().map(|s| format!("{s:#x}")).collect();
    succeeded(statuses(api, json!([hexes(hashes), senders])).await)
}

fn succeeded(response: Value) -> Value {
    response
        .get("result")
        .unwrap_or_else(|| panic!("batched status failed: {response}"))
        .clone()
}

fn keys(value: &Value) -> BTreeSet<String> {
    value.as_object().unwrap().keys().cloned().collect()
}

fn set(names: &[&str]) -> BTreeSet<String> {
    names.iter().map(|name| name.to_string()).collect()
}

#[tokio::test]
async fn batched_status_answers_in_request_order_with_unknown_as_null() {
    let node = node();
    let boot = call(&node.api, "ops_policyStatus", json!([])).await["result"]["boot_id"].clone();
    let result = answer(&node.api, &[A, UNKNOWN, P, A, B]).await;
    // Exactly the proposed shape: no evidence fields unless asked for.
    assert_eq!(
        keys(&result),
        set(&["boot_id", "finalized", "canonical_epoch", "statuses"]),
        "{result}"
    );
    assert_eq!(result["boot_id"], boot, "another boot answered: {result}");
    assert_eq!(result["canonical_epoch"], 0, "{result}");
    let entries = result["statuses"].as_array().unwrap();
    assert_eq!(entries.len(), 5, "{result}");
    assert!(entries[1].is_null(), "an unknown hash disclosed a status");
    assert_eq!(entries[0], entries[3], "a repeated hash got another answer");
    for (entry, hash) in entries.iter().zip([A, UNKNOWN, P, A, B]) {
        if entry.is_null() {
            continue;
        }
        assert_eq!(
            entry["transaction_hash"],
            hex(hash),
            "out of order: {result}"
        );
        assert_eq!(
            keys(entry),
            set(&[
                "transaction_hash",
                "principal_id",
                "org_id",
                "context_id",
                "execution",
                "pooled",
            ]),
            "{entry}"
        );
        assert_eq!(entry["principal_id"], "fixture_principal");
        assert_eq!(entry["org_id"], "org_acme");
    }
    let included = &entries[0];
    assert_eq!(included["context_id"], "ctx-a");
    assert_eq!(included["execution"]["status"], "included", "{included}");
    assert_eq!(included["execution"]["block_number"], 5);
    assert_eq!(
        included["execution"]["block_hash"],
        hex(B256::repeat_byte(50))
    );
    assert_eq!(included["execution"]["finalized"], false);
    assert_eq!(included["pooled"], false);
    let pending = &entries[2];
    assert_eq!(pending["context_id"], "ctx-p");
    assert_eq!(pending["execution"]["status"], "pending", "{pending}");
    assert_eq!(pending["execution"]["block_number"], Value::Null);
    assert_eq!(pending["pooled"], true);
    assert_eq!(entries[4]["execution"]["status"], "reverted", "{result}");
    // Each entry is the single call's result without the boot id.
    for (entry, hash) in [(&entries[0], A), (&entries[2], P), (&entries[4], B)] {
        let single = call(&node.api, "ops_transactionStatus", json!([hex(hash)])).await;
        let mut single = single["result"].clone();
        single.as_object_mut().unwrap().remove("boot_id");
        let mut entry = entry.clone();
        entry.as_object_mut().unwrap().remove("pooled");
        assert_eq!(entry, single, "the batch and the single call disagree");
    }
}

#[tokio::test]
async fn batched_status_takes_one_to_256_lowercase_hashes() {
    let node = node();
    let full = answer(&node.api, &[UNKNOWN; 256]).await;
    let entries = full["statuses"].as_array().unwrap();
    assert_eq!(entries.len(), 256);
    assert!(entries.iter().all(Value::is_null));
    let many: Vec<String> = vec![hex(UNKNOWN); 257];
    let upper = hex(UNKNOWN).to_uppercase().replacen("0X", "0x", 1);
    let sender = format!("{:#x}", sender());
    for (name, params) in [
        ("257 hashes", json!([many])),
        ("no hashes", json!([[]])),
        ("uppercase hash", json!([[upper]])),
        ("no 0x prefix", json!([[hex(A)[2..].to_owned()]])),
        ("short hash", json!([["0x0102"]])),
        ("not a string", json!([[1]])),
        ("not an array", json!([hex(A)])),
        ("no params", json!([])),
        ("three params", json!([[hex(A)], [sender], []])),
        ("hash as sender", json!([[hex(A)], [hex(A)]])),
        (
            "uppercase sender",
            json!([
                [hex(A)],
                [format!("{:#x}", OTHER)
                    .to_uppercase()
                    .replacen("0X", "0x", 1)]
            ]),
        ),
        ("no senders", json!([[hex(A)], []])),
        ("257 senders", json!([[hex(A)], vec![sender.clone(); 257]])),
        ("senders not an array", json!([[hex(A)], sender])),
    ] {
        let refused = statuses(&node.api, params).await;
        assert_eq!(refused["error"]["code"], -32000, "{name}: {refused}");
        assert!(refused.get("result").is_none(), "{name}");
    }
}

#[tokio::test]
async fn finalized_head_is_capped_at_the_written_height() {
    let node = node();
    // Forkchoice-final through 6, but Reth has written only through 5.
    node.chain.set(Some(6), Some(5));
    let result = answer(&node.api, &[A, C]).await;
    assert_eq!(
        result["finalized"],
        json!({"number":5,"hash":hex(B256::repeat_byte(50)),"timestamp":1005}),
        "{result}"
    );
    let (a, c) = (&result["statuses"][0], &result["statuses"][1]);
    assert_eq!(a["execution"]["finalized"], true, "{a}");
    assert_eq!(a["execution"]["finalized_block_number"], 5);
    assert_eq!(
        a["execution"]["finalized_block_hash"],
        hex(B256::repeat_byte(50))
    );
    assert_eq!(c["execution"]["status"], "included");
    assert_eq!(
        c["execution"]["finalized"], false,
        "finalized above the written height: {c}"
    );
    // As the single call does, a finalized answer releases the slot.
    assert!(node.runtime.live_identity(A).is_none());
    assert!(node.runtime.live_identity(C).is_some());
    // Written through 6 now: C is final in the same view as the head.
    node.chain.set(Some(6), Some(6));
    let result = answer(&node.api, &[C]).await;
    assert_eq!(result["finalized"]["number"], 6, "{result}");
    assert_eq!(result["statuses"][0]["execution"]["finalized"], true);
    assert_eq!(
        result["statuses"][0]["execution"]["finalized_block_number"],
        6
    );
}

#[tokio::test]
async fn finality_evidence_is_withheld_when_unknown_genesis_or_unreadable() {
    // Unknown finality.
    let unknown = node_with(true, false);
    unknown.chain.set(None, Some(6));
    unknown.runtime.attach_chain(unknown.chain.clone());
    let result = evidence(&unknown.api, &[A, P], &[sender()]).await;
    assert_eq!(result["finalized"], Value::Null, "{result}");
    assert_eq!(result["sender_nonces"], Value::Null, "{result}");
    for entry in result["statuses"].as_array().unwrap() {
        assert_eq!(entry["execution"]["finalized"], false, "{entry}");
    }
    assert!(unknown.chain.nonce_reads.lock().unwrap().is_empty());

    // Only genesis final: no block that could hold a transaction is final.
    let genesis = node_with(true, false);
    genesis.chain.set(Some(0), Some(6));
    genesis.runtime.attach_chain(genesis.chain.clone());
    let result = evidence(&genesis.api, &[A], &[sender()]).await;
    assert_eq!(result["finalized"], Value::Null, "{result}");
    assert_eq!(result["sender_nonces"], Value::Null, "{result}");

    // The finalized block's header cannot be read.
    let node = node();
    node.chain.set(Some(5), Some(6));
    node.chain
        .headerless
        .lock()
        .unwrap()
        .insert(B256::repeat_byte(50));
    let result = evidence(&node.api, &[A], &[sender()]).await;
    assert_eq!(result["finalized"], Value::Null, "{result}");
    assert_eq!(result["statuses"][0]["execution"]["finalized"], false);
    assert_eq!(result["sender_nonces"], Value::Null, "{result}");
}

#[tokio::test]
async fn dropped_evidence_reads_receipts_and_nonces_at_the_finalized_hash() {
    let node = node();
    node.chain.set(Some(5), Some(6));
    node.chain.nonce(B256::repeat_byte(50), sender(), 3);
    node.chain.nonce(B256::repeat_byte(60), sender(), 5);
    node.chain.nonce(B256::repeat_byte(50), OTHER, 7);
    // Q has a registered identity, but its inclusion cannot be read.
    let q = B256::repeat_byte(5);
    node.runtime
        .accept_identity(&seal("identity", &identity(q, "ctx-q")), AT)
        .unwrap();
    node.chain.failing.lock().unwrap().insert(q);
    let result = evidence(
        &node.api,
        &[A, P, UNKNOWN, C, q],
        &[sender(), OTHER, sender()],
    )
    .await;
    assert_eq!(result["finalized"]["hash"], hex(B256::repeat_byte(50)));
    assert_eq!(
        result["receipts"],
        json!([true, false, false, true, null]),
        "{result}"
    );
    assert_eq!(
        result["sender_nonces"],
        json!([3, 7, 3]),
        "not the nonces at the finalized block: {result}"
    );
    // A failed lookup is no answer, never the registry's "pending".
    assert!(result["statuses"][4].is_null(), "{result}");
    // One state read per call, at exactly the finalized hash.
    assert_eq!(
        node.chain.nonce_reads.lock().unwrap().as_slice(),
        [(B256::repeat_byte(50), vec![sender(), OTHER, sender()])]
    );
    // Without senders, no evidence fields and no state read.
    let plain = answer(&node.api, &[A]).await;
    assert!(plain.get("receipts").is_none() && plain.get("sender_nonces").is_none());
    assert_eq!(node.chain.nonce_reads.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn pooled_tells_a_pending_transaction_from_an_evicted_one() {
    let node = node();
    let first = answer(&node.api, &[P]).await;
    assert_eq!(first["statuses"][0]["pooled"], true, "{first}");
    // Evicted from the pool (same boot): still pending, no longer pooled.
    node.pool.pooled.lock().unwrap().remove(&P);
    let evicted = answer(&node.api, &[P]).await;
    assert_eq!(evicted["statuses"][0]["execution"]["status"], "pending");
    assert_eq!(evicted["statuses"][0]["pooled"], false, "{evicted}");
    // An included transaction is never reported pooled, even while the pool
    // has not yet dropped it.
    node.pool.pooled.lock().unwrap().insert(A);
    let included = answer(&node.api, &[A]).await;
    assert_eq!(included["statuses"][0]["execution"]["status"], "included");
    assert_eq!(included["statuses"][0]["pooled"], false, "{included}");
    // Pooled without an identity (a pool restored after a restart): the node
    // has no status for it.
    let orphan = B256::repeat_byte(9);
    node.pool.pooled.lock().unwrap().insert(orphan);
    let restored = answer(&node.api, &[orphan]).await;
    assert!(restored["statuses"][0].is_null(), "{restored}");
}

#[tokio::test]
async fn canonical_epoch_changes_when_a_reported_block_leaves_the_chain() {
    let node = node();
    assert_eq!(answer(&node.api, &[A]).await["canonical_epoch"], 0);
    // Appending blocks is not a change.
    node.chain.block(7, B256::repeat_byte(70), Vec::new());
    assert_eq!(answer(&node.api, &[A]).await["canonical_epoch"], 0);
    // A block no answer named is replaced: nothing OPS holds changed.
    node.chain.block(7, B256::repeat_byte(71), Vec::new());
    assert_eq!(answer(&node.api, &[A]).await["canonical_epoch"], 0);
    // The block the answers named for A is replaced by one without A.
    node.chain.block(5, B256::repeat_byte(51), vec![B]);
    let reorged = answer(&node.api, &[A]).await;
    assert_eq!(reorged["canonical_epoch"], 1, "{reorged}");
    // Not final, so A's identity was kept: pending again.
    assert_eq!(reorged["statuses"][0]["execution"]["status"], "pending");
    assert_eq!(answer(&node.api, &[A]).await["canonical_epoch"], 1);

    // A block named only by the single status call counts too.
    let single = call(&node.api, "ops_transactionStatus", json!([hex(C)])).await;
    assert_eq!(single["result"]["execution"]["block_number"], 6, "{single}");
    node.chain.block(6, B256::repeat_byte(61), Vec::new());
    let reorged = answer(&node.api, &[P]).await;
    assert_eq!(reorged["canonical_epoch"], 2, "{reorged}");
}

#[tokio::test]
async fn a_block_gone_by_the_end_of_an_answer_is_never_named() {
    let node = node();
    // Q is in block 7, for which this node has no evidence (entry null).
    let q = B256::repeat_byte(7);
    node.chain.block(7, B256::repeat_byte(70), vec![q]);
    // While P is looked up (after A and Q were read), blocks 5 and 7 are
    // replaced: the answer would name blocks that are gone.
    *node.chain.during.lock().unwrap() = Some((
        P,
        Box::new(|chain: &Chain| {
            chain.block(5, B256::repeat_byte(52), Vec::new());
            chain.block(7, B256::repeat_byte(72), Vec::new());
        }),
    ));
    let result = evidence(&node.api, &[A, q, P], &[sender()]).await;
    assert!(
        result["statuses"][0].is_null(),
        "named a gone block: {result}"
    );
    assert!(result["statuses"][1].is_null(), "{result}");
    assert_eq!(result["receipts"], json!([null, null, false]), "{result}");
    assert_eq!(result["statuses"][2]["execution"]["status"], "pending");
    // Nothing named it, so nothing OPS holds changed.
    assert_eq!(result["canonical_epoch"], 0, "{result}");
}

#[tokio::test]
async fn a_change_during_an_answer_is_reported_by_that_answer() {
    let node = node();
    assert_eq!(answer(&node.api, &[A]).await["canonical_epoch"], 0);
    // While P is looked up, block 5 (named for A before) is replaced.
    *node.chain.during.lock().unwrap() = Some((
        P,
        Box::new(|chain: &Chain| chain.block(5, B256::repeat_byte(52), Vec::new())),
    ));
    let result = answer(&node.api, &[C, P]).await;
    assert_eq!(
        result["canonical_epoch"], 1,
        "the change was left for a later answer: {result}"
    );
}

#[tokio::test]
async fn the_answer_that_reports_a_change_anchors_its_own_blocks() {
    let node = node();
    assert_eq!(answer(&node.api, &[A]).await["canonical_epoch"], 0);
    node.chain.block(5, B256::repeat_byte(51), Vec::new());
    // This answer reports the loss of block 5 and names C's block 6.
    let result = answer(&node.api, &[C]).await;
    assert_eq!(result["canonical_epoch"], 1, "{result}");
    assert_eq!(result["statuses"][0]["execution"]["block_number"], 6);
    // Block 6 is lost later; no answer names a higher block meanwhile.
    node.chain.block(6, B256::repeat_byte(61), Vec::new());
    let result = answer(&node.api, &[P]).await;
    assert_eq!(
        result["canonical_epoch"], 2,
        "the loss of a block named with a change went unnoticed: {result}"
    );
}

#[tokio::test]
async fn a_block_named_below_the_highest_is_still_watched_after_a_change() {
    let node = node();
    assert_eq!(answer(&node.api, &[C]).await["canonical_epoch"], 0);
    // Named below the highest named block (6): only the highest is checked.
    assert_eq!(answer(&node.api, &[A]).await["canonical_epoch"], 0);
    // Block 6 alone is replaced: a change, but block 5 is still canonical.
    node.chain.block(6, B256::repeat_byte(61), Vec::new());
    assert_eq!(answer(&node.api, &[P]).await["canonical_epoch"], 1);
    // Later block 5 is lost too, while no answer names anything new.
    node.chain.block(5, B256::repeat_byte(51), Vec::new());
    let result = answer(&node.api, &[P]).await;
    assert_eq!(
        result["canonical_epoch"], 2,
        "a block named before a change was forgotten: {result}"
    );
}

#[tokio::test]
async fn named_blocks_at_or_below_finality_are_no_longer_watched() {
    let node = node();
    assert_eq!(answer(&node.api, &[A]).await["canonical_epoch"], 0);
    node.chain.set(Some(5), Some(5));
    // Block 5 is final: it can no longer leave (a replacement in the model
    // after finality is not a change OPS must hear about).
    assert_eq!(answer(&node.api, &[P]).await["canonical_epoch"], 0);
    node.chain.block(5, B256::repeat_byte(51), vec![A, B]);
    assert_eq!(answer(&node.api, &[P]).await["canonical_epoch"], 0);
}

#[tokio::test]
async fn the_finalized_block_is_fixed_before_any_transaction_is_looked_up() {
    let node = node();
    node.chain.set(Some(5), Some(5));
    node.chain.nonce(B256::repeat_byte(50), sender(), 3);
    node.chain.nonce(B256::repeat_byte(60), sender(), 4);
    // Block 6 becomes final and written while P is looked up.
    *node.chain.during.lock().unwrap() =
        Some((P, Box::new(|chain: &Chain| chain.set(Some(6), Some(6)))));
    let result = evidence(&node.api, &[A, P, C], &[sender()]).await;
    assert_eq!(result["finalized"]["number"], 5, "{result}");
    assert_eq!(result["sender_nonces"], json!([3]), "{result}");
    assert_eq!(result["statuses"][0]["execution"]["finalized"], true);
    assert_eq!(
        result["statuses"][2]["execution"]["finalized"], false,
        "an entry was decided against a later finalized block: {result}"
    );
    assert_eq!(
        node.chain.nonce_reads.lock().unwrap().as_slice(),
        [(B256::repeat_byte(50), vec![sender()])]
    );
    // The next answer sees the new finalized block.
    assert_eq!(answer(&node.api, &[C]).await["finalized"]["number"], 6);
}

#[tokio::test]
async fn included_without_local_evidence_is_null() {
    let node = node();
    // Canonical in a block this node has no manifest for (pruned or never
    // published here): no identity can be named, and the registry's answer
    // for P is not used.
    node.chain.block(7, B256::repeat_byte(70), vec![P]);
    let result = evidence(&node.api, &[P, A], &[sender()]).await;
    assert!(result["statuses"][0].is_null(), "{result}");
    assert_eq!(result["statuses"][1]["execution"]["status"], "included");
    assert_eq!(result["receipts"], json!([true, true]), "{result}");
}

#[tokio::test]
async fn a_call_loads_a_bounded_number_of_uncached_blocks() {
    let storage = MemoryStorage::new();
    let chain = base_chain();
    let hashes: Vec<B256> = (0..18u8)
        .map(|i| B256::left_padding_from(&[0xa0, i]))
        .collect();
    {
        let archive = ArtifactStore::open_with(Path::new("/state"), storage.clone()).unwrap();
        let runtime = PolicyRuntime::new(verifier(), Arc::new(archive), 64);
        runtime
            .accept_facts("snapshot", &seal("snapshot", &snapshot()), AT)
            .unwrap();
        runtime.attach_chain(chain.clone());
        for (offset, &hash) in hashes.iter().enumerate() {
            runtime
                .accept_identity(&seal("identity", &identity(hash, "ctx")), AT)
                .unwrap();
            let candidate = runtime.pin_candidate(AT).unwrap();
            assert!(execute(&candidate, hash));
            let number = 5 + offset as u64;
            let block_hash = B256::left_padding_from(&[0xb0, offset as u8]);
            runtime
                .persist(&candidate, &block(number, block_hash, vec![hash]))
                .unwrap();
            chain.block(number, block_hash, vec![hash]);
        }
    }
    // Restarted: nothing cached, every block's evidence is on disk.
    let archive = ArtifactStore::open_with(Path::new("/state"), storage.clone()).unwrap();
    let runtime = Arc::new(PolicyRuntime::open(verifier(), Arc::new(archive), 64, AT).unwrap());
    runtime.attach_chain(chain.clone());
    let (api, _) = api(&runtime, true);
    let first = answer(&api, &hashes).await;
    let answered = |result: &Value| {
        result["statuses"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|entry| !entry.is_null())
            .count()
    };
    assert_eq!(answered(&first), 16, "{first}");
    assert!(first["statuses"][16].is_null() && first["statuses"][17].is_null());
    let second = answer(&api, &hashes).await;
    assert_eq!(answered(&second), 18, "{second}");
}

#[tokio::test]
async fn batched_status_fails_closed_without_chain_or_pool_view() {
    for (name, node) in [
        ("no pool view", node_with(false, true)),
        ("no chain attached", node_with(true, false)),
    ] {
        let refused = statuses(&node.api, json!([[hex(A)]])).await;
        assert_eq!(refused["error"]["code"], -32000, "{name}: {refused}");
    }
}

#[tokio::test]
async fn batched_status_is_served_only_on_the_execution_listener_off_the_admission_pool() {
    let node = node();
    let body = serde_json::to_vec(
        &json!({"jsonrpc":"2.0","id":"ops-1","method":"ops_transactionStatuses","params":[[hex(A)]]}),
    )
    .unwrap();
    let control = node
        .api
        .process_on(Lane::Control, "Bearer private-test-token", &body)
        .await;
    let control: Value = serde_json::from_slice(&control.body).unwrap();
    assert_eq!(control["error"]["code"], -32000, "{control}");
    // Every admission permit held by a job that never runs: the batched
    // status still answers.
    let parked = Arc::new(Mutex::new(Vec::new()));
    let api = Arc::new(node.api.with_cpu_pool(CpuPool::with_spawner(1, {
        let parked = parked.clone();
        move |job| parked.lock().unwrap().push(job)
    })));
    let blocked = tokio::spawn({
        let api = api.clone();
        async move { call(&api, "ops_submitTransaction", json!([seal_value(), "0x00"])).await }
    });
    for _ in 0..1_000 {
        if !parked.lock().unwrap().is_empty() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(1)).await;
    }
    assert_eq!(parked.lock().unwrap().len(), 1, "admission never queued");
    let result = answer(&api, &[A]).await;
    assert_eq!(result["statuses"][0]["execution"]["status"], "included");
    blocked.abort();
}

fn seal_value() -> Value {
    serde_json::from_slice(&seal("identity", &identity(UNKNOWN, "ctx-x"))).unwrap()
}

/// A backend whose single status answers block on a gate, counting how many
/// run at once (finding 4: the single call had no bound).
struct Held {
    runtime: Arc<PolicyRuntime>,
    gate: Arc<common::Gate>,
    entered: std::sync::atomic::AtomicUsize,
    active: std::sync::atomic::AtomicUsize,
    most: std::sync::atomic::AtomicUsize,
}

#[async_trait]
impl ExecutionBackend for Held {
    fn capabilities(&self) -> Vec<String> {
        common::golden::Backend.capabilities()
    }
    async fn submit(
        &self,
        _identity: Identity,
        _raw: Bytes,
        _signer: Address,
    ) -> Result<PoolSubmission, String> {
        Err("unused".into())
    }
    fn transaction_status(&self, hash: B256) -> Result<Value, String> {
        use std::sync::atomic::Ordering::SeqCst;
        self.entered.fetch_add(1, SeqCst);
        let now = self.active.fetch_add(1, SeqCst) + 1;
        self.most.fetch_max(now, SeqCst);
        self.gate.pass();
        self.active.fetch_sub(1, SeqCst);
        Ok(serde_json::to_value(self.runtime.status(hash, AT)?).unwrap())
    }
    async fn simulate(
        &self,
        _identity: Identity,
        _request: SimulationRequest,
        _exact: Bytes,
    ) -> Result<Value, String> {
        Err("unused".into())
    }
    fn pooled(&self, hashes: &[B256]) -> Result<Vec<bool>, String> {
        Ok(vec![false; hashes.len()])
    }
}

/// Opens the gate when the test ends, also on a failed assertion, so no
/// blocking thread stays parked.
struct OpenOnDrop(Arc<common::Gate>);

impl Drop for OpenOnDrop {
    fn drop(&mut self) {
        self.0.open();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn single_status_calls_share_the_bounded_status_lane() {
    use std::sync::atomic::Ordering::SeqCst;
    use std::time::Duration;
    let node = node();
    let held = Arc::new(Held {
        runtime: node.runtime.clone(),
        gate: common::Gate::new(),
        entered: Default::default(),
        active: Default::default(),
        most: Default::default(),
    });
    let _open = OpenOnDrop(held.gate.clone());
    let api = Arc::new(
        PrivateApi::new(
            node.runtime.clone(),
            held.clone(),
            "private-test-token".into(),
            Arc::new(|| AT),
        )
        .unwrap(),
    );
    let single = |api: Arc<PrivateApi>| {
        tokio::spawn(async move { call(&api, "ops_transactionStatus", json!([hex(P)])).await })
    };
    let calls: Vec<_> = (0..8).map(|_| single(api.clone())).collect();
    let mut reached = false;
    for _ in 0..2_000 {
        if held.active.load(SeqCst) >= 4 {
            reached = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    assert!(reached, "four status jobs never started");
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(
        (held.most.load(SeqCst), held.entered.load(SeqCst)),
        (4, 4),
        "single status calls ran beside each other without a bound"
    );
    // Cancelled requests (a client gone, the 30 s bound): the jobs already
    // running keep their places until they finish, so nothing else starts.
    for call in &calls {
        call.abort();
    }
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(
        held.entered.load(SeqCst),
        4,
        "a queued call ran after its cancel"
    );
    // The batched call shares the lane: it waits for those jobs.
    let batch = tokio::spawn({
        let api = api.clone();
        async move { answer(&api, &[A]).await }
    });
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(
        !batch.is_finished(),
        "the batched call ran beside four status jobs"
    );
    held.gate.open();
    let answered = tokio::time::timeout(Duration::from_secs(5), batch)
        .await
        .expect("the batched call ran once the lane was free")
        .unwrap();
    assert_eq!(answered["statuses"][0]["execution"]["status"], "included");
    let result = call(&api, "ops_transactionStatus", json!([hex(P)])).await;
    assert_eq!(
        result["result"]["execution"]["status"], "pending",
        "{result}"
    );
    assert!(held.most.load(SeqCst) <= 4);
}
