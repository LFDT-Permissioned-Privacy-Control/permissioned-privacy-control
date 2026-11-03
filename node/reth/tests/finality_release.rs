//! Release at finality from the node's own canonical chain (plan T11), and
//! finality reported only up to what Reth has written.

use alloy_primitives::B256;
use common::{
    MemoryStorage,
    fixture::{AT, descriptor, execute, execute_result, identity, seal, snapshot, verifier},
};
use ops_reth_policy::{
    archive::{ArtifactStore, BlockDescriptor},
    chain::ChainState,
    context::ExecutionBinding,
    runtime::PolicyRuntime,
};
use std::{
    collections::HashMap,
    path::Path,
    sync::{Arc, Mutex},
};

mod common;

const TX: B256 = B256::repeat_byte(1);

/// A canonical chain model: finalized and persisted heights, and the
/// canonical block (hash, transactions) at each height.
#[derive(Debug, Default)]
struct Chain {
    finalized: Mutex<Option<u64>>,
    persisted: Mutex<Option<u64>>,
    canonical: Mutex<HashMap<u64, (B256, Vec<B256>)>>,
    /// Heights whose transactions were read.
    reads: Mutex<Vec<u64>>,
}

impl Chain {
    fn block(&self, number: u64, hash: B256, transactions: Vec<B256>) {
        self.canonical
            .lock()
            .unwrap()
            .insert(number, (hash, transactions));
    }
    fn set(&self, finalized: u64, persisted: u64) {
        *self.finalized.lock().unwrap() = Some(finalized);
        *self.persisted.lock().unwrap() = Some(persisted);
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
        Some(self.canonical.lock().unwrap().get(&number)?.0)
    }
    fn transactions(&self, number: u64) -> Option<Vec<B256>> {
        self.reads.lock().unwrap().push(number);
        Some(self.canonical.lock().unwrap().get(&number)?.1.clone())
    }
}

/// Heights 0..=4 canonical and final; the runtime attached to `chain`.
fn runtime(chain: &Arc<Chain>) -> PolicyRuntime {
    for number in 0..=4 {
        chain.block(number, B256::repeat_byte(100 + number as u8), Vec::new());
    }
    chain.set(4, 4);
    let archive = ArtifactStore::open_with(Path::new("/state"), MemoryStorage::new()).unwrap();
    let runtime = PolicyRuntime::new(verifier(), Arc::new(archive), 16);
    runtime
        .accept_facts("snapshot", &seal("snapshot", &snapshot()), AT)
        .unwrap();
    runtime.attach_chain(chain.clone());
    runtime
}

fn live(runtime: &PolicyRuntime) -> bool {
    runtime
        .identities
        .lookup(&ExecutionBinding::Transaction(TX), AT)
        .is_ok()
}

fn block(number: u64, hash: u8) -> BlockDescriptor {
    BlockDescriptor {
        number,
        hash: B256::repeat_byte(hash),
        ..descriptor(vec![TX])
    }
}

#[test]
fn identity_released_at_finality_not_inclusion() {
    let chain = Arc::new(Chain::default());
    let runtime = runtime(&chain);
    runtime
        .accept_identity(&seal("identity", &identity(TX, "ctx-a")), AT)
        .unwrap();
    let candidate = runtime.pin_candidate(AT).unwrap();
    assert!(execute(&candidate, TX));
    runtime.persist(&candidate, &block(5, 50)).unwrap();
    chain.block(5, B256::repeat_byte(50), vec![TX]);
    chain.block(6, B256::repeat_byte(60), Vec::new());
    // Included and canonical, not final: kept.
    chain.set(4, 6);
    runtime.maintain(AT).unwrap();
    assert!(live(&runtime), "released at inclusion");
    // Final by forkchoice but not yet written by Reth: kept.
    chain.set(6, 4);
    runtime.maintain(AT).unwrap();
    assert!(live(&runtime), "released before the block was written");
    // Final and written: released by the node itself, without any status poll.
    chain.set(6, 6);
    runtime.maintain(AT).unwrap();
    assert!(!live(&runtime), "not released at finality");
    assert_eq!(runtime.identities.occupancy().unwrap(), 0);
}

#[test]
fn reorg_before_finality_reexecutes_without_ops() {
    let chain = Arc::new(Chain::default());
    let runtime = runtime(&chain);
    runtime
        .accept_identity(&seal("identity", &identity(TX, "ctx-a")), AT)
        .unwrap();
    let candidate = runtime.pin_candidate(AT).unwrap();
    assert!(execute(&candidate, TX));
    runtime.persist(&candidate, &block(5, 50)).unwrap();
    chain.block(5, B256::repeat_byte(50), vec![TX]);
    chain.set(4, 5);
    runtime.maintain(AT).unwrap();
    // A reorganization replaces block 5 with one without the transaction.
    chain.block(5, B256::repeat_byte(51), Vec::new());
    chain.set(5, 5);
    runtime.maintain(AT).unwrap();
    assert!(
        live(&runtime),
        "a reorg before finality dropped the identity"
    );
    // Back in the pool, it executes again in the next candidate with no
    // resubmission from OPS.
    let next = runtime.pin_candidate(AT).unwrap();
    execute_result(&next, TX).expect("the reorganized transaction could not execute again");
    runtime.persist(&next, &block(6, 60)).unwrap();
    chain.block(6, B256::repeat_byte(60), vec![TX]);
    chain.set(6, 6);
    runtime.maintain(AT).unwrap();
    assert!(!live(&runtime));
}

#[test]
fn finality_reported_only_up_to_persisted_height() {
    let chain = Arc::new(Chain::default());
    let runtime = runtime(&chain);
    for number in 5..=10 {
        chain.block(number, B256::repeat_byte(number as u8), Vec::new());
    }
    chain.set(10, 7);
    assert_eq!(
        runtime.effective_finality(),
        Some((7, B256::repeat_byte(7)))
    );
    let evidence = runtime.finality_evidence(7).unwrap();
    assert_eq!(evidence.finalized_number, 7);
    assert_eq!(evidence.canonical_at_inclusion, B256::repeat_byte(7));
    // A lower later reading (an unwind of written blocks) never takes it back.
    chain.set(10, 5);
    assert_eq!(runtime.effective_finality().unwrap().0, 7);
    // Unknown finality proves nothing new.
    chain.set(10, 10);
    *chain.finalized.lock().unwrap() = None;
    assert_eq!(runtime.effective_finality().unwrap().0, 7);
    chain.set(10, 10);
    assert_eq!(runtime.effective_finality().unwrap().0, 10);
    // Unknown persistence: nothing beyond what was already reported.
    *chain.persisted.lock().unwrap() = None;
    assert_eq!(runtime.effective_finality().unwrap().0, 10);
}

#[test]
fn no_block_is_published_at_or_below_finality() {
    let chain = Arc::new(Chain::default());
    let runtime = runtime(&chain);
    runtime.maintain(AT).unwrap();
    let candidate = runtime.pin_candidate(AT).unwrap();
    let empty = |number: u64| BlockDescriptor {
        transactions: Vec::new(),
        ..block(number, 70 + number as u8)
    };
    for number in [3, 4] {
        let refused = runtime.persist(&candidate, &empty(number)).unwrap_err();
        assert!(refused.contains("finalized"), "block {number}: {refused}");
    }
    runtime.persist(&candidate, &empty(5)).unwrap();
}

#[test]
fn stale_finality_is_no_evidence_after_a_reorganization_below_it() {
    let chain = Arc::new(Chain::default());
    let runtime = runtime(&chain);
    assert!(runtime.finality_evidence(3).is_some());
    // The finalized block is replaced (consensus reorganized below finality):
    // the remembered height is kept, but proves nothing about the new chain.
    chain.block(4, B256::repeat_byte(44), Vec::new());
    assert_eq!(runtime.effective_finality().unwrap().0, 4);
    assert!(runtime.finality_evidence(3).is_none());
}

#[test]
fn release_scans_only_heights_finalized_since_attach() {
    // Attached when 0..=4 are final: those heights are never read (the
    // registry started empty), only newly final ones, each once.
    let chain = Arc::new(Chain::default());
    let runtime = runtime(&chain);
    chain.block(5, B256::repeat_byte(5), Vec::new());
    chain.block(6, B256::repeat_byte(6), Vec::new());
    chain.set(6, 6);
    runtime.maintain(AT).unwrap();
    runtime.maintain(AT).unwrap();
    assert_eq!(chain.reads.lock().unwrap().as_slice(), [5, 6]);
}
