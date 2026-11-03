//! Self-import of the node's own produced blocks (plan P6): importing a block
//! this process just published reuses its verified facts and identities
//! instead of reading and re-verifying its manifest; forensic replay always
//! reads the evidence.

use alloy_primitives::{B256, U256};
use common::{
    MemoryStorage,
    fixture::{AT, descriptor, execute, execute_result, identity, seal, snapshot, verifier},
};
use ops_reth_policy::{
    archive::{ArtifactStore, BlockDescriptor},
    runtime::PolicyRuntime,
};
use std::{path::Path, sync::Arc, time::Instant};

mod common;

fn tx(index: u64) -> B256 {
    B256::from(U256::from(index + 1))
}

fn runtime(storage: &Arc<MemoryStorage>, capacity: usize) -> PolicyRuntime {
    let archive = ArtifactStore::open_with(Path::new("/state"), storage.clone()).unwrap();
    let runtime = PolicyRuntime::open(verifier(), Arc::new(archive), capacity, AT).unwrap();
    runtime
        .accept_facts("snapshot", &seal("snapshot", &snapshot()), AT)
        .unwrap();
    runtime
}

fn admit(runtime: &PolicyRuntime, count: u64, context: &str, issued: i64) {
    for index in 0..count {
        let mut identity = identity(tx(index), &format!("{context}-{index}"));
        identity["issued_at"] = issued.into();
        runtime
            .accept_identity(&seal("identity", &identity), AT)
            .unwrap();
    }
}

/// Build and publish block `number` with transactions 0..count.
fn produce(runtime: &PolicyRuntime, number: u64, count: u64) -> BlockDescriptor {
    let candidate = runtime.pin_candidate(AT).unwrap();
    for index in 0..count {
        assert!(execute(&candidate, tx(index)));
    }
    let block = BlockDescriptor {
        number,
        hash: B256::from(U256::from(1_000 + number)),
        ..descriptor((0..count).map(tx).collect())
    };
    runtime.persist(&candidate, &block).unwrap();
    block
}

#[test]
fn own_block_imports_from_memory_without_reading_or_verifying() {
    let storage = MemoryStorage::new();
    let runtime = runtime(&storage, 64);
    admit(&runtime, 8, "ctx", 1800000000);
    let block = produce(&runtime, 1, 8);
    let (before, verified) = (
        storage.counts(),
        runtime.verifier().signature_verifications(),
    );
    let import = runtime.self_import(&block).unwrap();
    assert_eq!(
        storage.counts() - before,
        Default::default(),
        "self-import read the archive"
    );
    assert_eq!(
        runtime.verifier().signature_verifications(),
        verified,
        "self-import verified again"
    );
    for index in 0..8 {
        assert!(execute(&import, tx(index)), "transaction {index}");
    }
    // Bound to the block's own transactions and their recorded outcomes.
    assert!(execute_result(&import, tx(99)).is_err());
    // Used once: a second import reads the manifest, as forensic replay always does.
    let before = storage.counts();
    let again = runtime.self_import(&block).unwrap();
    assert!((storage.counts() - before).reads > 0);
    assert!(execute(&again, tx(0)));
    let before = storage.counts();
    runtime.replay(&block).unwrap();
    assert!(
        (storage.counts() - before).reads > 0,
        "forensic replay used memory"
    );
}

#[test]
fn another_block_body_or_hash_never_uses_the_cached_execution() {
    let storage = MemoryStorage::new();
    let runtime = runtime(&storage, 64);
    admit(&runtime, 4, "ctx", 1800000000);
    let block = produce(&runtime, 1, 4);
    let mut reordered = block.clone();
    reordered.transactions.reverse();
    assert!(runtime.self_import(&reordered).is_err());
    let mut rival = block.clone();
    rival.hash = B256::repeat_byte(77);
    assert!(
        runtime
            .self_import(&rival)
            .unwrap_err()
            .contains("manifest")
    );
    let mut other_network = block.clone();
    other_network.network.deployment_id = "another".into();
    assert!(runtime.self_import(&other_network).is_err());
    // The exact block still imports from memory.
    let before = storage.counts();
    runtime.self_import(&block).unwrap();
    assert_eq!((storage.counts() - before).reads, 0);
}

#[test]
fn a_rebuild_that_kept_earlier_evidence_imports_that_evidence() {
    let storage = MemoryStorage::new();
    let runtime = runtime(&storage, 64);
    admit(&runtime, 1, "ctx-a", 1800000000);
    let block = produce(&runtime, 1, 1);
    // A renewal, then another build of the same block: the archive keeps the
    // first evidence (an equivalent manifest exists), so must the import.
    admit(&runtime, 1, "ctx-renewed", 1800000005);
    produce(&runtime, 1, 1);
    let import = runtime.self_import(&block).unwrap();
    assert_eq!(import.identity_context(tx(0)).as_deref(), Some("ctx-a-0"));
    let replay = runtime.replay(&block).unwrap();
    assert_eq!(replay.identity_context(tx(0)).as_deref(), Some("ctx-a-0"));
}

#[test]
fn the_cache_is_bounded() {
    let storage = MemoryStorage::new();
    let runtime = runtime(&storage, 64);
    admit(&runtime, 1, "ctx", 1800000000);
    let blocks: Vec<_> = (1..=10)
        .map(|number| produce(&runtime, number, 1))
        .collect();
    let before = storage.counts();
    runtime.self_import(&blocks[0]).unwrap();
    assert!(
        (storage.counts() - before).reads > 0,
        "the oldest block stayed cached"
    );
    let before = storage.counts();
    runtime.self_import(&blocks[9]).unwrap();
    assert_eq!((storage.counts() - before).reads, 0);
}

#[test]
fn at_or_below_finality_the_archive_decides() {
    use ops_reth_policy::chain::ChainState;
    #[derive(Debug)]
    struct Final(B256);
    impl ChainState for Final {
        fn finalized(&self) -> Option<(u64, B256)> {
            Some((1, self.0))
        }
        fn persisted(&self) -> Option<u64> {
            Some(1)
        }
        fn canonical_hash(&self, number: u64) -> Option<B256> {
            (number == 1).then_some(self.0)
        }
        fn transactions(&self, _number: u64) -> Option<Vec<B256>> {
            Some(Vec::new())
        }
    }
    let storage = MemoryStorage::new();
    let runtime = runtime(&storage, 64);
    admit(&runtime, 1, "ctx", 1800000000);
    let block = produce(&runtime, 1, 1);
    runtime.attach_chain(Arc::new(Final(block.hash)));
    let before = storage.counts();
    runtime.self_import(&block).unwrap();
    assert!(
        (storage.counts() - before).reads > 0,
        "a final block imported from memory"
    );
}

/// Microbenchmark (not run by default): import of a 2,000-transaction block
/// from the manifest versus from memory.
#[test]
#[ignore]
fn self_import_cost() {
    let storage = MemoryStorage::new();
    let runtime = runtime(&storage, 4096);
    admit(&runtime, 2000, "ctx", 1800000000);
    let block = produce(&runtime, 1, 2000);
    let started = Instant::now();
    runtime.self_import(&block).unwrap();
    let cached = started.elapsed();
    let started = Instant::now();
    runtime.replay(&block).unwrap();
    let from_manifest = started.elapsed();
    println!(
        "import of 2000 transactions: from the manifest {from_manifest:?}, from memory {cached:?}"
    );
}
