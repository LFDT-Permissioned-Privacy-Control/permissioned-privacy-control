//! Trusted finalized history (plan T26, decision D1): a block imported as a
//! canonical ancestor of the known finalized block runs without policy and
//! needs no manifest; every other import needs its manifest (fail-closed).

use alloy_primitives::B256;
use common::{
    MemoryStorage,
    fixture::{AT, descriptor, execute_with, seal, snapshot, verifier},
};
use ops_reth_policy::{
    archive::ArtifactStore,
    runtime::{ChainView, FinalityView, ImportExecution, ImportOrigin, PolicyRuntime},
};
use std::{
    collections::HashMap,
    path::Path,
    sync::{Arc, Mutex},
};

mod common;

#[derive(Debug, Default)]
struct View {
    finalized: Mutex<Option<(u64, B256)>>,
    best: u64,
    canonical: HashMap<u64, B256>,
}

impl FinalityView for View {
    fn chain_view(&self, number: u64) -> Option<ChainView> {
        let finalized = (*self.finalized.lock().unwrap())?;
        Some(ChainView {
            finalized,
            best: self.best,
            canonical_at_block: self.canonical.get(&number).copied(),
            canonical_at_finalized: self.canonical.get(&finalized.0).copied(),
        })
    }
}

fn runtime() -> PolicyRuntime {
    let archive = ArtifactStore::open_with(Path::new("/state"), MemoryStorage::new()).unwrap();
    let runtime = PolicyRuntime::new(verifier(), Arc::new(archive), 16);
    runtime
        .accept_facts("snapshot", &seal("snapshot", &snapshot()), AT)
        .unwrap();
    runtime
}

const TX: B256 = B256::repeat_byte(1);

/// Block 1 (`descriptor`) below a finalized block 3, all canonical.
fn view() -> View {
    let block = descriptor(vec![TX]);
    View {
        finalized: Mutex::new(Some((3, B256::repeat_byte(33)))),
        best: 4,
        canonical: HashMap::from([(1, block.hash), (3, B256::repeat_byte(33))]),
    }
}

#[test]
fn finalized_ancestor_without_manifest_imports_with_pass_through_policy() {
    let runtime = runtime();
    let block = descriptor(vec![TX]);
    let import = runtime
        .import(&block, ImportOrigin::Block, &view())
        .expect("a finalized canonical ancestor needs no manifest");
    assert!(matches!(import, ImportExecution::TrustedFinalized(_)));
    // No identity was ever admitted: the block's own transaction executes
    // unchecked, anything else is still denied.
    assert!(execute_with(import.factory(), Some(TX)).is_ok());
    let foreign = execute_with(import.factory(), Some(B256::repeat_byte(2))).unwrap_err();
    assert!(foreign.contains("not in the trusted block"), "{foreign}");
    assert!(
        execute_with(import.factory(), None).is_err(),
        "unbound transaction ran unchecked"
    );
}

#[test]
fn every_other_import_needs_its_manifest() {
    let runtime = runtime();
    let block = descriptor(vec![TX]);
    let mut cases: Vec<(&str, View, ImportOrigin)> = Vec::new();
    let unknown = view();
    *unknown.finalized.lock().unwrap() = None;
    cases.push(("unknown finality", unknown, ImportOrigin::Block));
    let mut rival = view();
    rival.canonical.insert(1, B256::repeat_byte(77));
    cases.push(("same-height rival is canonical", rival, ImportOrigin::Block));
    let mut not_canonical = view();
    not_canonical.canonical.insert(3, B256::repeat_byte(78));
    cases.push((
        "finalized hash not canonical (a prospective forkchoice declaration)",
        not_canonical,
        ImportOrigin::Block,
    ));
    let mut below = view();
    below.canonical.remove(&1);
    cases.push((
        "below finality but not on the canonical chain",
        below,
        ImportOrigin::Block,
    ));
    let mut ahead = view();
    ahead.best = 2;
    cases.push(("finalized above the best block", ahead, ImportOrigin::Block));
    let mut above = view();
    *above.finalized.lock().unwrap() = Some((0, B256::repeat_byte(30)));
    above.canonical.insert(0, B256::repeat_byte(30));
    cases.push(("block above finality", above, ImportOrigin::Block));
    cases.push(("incoming payload", view(), ImportOrigin::Payload));
    for (name, view, origin) in cases {
        let error = runtime
            .import(&block, origin, &view)
            .err()
            .unwrap_or_else(|| panic!("{name}: trusted"));
        assert!(error.contains("manifest"), "{name}: {error}");
    }
}

#[test]
fn finality_is_read_at_every_import() {
    let runtime = runtime();
    let block = descriptor(vec![TX]);
    let view = view();
    let finalized = *view.finalized.lock().unwrap();
    *view.finalized.lock().unwrap() = None;
    assert!(runtime.import(&block, ImportOrigin::Block, &view).is_err());
    *view.finalized.lock().unwrap() = finalized;
    assert!(runtime.import(&block, ImportOrigin::Block, &view).is_ok());
}

#[test]
fn another_networks_block_is_never_trusted() {
    let runtime = runtime();
    let mut block = descriptor(vec![TX]);
    block.network.deployment_id = "another-deployment".into();
    assert!(
        runtime
            .import(&block, ImportOrigin::Block, &view())
            .is_err()
    );
}
