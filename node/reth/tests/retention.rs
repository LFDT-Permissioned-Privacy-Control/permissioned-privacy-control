//! Manifest retention, compaction and fact-record collection (plan T27).

use alloy_primitives::{B256, U256};
use common::{
    Action, MemoryStorage, Op,
    fixture::{AT, descriptor, seal, snapshot, verifier},
};
use ops_reth_policy::{
    archive::{ArtifactStore, BlockDescriptor, Retention},
    chain::ChainState,
    manifest::BlockManifest,
    runtime::PolicyRuntime,
};
use std::{
    collections::HashMap,
    path::Path,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};

mod common;

const ROOT: &str = "/state";

#[derive(Debug, Default)]
struct Chain {
    final_height: Mutex<Option<u64>>,
    canonical: Mutex<HashMap<u64, B256>>,
}

impl Chain {
    fn finalize(&self, height: u64) {
        *self.final_height.lock().unwrap() = Some(height);
    }
}

impl ChainState for Chain {
    fn finalized(&self) -> Option<(u64, B256)> {
        let height = (*self.final_height.lock().unwrap())?;
        Some((height, self.canonical_hash(height)?))
    }
    fn persisted(&self) -> Option<u64> {
        *self.final_height.lock().unwrap()
    }
    fn canonical_hash(&self, number: u64) -> Option<B256> {
        self.canonical.lock().unwrap().get(&number).copied()
    }
    fn transactions(&self, _number: u64) -> Option<Vec<B256>> {
        Some(Vec::new())
    }
}

fn hash(number: u64, build: u64) -> B256 {
    B256::from(U256::from(number * 1_000 + build))
}

fn block(number: u64, build: u64, timestamp: i64) -> BlockDescriptor {
    BlockDescriptor {
        number,
        hash: hash(number, build),
        timestamp: timestamp as u64,
        ..descriptor(Vec::new())
    }
}

struct Node {
    storage: Arc<MemoryStorage>,
    chain: Arc<Chain>,
    runtime: PolicyRuntime,
}

impl Node {
    fn new(retention: Retention) -> Self {
        let storage = MemoryStorage::new();
        let chain = Arc::new(Chain::default());
        let runtime = Self::open(&storage, &chain, retention);
        runtime
            .accept_facts("snapshot", &seal("snapshot", &snapshot()), AT)
            .unwrap();
        Self {
            storage,
            chain,
            runtime,
        }
    }

    fn open(
        storage: &Arc<MemoryStorage>,
        chain: &Arc<Chain>,
        retention: Retention,
    ) -> PolicyRuntime {
        let archive = ArtifactStore::open_with(Path::new(ROOT), storage.clone()).unwrap();
        let runtime = PolicyRuntime::open(verifier(), Arc::new(archive), 16, AT)
            .unwrap()
            .with_retention(retention);
        runtime.attach_chain(chain.clone());
        runtime
    }

    /// Publish canonical empty blocks `heights` at `timestamp`.
    fn produce(&self, heights: impl IntoIterator<Item = u64>, timestamp: i64) {
        for number in heights {
            self.build(number, 0, timestamp);
            self.chain
                .canonical
                .lock()
                .unwrap()
                .insert(number, hash(number, 0));
        }
    }

    /// Publish build `build` of height `number` (canonical only if marked).
    fn build(&self, number: u64, build: u64, timestamp: i64) {
        let candidate = self.runtime.pin_candidate(timestamp).unwrap();
        self.runtime
            .persist(&candidate, &block(number, build, timestamp))
            .unwrap();
    }

    /// Maintain until nothing is pending; the number of runs.
    fn settle(&self, now: i64) -> usize {
        for runs in 1..=64 {
            if !self.runtime.maintain(now).unwrap().pending {
                return runs;
            }
        }
        panic!("maintenance never settled");
    }

    fn manifest(&self, number: u64, build: u64) -> Option<BlockManifest> {
        self.runtime
            .archive
            .manifest(number, hash(number, build))
            .unwrap()
    }

    fn names(&self, directory: &str) -> Vec<String> {
        let root = Path::new(ROOT).join(directory);
        self.storage
            .names(&root)
            .into_iter()
            .flat_map(|bucket| self.storage.names(&root.join(bucket)))
            .collect()
    }

    fn snapshot(&self, version: u64) {
        let mut next = snapshot();
        next["version"] = version.into();
        self.runtime
            .accept_facts("snapshot", &seal("snapshot", &next), AT)
            .unwrap();
    }
}

/// Fact versions of the stored records or lists (`facts` or `lists`).
fn versions(node: &Node, area: &str) -> Vec<u64> {
    let mut found: Vec<u64> = node
        .names(area)
        .iter()
        .map(|name| u64::from_str_radix(&name[..16], 16).unwrap())
        .collect();
    found.sort_unstable();
    found
}

#[test]
fn prune_removes_manifests_after_retention_and_unreachable_records() {
    let node = Node::new(Retention::Seconds(100));
    node.produce(1..=300, AT);
    node.chain.finalize(300);
    node.settle(AT);
    node.snapshot(2);
    node.produce(301..=600, AT + 40);
    node.chain.finalize(600);
    node.settle(AT + 40);
    let blocks = node.names("blocks");
    assert!(
        blocks.iter().all(|name| name.starts_with("s-")),
        "finalized canonical manifests were not compacted: {blocks:?}"
    );
    assert_eq!(blocks.len(), 2, "{blocks:?}");
    assert!(node.manifest(1, 0).is_some() && node.manifest(600, 0).is_some());
    assert_eq!(versions(&node, "lists"), [1, 2]);

    // Blocks 1..=300 (at AT) are past the retention, 301..=600 are not.
    node.settle(AT + 120);
    assert!(node.manifest(1, 0).is_none() && node.manifest(300, 0).is_none());
    assert!(node.manifest(301, 0).is_some() && node.manifest(600, 0).is_some());
    assert_eq!(
        versions(&node, "lists"),
        [2],
        "unreachable record list kept"
    );
    assert_eq!(versions(&node, "facts"), [2], "unreachable record kept");
    // Retained evidence still replays.
    node.runtime.replay(&block(450, 0, AT + 40)).unwrap();
}

/// Delta `version` on top of the installed facts with `digest` (no rows).
fn delta(version: u64, digest: &str) -> serde_json::Value {
    serde_json::json!({"network":common::fixture::network(),"issued_at":1800000000,"expires_at":1800000060,
    "previous_version":version - 1,"previous_digest":digest,"version":version,
    "upserts":{"principals":[],"groups":[],"contracts":[],"policies":[],"sanctions":[]},
    "deletes":{"principals":[],"groups":[],"contracts":[],"policies":[],"sanctions":[]}})
}

fn digest_of(payload: &serde_json::Value) -> String {
    use sha2::Digest;
    alloy_primitives::hex::encode(sha2::Sha256::digest(serde_json::to_vec(payload).unwrap()))
}

#[test]
fn a_delta_chain_keeps_every_list_its_retained_blocks_reach() {
    let node = Node::new(Retention::Seconds(100));
    let mut digest = digest_of(&snapshot());
    // Blocks on v1, v2 and v3 at AT (pruned later), on v4 at AT + 40 (kept).
    for (version, heights, at) in [
        (1, 1..=300, AT),
        (2, 301..=600, AT),
        (3, 601..=900, AT),
        (4, 901..=1200, AT + 40),
    ] {
        if version > 1 {
            let next = delta(version, &digest);
            node.runtime
                .accept_facts("delta", &seal("delta", &next), AT)
                .unwrap();
            digest = digest_of(&next);
        }
        let last = *heights.end();
        node.produce(heights, at);
        // Compacted per group, so each group's segment has its own age.
        node.chain.finalize(last);
        node.settle(at);
    }
    node.settle(AT + 120);
    assert!(node.manifest(900, 0).is_none() && node.manifest(901, 0).is_some());
    // The retained blocks (facts 4) reach every list back to the snapshot.
    assert_eq!(versions(&node, "lists"), [1, 2, 3, 4]);
    assert_eq!(versions(&node, "facts"), [1, 2, 3, 4]);
    node.runtime.replay(&block(1000, 0, AT + 40)).unwrap();
    // What a restart restores: the head's chain, read back from disk.
    let (version, head) = node.runtime.archive.head().unwrap().unwrap();
    let restored = ops_reth_policy::stream::FactStream::restore(
        verifier(),
        &node.runtime.archive,
        version,
        head,
        AT,
    )
    .unwrap();
    assert_eq!(restored.latest().unwrap().unwrap().version(), 4);
    // A newer snapshot, then pruning the delta chain's blocks: its lists and
    // records go.
    node.snapshot(10);
    node.produce(1201..=1500, AT + 40);
    node.chain.finalize(1500);
    node.settle(AT + 200);
    assert!(node.manifest(1200, 0).is_none());
    assert_eq!(versions(&node, "lists"), [10]);
    assert_eq!(versions(&node, "facts"), [10]);
}

#[test]
fn pinned_old_facts_build_keeps_records() {
    let node = Node::new(Retention::Seconds(100));
    node.produce(1..=300, AT);
    node.chain.finalize(300);
    node.settle(AT);
    // A candidate pinned on version 1 is still building...
    let pinned = node.runtime.pin_candidate(AT + 30).unwrap();
    node.snapshot(2);
    node.produce(301..=600, AT + 40);
    node.chain.finalize(600);
    node.settle(AT + 120);
    assert!(
        node.manifest(1, 0).is_none(),
        "the old segment was not pruned"
    );
    assert!(
        versions(&node, "facts").contains(&1),
        "a pinned candidate's records were collected"
    );
    // ...and publishes its block, which replays.
    node.runtime
        .persist(&pinned, &block(601, 0, AT + 30))
        .unwrap();
    drop(pinned);
    node.runtime.replay(&block(601, 0, AT + 30)).unwrap();
}

#[test]
fn parent_record_list_survives_parent_prune() {
    // Every block on unchanged facts names the same record list: pruning the
    // older blocks must keep it for the newer ones.
    let node = Node::new(Retention::Seconds(100));
    node.produce(1..=300, AT);
    node.chain.finalize(300);
    node.settle(AT);
    node.produce(301..=600, AT + 40);
    node.chain.finalize(600);
    node.settle(AT + 120);
    assert!(node.manifest(1, 0).is_none());
    assert_eq!(versions(&node, "lists"), [1]);
    node.runtime.replay(&block(400, 0, AT + 40)).unwrap();
}

#[test]
fn repeated_discarded_payloads_are_reclaimed_below_finalized() {
    let node = Node::new(Retention::Forever);
    for build in 1..=5 {
        node.build(10, build, AT);
    }
    node.produce([9, 10], AT);
    node.chain.finalize(9);
    node.settle(AT);
    assert_eq!(node.runtime.effective_finality().unwrap().0, 9);
    assert_eq!(node.names("blocks").len(), 7, "removed above finality");
    node.chain.finalize(10);
    node.settle(AT);
    for build in 1..=5 {
        assert!(
            node.manifest(10, build).is_none(),
            "discarded build {build} kept"
        );
    }
    assert!(node.manifest(10, 0).is_some());
    assert_eq!(node.names("blocks").len(), 2);
}

#[test]
fn prune_run_is_bounded() {
    use ops_reth_policy::archive::RUN_REMOVALS;
    let node = Node::new(Retention::Forever);
    let rivals = RUN_REMOVALS as u64 + 100;
    for number in 1..=rivals {
        node.build(number, 1, AT);
    }
    node.produce(1..=rivals, AT);
    node.chain.finalize(rivals);
    let first = node.runtime.maintain(AT).unwrap();
    assert!(first.pending, "{first:?}");
    assert!(first.removed() <= RUN_REMOVALS, "{first:?}");
    node.settle(AT);
    assert!((1..=rivals).all(|number| node.manifest(number, 1).is_none()));
    assert!((1..=rivals).all(|number| node.manifest(number, 0).is_some()));
}

#[test]
fn forever_never_prunes_canonical() {
    let node = Node::new(Retention::Forever);
    node.produce(1..=300, AT);
    node.chain.finalize(300);
    node.settle(AT + 10 * 365 * 86_400);
    assert!((1..=300).all(|number| node.manifest(number, 0).is_some()));
    assert_eq!(versions(&node, "lists"), [1]);
}

#[test]
fn segment_lookup_reads_footer_index_and_one_entry() {
    let node = Node::new(Retention::Forever);
    node.produce(1..=300, AT);
    node.chain.finalize(300);
    node.settle(AT);
    let segment = node.names("blocks");
    let [segment] = segment.as_slice() else {
        panic!("{segment:?}");
    };
    let size = node.storage.tree()[&Path::new(ROOT).join("blocks/00000000")][segment].len() as u64;
    let before = node.storage.counts();
    node.manifest(150, 0).unwrap();
    let read = (node.storage.counts() - before).read_bytes;
    // Footer + 300 index rows + one small entry, never the whole segment.
    assert!(read < 300 * 140 + 52 + 1024, "read {read} of {size} bytes");
    assert!(read < size, "read {read} of {size} bytes");
}

/// The compaction of a complete bucket with six canonical blocks and one
/// discarded build, crashing after each storage operation in turn: after a
/// restart every canonical block is found exactly and the discarded build is
/// never resurrected.
#[test]
fn crash_at_each_segment_publication_step_recovers_with_exact_lookups() {
    let heights = 4090..=4095u64;
    let setup = || {
        let node = Node::new(Retention::Forever);
        node.produce(heights.clone(), AT);
        node.build(4093, 1, AT);
        let expected: Vec<_> = heights
            .clone()
            .map(|number| node.manifest(number, 0).unwrap())
            .collect();
        (node, expected)
    };
    let mut step = 0;
    loop {
        let (node, expected) = setup();
        node.chain.finalize(4095);
        let seen = Arc::new(AtomicUsize::new(0));
        node.storage.set_hook({
            let seen = seen.clone();
            move |op, _| {
                if matches!(op, Op::Read | Op::List) {
                    return Action::Proceed;
                }
                if seen.fetch_add(1, Ordering::SeqCst) == step {
                    Action::CrashAfter
                } else {
                    Action::Proceed
                }
            }
        });
        let _ = node.runtime.maintain(AT);
        node.storage.clear_hook();
        if seen.load(Ordering::SeqCst) <= step {
            // Past the last storage operation: the sweep is complete.
            assert!(step > 3, "compaction used only {step} operations");
            break;
        }
        let Node {
            storage,
            chain,
            runtime,
        } = node;
        drop(runtime);
        storage.crash();
        storage.restart();
        let reopened = Node {
            runtime: Node::open(&storage, &chain, Retention::Forever),
            storage,
            chain,
        };
        reopened.settle(AT);
        for (number, manifest) in heights.clone().zip(&expected) {
            assert_eq!(
                reopened.manifest(number, 0).as_ref(),
                Some(manifest),
                "step {step}: block {number}"
            );
        }
        assert!(
            reopened.manifest(4093, 1).is_none(),
            "step {step}: discarded build"
        );
        let names = reopened.names("blocks");
        assert_eq!(names.len(), 1, "step {step}: {names:?}");
        step += 1;
    }
}

#[test]
fn retention_setting_accepts_forever_and_whole_durations() {
    assert_eq!(Retention::parse("forever"), Ok(Retention::Forever));
    assert_eq!(Retention::parse("7d"), Ok(Retention::Seconds(7 * 86_400)));
    assert_eq!(Retention::parse("36h"), Ok(Retention::Seconds(36 * 3600)));
    assert_eq!(Retention::parse("90m"), Ok(Retention::Seconds(5400)));
    assert_eq!(Retention::parse("3600s"), Ok(Retention::Seconds(3600)));
    assert_eq!(Retention::default(), Retention::Seconds(7 * 86_400));
    for invalid in [
        "",
        "0d",
        "600s",
        "59m",
        "d",
        "7",
        "7w",
        "-1d",
        "1.5d",
        "7 d",
        "999999999999999999d",
        "é",
    ] {
        assert!(Retention::parse(invalid).is_err(), "{invalid:?} accepted");
    }
}

#[test]
fn an_earlier_layout_is_refused() {
    // Layout 3 held record lists naming every record of their chain.
    for earlier in [
        &b"ops-node-policy-archive 2\n"[..],
        b"ops-node-policy-archive 3\n",
    ] {
        let storage = MemoryStorage::new();
        storage.plant(&Path::new(ROOT).join("LAYOUT"), earlier);
        let error = ArtifactStore::open_with(Path::new(ROOT), storage).unwrap_err();
        assert!(error.contains("empty directory"), "{error}");
    }
}

#[test]
fn a_retained_segment_alone_keeps_its_older_facts() {
    // Blocks 301..=600 still use version 1 and are retained; the installed
    // facts are version 2. Only their segment keeps list and record 1.
    let node = Node::new(Retention::Seconds(100));
    node.produce(1..=300, AT);
    node.chain.finalize(300);
    node.settle(AT);
    node.produce(301..=600, AT + 40);
    node.chain.finalize(600);
    node.settle(AT + 40);
    node.snapshot(2);
    node.produce(601..=900, AT + 40);
    node.chain.finalize(900);
    node.settle(AT + 120);
    assert!(
        node.manifest(1, 0).is_none(),
        "the oldest segment was not pruned"
    );
    assert_eq!(versions(&node, "lists"), [1, 2]);
    assert_eq!(versions(&node, "facts"), [1, 2]);
    node.runtime.replay(&block(450, 0, AT + 40)).unwrap();
}

#[test]
fn an_unfinalized_block_file_alone_keeps_its_older_facts() {
    let node = Node::new(Retention::Seconds(100));
    node.produce(1..=300, AT);
    node.chain.finalize(300);
    node.settle(AT);
    // Above finality, on version 1, not compacted.
    node.produce(301..=310, AT + 40);
    node.snapshot(2);
    node.settle(AT + 120);
    assert!(node.manifest(1, 0).is_none());
    assert_eq!(versions(&node, "lists"), [1, 2]);
    assert_eq!(versions(&node, "facts"), [1, 2]);
    node.runtime.replay(&block(305, 0, AT + 40)).unwrap();
}

/// Crash after each storage operation of a prune and collection: after a
/// restart the installed facts restore and retained blocks replay.
#[test]
fn crash_during_collection_keeps_the_head_and_retained_evidence() {
    let setup = || {
        let node = Node::new(Retention::Seconds(100));
        node.produce(1..=300, AT);
        node.chain.finalize(300);
        node.settle(AT);
        node.snapshot(2);
        node.produce(301..=600, AT + 40);
        node.chain.finalize(600);
        node.settle(AT + 40);
        node
    };
    let mut step = 0;
    loop {
        let node = setup();
        let seen = Arc::new(AtomicUsize::new(0));
        node.storage.set_hook({
            let seen = seen.clone();
            move |op, _| {
                if matches!(op, Op::Read | Op::List) {
                    return Action::Proceed;
                }
                if seen.fetch_add(1, Ordering::SeqCst) == step {
                    Action::CrashAfter
                } else {
                    Action::Proceed
                }
            }
        });
        let _ = node.runtime.maintain(AT + 120);
        node.storage.clear_hook();
        if seen.load(Ordering::SeqCst) <= step {
            assert!(step > 3, "pruning used only {step} operations");
            break;
        }
        let Node {
            storage,
            chain,
            runtime,
        } = node;
        drop(runtime);
        storage.crash();
        storage.restart();
        let reopened = Node {
            runtime: Node::open(&storage, &chain, Retention::Seconds(100)),
            storage,
            chain,
        };
        assert_eq!(
            reopened.runtime.feed.latest().unwrap().unwrap().version(),
            2,
            "step {step}: installed facts lost"
        );
        reopened.settle(AT + 120);
        reopened
            .runtime
            .replay(&block(450, 0, AT + 40))
            .unwrap_or_else(|error| panic!("step {step}: {error}"));
        assert_eq!(versions(&reopened, "lists"), [2], "step {step}");
        step += 1;
    }
}
