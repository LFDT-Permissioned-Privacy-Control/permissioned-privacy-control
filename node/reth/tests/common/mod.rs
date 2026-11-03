//! Shared test storage: an in-memory filesystem model that keeps volatile and
//! durable state apart, so a simulated crash keeps exactly what was synced.
#![allow(dead_code)]

use ops_reth_policy::storage::Storage;
use std::{
    collections::{BTreeMap, HashMap},
    fmt, io,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Op {
    Read,
    List,
    Write,
    Link,
    Rename,
    Remove,
    SyncDir,
}

/// What a hook decides for one operation, before it runs.
pub enum Action {
    Proceed,
    /// Fail this operation with an I/O error; nothing changes.
    Fail,
    /// Run this operation, then crash: every later operation fails until `restart`.
    CrashAfter,
}

type Hook = Arc<dyn Fn(Op, &Path) -> Action + Send + Sync>;

#[derive(Default)]
struct Inode {
    data: Vec<u8>,
    durable: Option<Vec<u8>>,
}

#[derive(Default, Clone)]
struct Directory {
    live: BTreeMap<String, u64>,
    durable: BTreeMap<String, u64>,
}

#[derive(Default)]
struct State {
    inodes: HashMap<u64, Inode>,
    directories: HashMap<PathBuf, Directory>,
    next: u64,
    crashed: bool,
    /// Bumped by every crash and restart. An operation that began before
    /// either (e.g. parked in a hook) must not change state afterwards.
    epoch: u64,
    counts: Counts,
}

#[derive(Default)]
pub struct MemoryStorage {
    state: Mutex<State>,
    hook: Mutex<Option<Hook>>,
    /// Held locks by path, with the epoch they were taken in: a crash or
    /// restart ends the "process", so older locks no longer count.
    locks: Arc<Mutex<HashMap<PathBuf, u64>>>,
}

struct LockGuard {
    locks: Arc<Mutex<HashMap<PathBuf, u64>>>,
    path: PathBuf,
    epoch: u64,
}

impl Drop for LockGuard {
    fn drop(&mut self) {
        let mut locks = self.locks.lock().unwrap();
        if locks.get(&self.path) == Some(&self.epoch) {
            locks.remove(&self.path);
        }
    }
}

impl fmt::Debug for MemoryStorage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MemoryStorage")
    }
}

/// A snapshot of the I/O counters. Every attempted operation counts, whether
/// it succeeds or not; `syncs` counts file plus directory syncs; `others`
/// counts links, renames, removals and locks.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Counts {
    pub writes: u64,
    pub syncs: u64,
    pub reads: u64,
    pub lists: u64,
    pub others: u64,
    /// Bytes returned by whole-file and positional reads.
    pub read_bytes: u64,
}

impl std::ops::Sub for Counts {
    type Output = Counts;
    fn sub(self, other: Counts) -> Counts {
        Counts {
            writes: self.writes - other.writes,
            syncs: self.syncs - other.syncs,
            reads: self.reads - other.reads,
            lists: self.lists - other.lists,
            others: self.others - other.others,
            read_bytes: self.read_bytes - other.read_bytes,
        }
    }
}

fn split(path: &Path) -> io::Result<(PathBuf, String)> {
    let parent = path.parent().ok_or(io::ErrorKind::InvalidInput)?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(io::ErrorKind::InvalidInput)?;
    Ok((parent.to_owned(), name.to_owned()))
}

/// Files in `dir` plus its subdirectories, as `read_dir` would list them.
fn listing(state: &State, dir: &Path) -> Option<Vec<String>> {
    let children: Vec<String> = state
        .directories
        .keys()
        .filter_map(|path| {
            (path.parent() == Some(dir))
                .then(|| path.file_name()?.to_str().map(str::to_owned))
                .flatten()
        })
        .collect();
    let files = state.directories.get(dir);
    if files.is_none() && children.is_empty() {
        return None;
    }
    let mut names: Vec<String> = files
        .map(|d| d.live.keys().cloned().collect())
        .unwrap_or_default();
    names.extend(children);
    names.sort();
    Some(names)
}

fn crashed() -> io::Error {
    io::Error::other("storage crashed")
}

impl MemoryStorage {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Taken under the state lock, so never torn by in-flight operations.
    pub fn counts(&self) -> Counts {
        self.state.lock().unwrap().counts
    }

    pub fn set_hook(&self, hook: impl Fn(Op, &Path) -> Action + Send + Sync + 'static) {
        *self.hook.lock().unwrap() = Some(Arc::new(hook));
    }

    pub fn clear_hook(&self) {
        *self.hook.lock().unwrap() = None;
    }

    /// Simulate power loss now: every later operation fails until `restart`.
    pub fn crash(&self) {
        let mut state = self.state.lock().unwrap();
        state.crashed = true;
        state.epoch += 1;
    }

    /// Come back from a crash with exactly the durable state.
    pub fn restart(&self) {
        let mut state = self.state.lock().unwrap();
        for directory in state.directories.values_mut() {
            directory.live = directory.durable.clone();
        }
        for inode in state.inodes.values_mut() {
            inode.data = inode.durable.clone().unwrap_or_default();
        }
        state.crashed = false;
        state.epoch += 1;
        drop(state);
        self.clear_hook();
    }

    /// Live names in `dir`, files and subdirectories (test inspection, not
    /// counted).
    pub fn names(&self, dir: &Path) -> Vec<String> {
        listing(&self.state.lock().unwrap(), dir).unwrap_or_default()
    }

    /// Every live directory with each entry's live content (test inspection,
    /// not counted).
    pub fn tree(&self) -> BTreeMap<PathBuf, BTreeMap<String, Vec<u8>>> {
        let state = self.state.lock().unwrap();
        state
            .directories
            .iter()
            .map(|(path, directory)| {
                let files = directory
                    .live
                    .iter()
                    .map(|(name, inode)| (name.clone(), state.inodes[inode].data.clone()))
                    .collect();
                (path.clone(), files)
            })
            .collect()
    }

    /// Overwrite a file's live and durable content (test tampering, not counted).
    pub fn tamper(&self, path: &Path, bytes: &[u8]) {
        let (parent, name) = split(path).unwrap();
        let mut state = self.state.lock().unwrap();
        let inode = state.directories[&parent].live[&name];
        let inode = state.inodes.get_mut(&inode).unwrap();
        inode.data = bytes.to_vec();
        inode.durable = Some(bytes.to_vec());
    }

    /// Create a file durably without going through the archive (test fixtures).
    pub fn plant(&self, path: &Path, bytes: &[u8]) {
        let (parent, name) = split(path).unwrap();
        let mut state = self.state.lock().unwrap();
        state.next += 1;
        let inode = state.next;
        state.inodes.insert(
            inode,
            Inode {
                data: bytes.to_vec(),
                durable: Some(bytes.to_vec()),
            },
        );
        let directory = state.directories.entry(parent).or_default();
        directory.live.insert(name.clone(), inode);
        directory.durable.insert(name, inode);
    }

    /// Run one operation: consult the hook (outside the state lock, so a hook
    /// may block), then apply `body` under the lock only if no crash or restart
    /// happened meanwhile. `CrashAfter` crashes whether `body` succeeded or not.
    fn run<T>(
        &self,
        op: Op,
        path: &Path,
        count: impl FnOnce(&mut Counts),
        body: impl FnOnce(&mut State) -> io::Result<T>,
    ) -> io::Result<T> {
        let epoch = {
            let mut state = self.state.lock().unwrap();
            if state.crashed {
                return Err(crashed());
            }
            count(&mut state.counts);
            state.epoch
        };
        let hook = self.hook.lock().unwrap().clone();
        let action = hook.map(|hook| hook(op, path)).unwrap_or(Action::Proceed);
        let mut state = self.state.lock().unwrap();
        if state.crashed || state.epoch != epoch {
            return Err(crashed());
        }
        let result = match action {
            Action::Fail => Err(io::Error::other("injected storage failure")),
            Action::Proceed | Action::CrashAfter => body(&mut state),
        };
        if matches!(action, Action::CrashAfter) {
            state.crashed = true;
            state.epoch += 1;
        }
        result
    }
}

impl Storage for MemoryStorage {
    fn ensure_private_dir(&self, path: &Path) -> io::Result<()> {
        let mut state = self.state.lock().unwrap();
        if state.crashed {
            return Err(crashed());
        }
        state.directories.entry(path.to_owned()).or_default();
        Ok(())
    }

    fn list(&self, dir: &Path) -> io::Result<Vec<String>> {
        self.run(
            Op::List,
            dir,
            |c| c.lists += 1,
            |state| listing(state, dir).ok_or_else(|| io::ErrorKind::NotFound.into()),
        )
    }

    fn read(&self, path: &Path, limit: usize) -> io::Result<Option<Vec<u8>>> {
        let (parent, name) = split(path)?;
        self.run(
            Op::Read,
            path,
            |c| c.reads += 1,
            |state| match state
                .directories
                .get(&parent)
                .and_then(|d| d.live.get(&name))
            {
                None => Ok(None),
                Some(inode) => {
                    let data = state.inodes[inode].data.clone();
                    if data.is_empty() || data.len() > limit {
                        Err(io::ErrorKind::InvalidData.into())
                    } else {
                        state.counts.read_bytes += data.len() as u64;
                        Ok(Some(data))
                    }
                }
            },
        )
    }

    fn size(&self, path: &Path) -> io::Result<Option<u64>> {
        let (parent, name) = split(path)?;
        self.run(
            Op::Read,
            path,
            |c| c.reads += 1,
            |state| {
                Ok(state
                    .directories
                    .get(&parent)
                    .and_then(|d| d.live.get(&name))
                    .map(|inode| state.inodes[inode].data.len() as u64))
            },
        )
    }

    fn read_at(&self, path: &Path, offset: u64, length: usize) -> io::Result<Option<Vec<u8>>> {
        let (parent, name) = split(path)?;
        self.run(
            Op::Read,
            path,
            |c| c.reads += 1,
            |state| match state
                .directories
                .get(&parent)
                .and_then(|d| d.live.get(&name))
                .copied()
            {
                None => Ok(None),
                Some(inode) => {
                    let data = &state.inodes[&inode].data;
                    let start = usize::try_from(offset).map_err(|_| io::ErrorKind::InvalidInput)?;
                    let end = start
                        .checked_add(length)
                        .ok_or(io::ErrorKind::InvalidInput)?;
                    if end > data.len() {
                        return Err(io::ErrorKind::UnexpectedEof.into());
                    }
                    let bytes = data[start..end].to_vec();
                    state.counts.read_bytes += length as u64;
                    Ok(Some(bytes))
                }
            },
        )
    }

    fn write_synced(&self, path: &Path, bytes: &[u8]) -> io::Result<()> {
        let (parent, name) = split(path)?;
        let counted = |c: &mut Counts| {
            c.writes += 1;
            c.syncs += 1;
        };
        self.run(Op::Write, path, counted, |state| {
            let inode = state.next + 1;
            let directory = state
                .directories
                .get_mut(&parent)
                .ok_or(io::ErrorKind::NotFound)?;
            match directory.live.entry(name) {
                std::collections::btree_map::Entry::Occupied(_) => {
                    return Err(io::ErrorKind::AlreadyExists.into());
                }
                std::collections::btree_map::Entry::Vacant(slot) => {
                    slot.insert(inode);
                }
            }
            state.next = inode;
            state.inodes.insert(
                inode,
                Inode {
                    data: bytes.to_vec(),
                    durable: Some(bytes.to_vec()),
                },
            );
            Ok(())
        })
    }

    fn link(&self, from: &Path, to: &Path) -> io::Result<bool> {
        let (from_dir, from_name) = split(from)?;
        let (to_dir, to_name) = split(to)?;
        self.run(
            Op::Link,
            to,
            |c| c.others += 1,
            |state| {
                let inode = *state
                    .directories
                    .get(&from_dir)
                    .and_then(|d| d.live.get(&from_name))
                    .ok_or(io::ErrorKind::NotFound)?;
                let directory = state
                    .directories
                    .get_mut(&to_dir)
                    .ok_or(io::ErrorKind::NotFound)?;
                Ok(match directory.live.entry(to_name) {
                    std::collections::btree_map::Entry::Occupied(_) => false,
                    std::collections::btree_map::Entry::Vacant(slot) => {
                        slot.insert(inode);
                        true
                    }
                })
            },
        )
    }

    fn rename(&self, from: &Path, to: &Path) -> io::Result<()> {
        let (from_dir, from_name) = split(from)?;
        let (to_dir, to_name) = split(to)?;
        self.run(
            Op::Rename,
            to,
            |c| c.others += 1,
            |state| {
                if !state.directories.contains_key(&to_dir) {
                    return Err(io::ErrorKind::NotFound.into());
                }
                let inode = state
                    .directories
                    .get_mut(&from_dir)
                    .and_then(|d| d.live.remove(&from_name))
                    .ok_or(io::ErrorKind::NotFound)?;
                state
                    .directories
                    .get_mut(&to_dir)
                    .expect("checked above")
                    .live
                    .insert(to_name, inode);
                Ok(())
            },
        )
    }

    fn remove(&self, path: &Path) -> io::Result<bool> {
        let (parent, name) = split(path)?;
        self.run(
            Op::Remove,
            path,
            |c| c.others += 1,
            |state| {
                Ok(state
                    .directories
                    .get_mut(&parent)
                    .is_some_and(|d| d.live.remove(&name).is_some()))
            },
        )
    }

    fn remove_dir(&self, path: &Path) -> io::Result<bool> {
        self.run(
            Op::Remove,
            path,
            |c| c.others += 1,
            |state| {
                let has_children = state
                    .directories
                    .keys()
                    .any(|other| other.parent() == Some(path));
                match state.directories.get(path) {
                    Some(directory) if directory.live.is_empty() && !has_children => {
                        state.directories.remove(path);
                        Ok(true)
                    }
                    _ => Ok(false),
                }
            },
        )
    }

    fn lock(&self, path: &Path) -> io::Result<Box<dyn std::any::Any + Send + Sync>> {
        let epoch = {
            let mut state = self.state.lock().unwrap();
            if state.crashed {
                return Err(crashed());
            }
            state.counts.others += 1;
            // Like the real thing, locking creates the lock file (durably empty).
            let (parent, name) = split(path)?;
            state.next += 1;
            let inode = state.next;
            let directory = state.directories.entry(parent).or_default();
            if !directory.live.contains_key(&name) {
                directory.live.insert(name.clone(), inode);
                directory.durable.insert(name, inode);
                state.inodes.insert(inode, Inode::default());
            }
            state.epoch
        };
        let mut locks = self.locks.lock().unwrap();
        if locks.get(path) == Some(&epoch) {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        locks.insert(path.to_owned(), epoch);
        Ok(Box::new(LockGuard {
            locks: self.locks.clone(),
            path: path.to_owned(),
            epoch,
        }))
    }

    fn sync_dir(&self, dir: &Path) -> io::Result<()> {
        self.run(
            Op::SyncDir,
            dir,
            |c| c.syncs += 1,
            |state| {
                let directory = state
                    .directories
                    .get_mut(dir)
                    .ok_or(io::ErrorKind::NotFound)?;
                directory.durable = directory.live.clone();
                Ok(())
            },
        )
    }
}

/// A gate a storage hook can block on until the test opens it.
#[derive(Default)]
pub struct Gate {
    state: Mutex<(bool, bool)>, // (entered, open)
    changed: std::sync::Condvar,
}

impl Gate {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }
    /// Called from the blocked side: records entry and waits for `open`
    /// (at most 30 s, so a failed test cannot leave a worker parked forever).
    pub fn pass(&self) {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        let mut state = self.state.lock().unwrap();
        state.0 = true;
        self.changed.notify_all();
        while !state.1 {
            let Some(left) = deadline.checked_duration_since(std::time::Instant::now()) else {
                panic!("gate was never opened");
            };
            state = self.changed.wait_timeout(state, left).unwrap().0;
        }
    }
    pub fn wait_entered(&self) {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        let mut state = self.state.lock().unwrap();
        while !state.0 {
            let left = deadline
                .checked_duration_since(std::time::Instant::now())
                .expect("gate was never reached");
            state = self.changed.wait_timeout(state, left).unwrap().0;
        }
    }
    pub fn entered(&self) -> bool {
        self.state.lock().unwrap().0
    }
    pub fn open(&self) {
        self.state.lock().unwrap().1 = true;
        self.changed.notify_all();
    }
}

/// Signed-envelope fixtures shared by the runtime tests (public test key `[7; 32]`).
pub mod fixture {
    use alloy_evm::{
        Evm, EvmEnv, EvmFactory,
        revm::{
            bytecode::Bytecode,
            context::{CfgEnv, TxEnv},
            database::InMemoryDB,
            primitives::hardfork::SpecId,
            state::AccountInfo,
        },
    };
    use alloy_primitives::{Address, B256, Bytes, U256, keccak256};
    use base64::{Engine, engine::general_purpose::STANDARD};
    use ed25519_dalek::{Signer, SigningKey};
    use ops_reth_policy::{
        archive::BlockDescriptor,
        context::ExecutionBinding,
        runtime::ExecutionHandle,
        transaction::PolicyTx,
        wire::{Network, Verifier},
    };
    use serde_json::{Value, json};
    use std::collections::BTreeMap;

    pub const AT: i64 = 1800000010;

    pub fn seal(kind: &str, payload: &Value) -> Vec<u8> {
        let payload = serde_json::to_vec(payload).unwrap();
        let mut bytes = b"OPS_NODE_POLICY_V1\0".to_vec();
        for part in [kind.as_bytes(), b"ops", payload.as_slice()] {
            bytes.extend_from_slice(&(part.len() as u32).to_be_bytes());
            bytes.extend_from_slice(part);
        }
        serde_json::to_vec(&json!({"version":1,"kind":kind,"key_id":"ops","payload":STANDARD.encode(payload),"signature":STANDARD.encode(SigningKey::from_bytes(&[7;32]).sign(&bytes).to_bytes())})).unwrap()
    }
    pub fn lifecycle() -> Value {
        serde_json::from_str(include_str!(
            "../../../../internal/policydsl/testdata/lifecycle-v1.json"
        ))
        .unwrap()
    }
    pub fn network() -> Network {
        Network {
            chain_id: 31337,
            deployment_id: "compiler-fixture".into(),
        }
    }
    pub fn verifier() -> Verifier {
        Verifier::new(
            network(),
            BTreeMap::from([(
                "ops".into(),
                SigningKey::from_bytes(&[7; 32]).verifying_key(),
            )]),
        )
    }
    /// The fixture snapshot, valid 1800000000..1800000060.
    pub fn snapshot() -> Value {
        lifecycle()["snapshot"].clone()
    }
    pub fn signer() -> String {
        snapshot()["principals"][0]["linked_addresses"][0]
            .as_str()
            .unwrap()
            .to_owned()
    }
    /// A transaction identity for `hash` issued by the fixture principal.
    pub fn identity(hash: B256, context: &str) -> Value {
        json!({"network":network(),"issued_at":1800000000,"expires_at":1800000060,"scope":"transaction","context_id":context,"principal_id":"fixture_principal","org_id":"org_acme","signer":signer(),"binding_hash":format!("{hash:#x}"),"min_snapshot_version":1})
    }
    pub fn descriptor(transactions: Vec<B256>) -> BlockDescriptor {
        BlockDescriptor {
            network: network(),
            hash: B256::repeat_byte(10),
            parent_hash: B256::repeat_byte(9),
            number: 1,
            timestamp: AT as u64,
            transactions,
        }
    }
    /// Execute the fixture's allowed call bound to `hash` in this handle.
    pub fn execute(handle: &ExecutionHandle, hash: B256) -> bool {
        execute_result(handle, hash).is_ok()
    }

    /// As `execute`, with the denial reason.
    pub fn execute_result(handle: &ExecutionHandle, hash: B256) -> Result<(), String> {
        execute_with(handle.factory(), Some(hash))
    }

    /// Execute the fixture's call with `factory`, bound to `hash` (or unbound).
    pub fn execute_with(
        factory: ops_reth_policy::policy::PolicyFactory,
        hash: Option<B256>,
    ) -> Result<(), String> {
        let case = &lifecycle()["cases"][0];
        let signer = case["facts"]["signer"]
            .as_str()
            .unwrap()
            .parse::<Address>()
            .unwrap();
        let target = case["call"]["code_address"]
            .as_str()
            .unwrap()
            .parse::<Address>()
            .unwrap();
        let data = case["call"]["data_hex"]
            .as_str()
            .unwrap()
            .parse::<Bytes>()
            .unwrap();
        let mut db = InMemoryDB::default();
        db.insert_account_info(
            signer,
            AccountInfo {
                balance: U256::from(1_000_000_000),
                ..Default::default()
            },
        );
        db.insert_account_info(
            target,
            AccountInfo {
                code_hash: keccak256([0]),
                code: Some(Bytecode::new_raw(Bytes::from_static(&[0]))),
                ..Default::default()
            },
        );
        let mut evm = factory.create_evm(
            db,
            EvmEnv {
                cfg_env: CfgEnv::new_with_spec(SpecId::PRAGUE),
                ..Default::default()
            },
        );
        let tx = TxEnv::builder()
            .caller(signer)
            .to(target)
            .data(data)
            .gas_limit(200_000)
            .gas_price(0)
            .build()
            .unwrap();
        let tx = match hash {
            Some(hash) => PolicyTx::bound(tx, ExecutionBinding::Transaction(hash)),
            None => PolicyTx::unbound(tx),
        };
        evm.transact_raw(tx)
            .map(|_| ())
            .map_err(|error| format!("{error:?}"))
    }
}

/// The exact Go-signed envelopes (`internal/nodepolicy/testdata`) behind a
/// private API with a fake pool backend.
pub mod golden {
    use super::MemoryStorage;
    use alloy_primitives::Bytes;
    use async_trait::async_trait;
    use base64::{Engine, engine::general_purpose::STANDARD};
    use ed25519_dalek::VerifyingKey;
    use ops_reth_policy::{
        api::{ExecutionBackend, PoolSubmission, PrivateApi},
        archive::ArtifactStore,
        runtime::PolicyRuntime,
        wire::{Identity, Network, SimulationRequest, Verifier},
    };
    use serde_json::{Value, json};
    use std::{collections::BTreeMap, path::Path, sync::Arc};

    pub struct Backend;
    #[async_trait]
    impl ExecutionBackend for Backend {
        fn capabilities(&self) -> Vec<String> {
            [
                "per_frame_a5",
                "signed_identity_v1",
                "fact_stream_v1",
                "simulation_v1",
                "archive_v1",
                "candidate_simulation_v1",
                "scoped_diagnostics_v1",
                "finalized_status_v1",
            ]
            .into_iter()
            .map(str::to_string)
            .collect()
        }
        async fn submit(
            &self,
            _identity: Identity,
            raw: Bytes,
            _signer: alloy_primitives::Address,
        ) -> Result<PoolSubmission, String> {
            use alloy_eips::eip2718::Decodable2718;
            let transaction = alloy_consensus::TxEnvelope::decode_2718(&mut raw.as_ref())
                .map_err(|_| "invalid fixture")?;
            Ok(PoolSubmission::Inserted(*transaction.tx_hash()))
        }
        async fn simulate(
            &self,
            _identity: Identity,
            _request: SimulationRequest,
            _exact: Bytes,
        ) -> Result<Value, String> {
            Ok(json!("0x1234"))
        }
    }

    pub fn envelopes() -> Value {
        serde_json::from_str(include_str!(
            "../../../../internal/nodepolicy/testdata/envelopes-v1.json"
        ))
        .unwrap()
    }

    pub fn verifier() -> Verifier {
        let key: [u8; 32] = STANDARD
            .decode(envelopes()["public_key"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        Verifier::new(
            Network {
                chain_id: 31337,
                deployment_id: "ops-test".into(),
            },
            BTreeMap::from([("ops-a".into(), VerifyingKey::from_bytes(&key).unwrap())]),
        )
    }

    /// A private API over `storage`, at the golden clock (1020), and a clone of
    /// its verifier.
    pub fn api(storage: &Arc<MemoryStorage>) -> (PrivateApi, Verifier) {
        let (api, verifier, _) = api_with_runtime(storage);
        (api, verifier)
    }

    /// As `api`, also returning the runtime for registry inspection.
    pub fn api_with_runtime(
        storage: &Arc<MemoryStorage>,
    ) -> (PrivateApi, Verifier, Arc<PolicyRuntime>) {
        let verifier = verifier();
        let archive = ArtifactStore::open_with(Path::new("/state"), storage.clone()).unwrap();
        let runtime = Arc::new(PolicyRuntime::new(verifier.clone(), Arc::new(archive), 16));
        let api = PrivateApi::new(
            runtime.clone(),
            Arc::new(Backend),
            "private-test-token".into(),
            Arc::new(|| 1020),
        )
        .unwrap();
        (api, verifier, runtime)
    }

    pub async fn call(api: &PrivateApi, method: &str, params: Value) -> Value {
        let body = serde_json::to_vec(
            &json!({"jsonrpc":"2.0","id":"ops-1","method":method,"params":params}),
        )
        .unwrap();
        let response = api.process("Bearer private-test-token", &body).await;
        assert_eq!(response.status, 200);
        serde_json::from_slice(&response.body).unwrap()
    }
}

/// The golden transaction and its facts, re-signed with a local test key
/// (`[11; 32]`, key id `local`), so a test can vary an identity's times,
/// fact floor, principal and context for the same raw transaction.
pub mod local {
    use super::golden;
    use alloy_primitives::B256;
    use base64::{Engine, engine::general_purpose::STANDARD};
    use ed25519_dalek::{Signer, SigningKey};
    use ops_reth_policy::wire::{Network, Verifier};
    use serde_json::{Value, json};
    use std::collections::BTreeMap;

    /// The golden clock.
    pub const NOW: i64 = 1020;

    fn key() -> SigningKey {
        SigningKey::from_bytes(&[11; 32])
    }

    pub fn network() -> Network {
        Network {
            chain_id: 31337,
            deployment_id: "ops-test".into(),
        }
    }

    pub fn verifier() -> Verifier {
        Verifier::new(
            network(),
            BTreeMap::from([("local".into(), key().verifying_key())]),
        )
    }

    /// A signed envelope (as a JSON value) of `payload`.
    pub fn seal(kind: &str, payload: &Value) -> Value {
        let payload = serde_json::to_vec(payload).unwrap();
        let mut bytes = b"OPS_NODE_POLICY_V1\0".to_vec();
        for part in [kind.as_bytes(), b"local", payload.as_slice()] {
            bytes.extend_from_slice(&(part.len() as u32).to_be_bytes());
            bytes.extend_from_slice(part);
        }
        json!({"version":1,"kind":kind,"key_id":"local","payload":STANDARD.encode(payload),
            "signature":STANDARD.encode(key().sign(&bytes).to_bytes())})
    }

    /// The decoded payload of a golden envelope.
    pub fn payload(name: &str) -> Value {
        let envelope = &golden::envelopes()[name];
        serde_json::from_slice(
            &STANDARD
                .decode(envelope["payload"].as_str().unwrap())
                .unwrap(),
        )
        .unwrap()
    }

    /// The golden transaction snapshot (version 7), valid 1000..1100.
    pub fn snapshot() -> Value {
        seal("snapshot", &payload("transaction_snapshot"))
    }

    /// The golden snapshot at `version`, issued at `issued_at`.
    pub fn snapshot_at(version: u64, issued_at: i64) -> Value {
        let mut snapshot = payload("transaction_snapshot");
        snapshot["version"] = json!(version);
        snapshot["issued_at"] = json!(issued_at);
        snapshot["expires_at"] = json!(issued_at + 100);
        seal("snapshot", &snapshot)
    }

    /// The golden transaction identity with these fields replaced.
    pub fn identity(context: &str, issued_at: i64, expires_at: i64, min_version: u64) -> Value {
        identity_with(context, issued_at, expires_at, min_version, |_| {})
    }

    pub fn identity_with(
        context: &str,
        issued_at: i64,
        expires_at: i64,
        min_version: u64,
        edit: impl FnOnce(&mut Value),
    ) -> Value {
        let mut identity = payload("transaction_identity");
        identity["context_id"] = json!(context);
        identity["issued_at"] = json!(issued_at);
        identity["expires_at"] = json!(expires_at);
        identity["min_snapshot_version"] = json!(min_version);
        edit(&mut identity);
        seal("identity", &identity)
    }

    pub fn raw() -> Value {
        golden::envelopes()["raw_transaction"].clone()
    }

    pub fn tx_hash() -> B256 {
        payload("transaction_identity")["binding_hash"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap()
    }
}
