# OPS Reth policy runtime

For the complete path from OPS authentication and policy compilation to node
execution, see [How OPS v2 authorizes Reth execution](../../docs/architecture/reth-execution-flow.md).

`ops-reth` runs the generated DSL policy inside Reth's live EVM before each
application CALL, STATICCALL, DELEGATECALL, CALLCODE, CREATE, and CREATE2 frame.
Policy bytecode is private to the node. It is never deployed to a chain account,
and its gas, storage journal, access warming, and trace frames are isolated from
application execution. A denied inner frame vetoes the entire transaction even
when application code catches the revert.

Execution rules are published as one artifact per bound group. The guard runs
only the signer's current groups in the target policy organization, in sorted
order, until one permits the frame. The complete set shares the frame's 100,000
gas budget, and failures deny execution. A pinned snapshot cannot mix revisions
or legacy org-wide artifacts with grouped artifacts for the same organization.
Upgrade OPS and this node together before activating grouped revisions.

**Known membership limitation:** A frame can be denied when its shared policy
budget is exhausted before reaching a group that would allow it. Adding groups
to a caller can therefore cause an otherwise permitted action to fail. The
measured last-match workload passed at 11 memberships and exhausted the budget
at 12; this is not a universal membership limit. An organization with sixty
groups is supported by the tested workflow, but arbitrary memberships per caller
are not established. Optimization is deferred for now; see
[the accepted limitation](../../docs/OPEN_ITEMS.md#12-reth-per-group-permission-budget)
and [live measurements](../../docs/implementation/evidence/per-group-live-2026-09-25.md).

Reth is pinned to **v2.5.2**, commit
`5a6940e351fed80458fe6c9da8581cbe4b8bd036`. Preparation refuses tracked source
modifications and reuses the research checkout when available:

```sh
python3 node/reth/scripts/prepare.py --offline
cargo build --release --locked --manifest-path node/reth/Cargo.toml --features reth-sdk
cargo test --release --locked --manifest-path node/reth/Cargo.toml --features reth-sdk
```

Set `OPS_RETH_SOURCE` to another checkout of that exact commit. Omit `--offline`
from preparation to clone the pinned release if needed. Set `CARGO_TARGET_DIR`
to reuse a release artifact cache; otherwise Cargo writes `node/reth/target`.
The HTTP tests bind isolated localhost ports.

## Running

Configure these variables before starting the node. The signing private key
belongs to OPS; the node only receives trusted public keys.

| Variable | Value |
| --- | --- |
| `OPS_NODE_POLICY_CHAIN_ID` | Must match the genesis chain ID |
| `OPS_NODE_POLICY_DEPLOYMENT_ID` | Unique OPS deployment identifier |
| `OPS_NODE_POLICY_PUBLIC_KEYS` | JSON object mapping key ID to base64 Ed25519 public key |
| `OPS_NODE_POLICY_LISTEN` | Private listener, for example `127.0.0.1:8555` |
| `OPS_NODE_POLICY_TOKEN` | Bearer token shared with OPS |
| `OPS_NODE_POLICY_VERIFY_WORKERS` | Optional concurrent identity-admission jobs (signature verification, transaction decoding, signer recovery), 1–64; default `4` |
| `OPS_NODE_POLICY_STATE_DIR` | Dedicated durable policy/archive directory on a local filesystem (a subdirectory, not a volume's root), used by one node process at a time: it is locked. Start from an empty directory: one written in an older layout is refused, there is no importer |
| `OPS_NODE_POLICY_MANIFEST_RETENTION` | Optional: how long a block's evidence (its manifest, and fact records only retained blocks use) is kept after the block's timestamp, `forever` or a whole number of `s`, `m`, `h` or `d`, at least one hour; default `7d`, a proposal until the record-retention policy sets it. Only finalized blocks are pruned; `forever` never prunes canonical evidence |
| `OPS_NODE_POLICY_CAPACITY` | Optional pending identity limit; default `262144` (estimated at about 370 MB when full). A slot is held until the transaction's block is final and written by Reth, or until its lease expires. Startup refuses a value below ⌈1.25 × (expected tx/s × (2 s + finality bound) + pending limit)⌉ |
| `OPS_NODE_POLICY_EXPECTED_TPS` | Optional sustained transactions per second the capacity must cover; default `2000` |
| `OPS_NODE_POLICY_FINALITY_BOUND` | Optional seconds from inclusion until a block is both final and written by Reth (the larger of finality depth × block time and Reth's persistence lag), at least `1`; default `64`. Set it from the deployed consensus, which has no universal fixed depth |
| `OPS_NODE_POLICY_PENDING_LIMIT` | Optional allowance for admitted submissions still awaiting inclusion, which capacity must also cover; default `37500` |
| `OPS_POLICY_DECISION_LOG` | Set to `1` to print one `OPS_POLICY_DECISION {…}` JSON line per checked transaction on stderr (development diagnostic; off by default — it costs a synchronous write per transaction and records principal/selector pairs in the node log) |

```sh
node/reth/target/release/ops-reth node \
  --chain /absolute/path/to/genesis.json --dev --dev.block-time 1s \
  --dev.finality-depth 1 \
  --engine.cross-block-cache-size 64 \
  --datadir /absolute/path/to/reth-data \
  --http --http.addr 127.0.0.1 --http.api eth,net,web3
```

The `--dev` producer is intended for the local OPS stack. OPS blocks are ordinary
Ethereum blocks: a vanilla Ethereum node imports and validates them (state and
receipt roots) but cannot verify their authorization. A guarded `ops-reth` node
replays each block it imports from the producer's execution manifest for that
block. Re-executing history it already holds at or below its finalized head (after
a restart or an unwind, or for RPC) runs only those blocks' own transactions,
without policy, under the same consensus validation. A node importing blocks for
the first time, including a fresh follower during its initial sync, has no known
finality for them, so production consensus integration must give every guarded
importing node the producer's manifests.
Public `pending` block queries are disabled: building one would execute and
record a candidate block from the pool.
The node can start before OPS publishes facts; private status remains unready
and application execution fails closed until a fresh signed snapshot arrives.

Signed full-admin diagnostic requests may run while reporting `would_allow` and
per-frame policy decisions. An independent mandatory guard confines frames and
account reads to the selected organization or explicitly permitted public/shared
classes. Scope escape returns no execution output or trace. Ordinary requests
always enforce the active policy.

Candidate previews replace only the selected organization's policy in an
ephemeral execution handle. They report the candidate's decisions while the
active policy continues to authorize every application frame. Candidate bytecode
never enters the signed facts feed or changes later execution. The signed
simulation request requires an explicit `candidate_policy` key, with `null` for
ordinary calls.
An ordinary candidate cannot read live contract/account state, including through
record-party getters: an unpublished rule must not become a new data-access
oracle. Those previews require the scoped human-admin diagnostic route. Active
approved policy getters continue to operate normally.

The private listener supports `ops_policyApply`, `ops_policyStatus`,
`ops_submitTransaction`, `ops_simulate`, and `ops_transactionStatus`. Its exact
wire protocol is in [execution-context.md](../../docs/architecture/execution-context.md).
It is separate from public Reth JSON-RPC. IPC is disabled, and the node refuses
to start with a public RPC module that replays, traces, validates or builds
blocks through the guarded executor (`debug`, `trace`, `ots`, `flashbots`, `mev`,
`testing`, or `all`), with `--rpc.forwarder` (it would send guarded
transactions to a node without policy and hide local pool rejections) or with
`--debug.reorg-frequency`, or with a `--db.sync-mode` other than `durable`
(finality is reported only for blocks Reth has written, which must survive a
host crash). Public `eth_simulateV1` builds no blocks (its block limit is
forced to 0). `eth_call`, `eth_estimateGas`, and `debug_traceCall` are available through
signed private simulations; public calls cannot inherit an OPS principal.
Nonempty state/code/storage and block overrides are rejected for every simulation
mode. An authenticated call never authorizes replacing customer bytecode with a
program that reads otherwise inaccessible storage. Trace output options remain
available.

Every successful `ops_policyStatus`, `ops_policyApply`, `ops_submitTransaction`
and `ops_transactionStatus` result carries the node's `boot_id`
(capability `boot_id_v1`): 32 random hex characters, new at every process start
and never stored, so OPS records each delivery against the boot that answered
it.

A pending transaction is bound to one principal and selected organization, even
when several principals share its signer. A newer identity for the same
principal, organization, signer and transaction replaces the registered one; an
older one whose fact floor and expiry the registered identity already covers
(for example a client's request that arrives after OPS renewed it) is accepted
as a duplicate under its own context without replacing it. Any other identity
for the hash is refused while the registered one is live. A pool answer of
"nonce too low" without the transaction's own receipt, or of an underpriced
replacement, is a definitive answer for those bytes at the current head (not a
final outcome): `ops_submitTransaction` returns error
`-32013` with `data.reason` `nonce_used` or `replaced`, and the node undoes
exactly that registration (restoring the identity it replaced, which a
reorganization may still need), never a newer one. "Nonce too low" for a
transaction whose own receipt exists, and "already known", are accepted. Any
other pool failure keeps the registration and returns the generic error. New execution requires a valid ticket.
The node keeps pending identities in memory only: admission does no storage
I/O. While an identity's lease is valid, the node refuses another principal,
organization or signer for its transaction hash; an expired lease is reclaimed by
a later admission. OPS's durable submission record refuses rebinding before
anything reaches the node, including after the node has released or lost the
identity. After a node restart the node holds no pending identities, so a
transaction not yet included cannot execute until the principal that submitted it
sends the same signed transaction again through OPS; OPS does not resubmit it.
The node accepts that resend even when its pool still holds the transaction:
after a clean shutdown Reth restores the pool from its backup. An `expired`
status describes the current lease and is not final: a
previously pinned candidate can still settle, so OPS continues receipt polling.
Once the expired lease has been reclaimed, a status request for the not-included
transaction returns an error. Rule denials describe the current
candidate and are not final pool eviction: Reth can retry an already admitted
transaction when later facts change. Included creation metadata is returned only
when a canonical receipt matches the exact archived block, and includes nested
successful CREATE/CREATE2 results. Reverted creations never become registration
evidence. The status of an included transaction reports the identity that executed
it, from the block's manifest. The node itself releases the bounded pending
identity slot once the transaction's canonical block is final and written (OPS's
status poll of a finalized receipt releases it too): before finality a
reorganization can return the transaction to the pool, where its registered
identity lets it execute again, without OPS, while its lease is valid; after
expiry the principal that submitted it must send it again through OPS.
Permanent OPS registration and visibility projection wait for `finalized:true`.
The node reports finality only up to the lower of Reth's forkchoice-finalized
height and the height Reth has written to disk (a crash can lose newer blocks),
checked against the canonical chain, and never takes it back. Trusted import of
finalized history uses consensus finality alone.
Wait for that reconciliation before calling a newly deployed contract across
blocks. Inclusion alone remains provisional and can return to pending after a
reorganization.

The local example uses `--dev.finality-depth 1`; Reth's default is 64. These are
the dev miner's forkchoice decisions, not an external consensus guarantee. The
pinned dev miner starts its retained-hash window at the current tip on restart,
so that tip can immediately become its finalized head. Production finality must
come from the deployed consensus system.

Policy facts are immutable for a candidate block. Signed delta updates are atomic,
heartbeats extend only the installed digest's freshness lease, and produced blocks
retain the exact verified snapshot chain and executed identity envelopes before
publication. Snapshots and deltas are durable before they are installed. Heartbeats
are not written: each block's manifest carries the heartbeat, if one renewed the
lease. After a restart the node therefore reports ready again at the next heartbeat
if the latest snapshot or delta's own lease has expired. Self-import reuses that archive; ordinary simulations use current
permissions even when querying historical chain state.

The state directory (layout 3; a directory from an earlier build is refused)
keeps signed snapshot and delta records and their record lists by fact version,
and one compressed manifest file per produced block. Final and written blocks'
manifests are compacted, in batches of at least 256 or a full 4096-height
range, into segment files of finalized canonical blocks (a lookup reads the
segment's footer, index and one entry); other builds of a final height, which
can no longer become canonical, are removed at once.
Segments whose newest block is older than `OPS_NODE_POLICY_MANIFEST_RETENTION`
are deleted, and so are fact records and lists that no retained block, the
installed facts or a block still being built uses. This runs on the
maintenance thread after writes, at most 1,024 removals per run, never on block
publication; with `forever` canonical evidence is never deleted.

Record-party getters run against live candidate storage. Every descendant code
and storage account must belong to the policy organization; active standard
precompiles are supported. Foreign account observations through BALANCE and
EXTCODE opcodes also fail the whole policy check, including caught child failures.
Same-organization proxy getters can delegate to registered implementations.
Optional signed code hashes apply to every getter descendant and diagnostic
account observation as well as ordinary application frames.

## Validation and supported boundaries

The repeatable smoke test needs the repository Go toolchain and Python
`cryptography`. It creates an isolated genesis, public development signing keys,
local ports, and a fresh data directory, then checks signed facts, scoped
simulations, pool submission, mining/self-import, deployment, and revocation:

```sh
python3 node/reth/scripts/smoke.py --binary node/reth/target/release/ops-reth
```

Evidence and logs remain under `.tmp/ops-reth-smoke-*`. The smoke chain enables
Shanghai; tests also verify active-fork precompile classification. EIP-7702
transactions and delegated accounts, SELFDESTRUCT, custom creation schemes,
custom precompile providers, and transaction-index traces currently fail explicitly. The local stack's supported
normal workflows do not require those features. MCP tooling is separate.

The crash check runs Reth with its persistence threshold set to 0 (not the
default), so each new chain head is written at once, asynchronously; a SIGKILL
can still lose the newest blocks. It stops the node around block production:
with SIGKILL while a batch waits in the pool, after a block with the batch was
built but before it became the chain head, and just after it became the head;
and once with SIGTERM, after which Reth restores its pool without the node's
identities. After each restart it checks that the node is ready with the facts it
had, that every block Reth reported saved survived, that a transaction without a
receipt has no status, that every transaction in a surviving block reports
`included` from its block's evidence, that restored pooled transactions do not
execute without an identity, that every resubmission is accepted and included,
and that the chain keeps importing its own blocks. A last restart without new
facts reads every inclusion from disk:

```sh
python3 node/reth/scripts/crash.py --binary node/reth/target/release/ops-reth
```

Its records and logs stay in `.tmp/ops-reth-crash-*`.

Implementation evidence: [reth-runtime.md](../../docs/implementation/evidence/reth-runtime.md).

## Reproducible load acceptance

The load harness measures signed private HTTP admission through canonical mining
with durable facts and block manifests enabled (pending identities are
memory-only):

```sh
python3 node/reth/scripts/load.py --binary node/reth/target/release/ops-reth \
  --transactions 512 --rounds 3 --senders 8 --concurrency 8 \
  --facts-principals 1000 --execution-cache-mib 64 \
  --contention-note 'Describe other workloads running on this machine.'
```

It starts a fresh node for plain calls, three application frames, a compiled
record-party getter, and plain calls with signed delta/full-snapshot churn. Each
phase records attempted/admitted/mined/successful/reverted counts, latency,
publication timing, sampled RSS, hardware, and the exact binary hash. Receipt and
private-status reconciliation are reported separately from the timed mining
window. A banned transaction probe must remain without a receipt. Records and
logs stay in `.tmp/ops-reth-load-*`.

The default load chain uses 150 million gas per one-second dev block and only
public deterministic development keys. The successful record-party application
is [LoadRecord.sol](scripts/LoadRecord.sol), compiled outside the timed interval
using the pinned Solidity compiler. This measures the complete node path, not
isolated policy-interpreter cost or full OPS/explorer throughput. It does not
establish the roadmap's 5,000 TPS target.

Transaction admission and candidate execution no longer write to disk. Block
assembly publishes one compressed execution manifest per block; see
[sustained throughput work](../../docs/OPEN_ITEMS.md#13-reth-sustained-transaction-throughput).
The current group's in-process timings imply only a
[policy-only theoretical ceiling](../../docs/implementation/evidence/per-group-live-2026-09-25.md#theoretical-throughput-from-policy-cost),
not achieved node TPS.

Reth's upstream 64-bit execution-cache default is 4 GiB and eagerly reserves
fixed-cache buckets when self-import starts. The local examples explicitly use
64 MiB; choose a cache budget suited to the production working set. Optional
`--memory-map` saves a bounded own-process macOS `vmmap` summary when available.
