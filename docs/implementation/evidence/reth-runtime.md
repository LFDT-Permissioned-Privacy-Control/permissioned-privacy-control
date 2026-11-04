# Reth runtime implementation evidence

16 September 2026. This file records implemented slices, not a claim that the
complete OPS stack is ready.

## Private interpreter frame and transaction context

The initial three behavioral tests failed against the copied PoC: a private
allow policy could not run without the public account at `0x0900`; public allow
code incorrectly replaced the intended private deny policy; the gas/state
comparison could not execute. After injecting private runtime bytecode directly
through the frame's `known_bytecode`, all three passed.

The suite now additionally checks that application `EXTCODESIZE` cannot see the
private code; cold-access warming, user gas, and returned state match an ordinary
EVM; a caught forbidden inner call still vetoes the whole transaction; missing,
reverting, malformed, looping, or state-writing policy code fails closed.

Context tests were introduced before the corresponding interfaces. They now
check shared signing-address isolation, missing bindings, signer mismatch,
minimum snapshot version, and retention of an immutable snapshot across an
execution. Binding conversion tests distinguish signed envelopes whose unsigned
EVM environment is identical and invalidate a binding when its signed fields
are changed.

Validation command (local cached target location is optional):

```sh
python3 node/reth/scripts/prepare.py --offline
CARGO_TARGET_DIR=/Users/blade/work/software/privacy-proxy/.tmp/reth-policy-poc/target \
  cargo test --release --offline --manifest-path node/reth/Cargo.toml
```

Twelve tests passed at the first completed context/binding slice. Further
verification is recorded below as additional slices complete.

The subsequent signed-wire and registry slice passed the complete 21-test suite.
Rust verifies the exact Go-generated identity and snapshot signatures and the
simulation hash in `internal/nodepolicy/testdata/envelopes-v1.json`. Cases include
signature tampering, network/domain mismatch, expiry, ambiguous JSON, missing
fields, noncanonical base64, bounded/idempotent ingestion, stale renewal, and
independent identities for otherwise identical simulation requests. Required
`org_id`, scoped sanctions, and contract `code_hash` fields match the coordinated
Go wire schema. An additional active-fork classification test distinguishes EOA,
contract code, and active precompile addresses from observed execution.

The `reth-sdk` feature's compile test also passed against the pinned upstream
SDK, proving the custom factory/transaction type satisfies `ConfigureEvm`.
`cargo clippy --release --offline --locked --manifest-path node/reth/Cargo.toml
--tests -- -D warnings` passed for this slice.

## Trust boundaries and remaining integration

`IdentityResolver` is the trusted authenticated-context lookup boundary;
`FramePolicy` resolves immutable snapshot facts and prepares the contract ABI.
The interpreter itself makes no external calls for facts. It requires explicit
transaction/request bindings and checks signer and minimum snapshot version.
`PolicyTx` retains the signed-envelope hash through Reth's transaction conversion.
`PinnedPolicySnapshot` is held for the complete EVM lifetime, not replaced per frame.

The low-level fixture tests still encode the old PoC ABI in test code only.
Production A3 ABI encoding, fact stream transport, deployment handling, block
manifest persistence/self-import, authenticated simulation RPCs, and node startup
remain separate integration work. The initial interpreter conservatively denies
CREATE and SELFDESTRUCT until lifecycle enforcement is implemented. No production
disable-policy switch exists in the new crate.

Reth source is pinned to v2.5.2, commit
`5a6940e351fed80458fe6c9da8581cbe4b8bd036`. Preparation checks the exact commit and
refuses tracked modifications; it never changes an existing upstream checkout.

## Review notes

The shared-signer change is explicitly flagged for user review in
`docs/architecture/execution-context.md`. These unit tests use controlled resolver
fixtures; they are not evidence of signature verification or complete user
workflows. Historic reexecution must use the immutable produced-block manifest,
not current mutable authorization facts. Ordinary user history queries must
continue to apply current visibility permissions.

## Product runtime, compiler integration, and live node (17 September 2026)

The earlier “remaining integration” list above describes the initial slice. The
crate now builds the `ops-reth` binary with the pinned, unmodified upstream SDK.
`OpsEvmConfig` carries explicit immutable execution handles through candidate
construction, block assembly, engine self-import, and replay. Reth's generic RPC
add-ons support `PolicyTx`; its Ethereum convenience add-ons hard-code stock
`TxEnv`, so the binary uses the generic builder directly. The standard debug
launcher is required to start Reth's configured local development producer.

The complete SDK test invocation passed 57 tests, including the actual localhost
private HTTP transport test. Subsequent targeted tests cover canonical status
reconciliation and durable identity retention. The final full-suite count will
be recorded after the remaining integration checks. No upstream source was edited.

Completed foundations include the final A3 ABI (selector `0xdd789b6a`), exact
Go/Rust envelope and compiler fixtures, atomic snapshot/delta ingestion, separate
heartbeat freshness leases, bounded replay chains, content-addressed signed
artifacts, and durable exact-block manifests. Replay re-verifies the original
signatures and exact ordered transaction bindings. A test executes with the old
snapshot, applies a current ban, restarts, and proves original block replay still
succeeds while current execution denies. Renewing a ticket between execution and
assembly cannot replace the envelope that actually executed.

CREATE began with a red actual-EVM deployment regression. After adding the gate,
constructor bytes and the actual EVM-derived address reach the generated policy.
An execution-local ownership overlay supports nested CREATE/CREATE2 and calls
into successful children later in the block. Existing foreign registrations
remain authoritative. Frame and transaction rollback discard unsuccessful
creations. A red estimation test exposed ownership leaking between uncommitted
probes; each simulation attempt now starts with a fresh overlay.

The A4 record-party fixtures execute generated policy and getter bytecode in the
live interpreter. All eight getter outcomes pass, including changed parties,
short/malformed returns, revert, out-of-gas, and oversized return data. Review
identified a cross-organization read oracle through getter child calls. The
private frame driver now checks every child code/storage account against the
policy organization and separately guards BALANCE/EXTCODE account observations.
A scope violation aborts the entire policy evaluation, so a getter cannot catch
and conceal it. Adversarial tests cover foreign calls and account observations;
a same-organization proxy getter remains valid. Original application gas/state
isolation checks still pass.

The real-node smoke script passed against an isolated Shanghai chain. Signed
facts enabled scoped `eth_call`, `eth_estimateGas`, and `debug_traceCall`; public
unsigned calls and the public `ops_*` namespace remained denied/unavailable.
A signed call was mined in block 1, then a deployment in block 2 at
`0x2946259e0334f33a064106302415ad3391bed384`. Both blocks self-imported using the
durable local evidence. A later ban denied current simulations and prevented
nonce 2 from receiving a receipt. Evidence from that run is at
`.tmp/ops-reth-smoke-w0yrsglo/result.json` and `node.log` in the integration worktree.

The smoke also confirmed that Reth retries an invalid pool entry in later
candidate blocks: the banned nonce was denied in candidates 3, 4, and 5. A policy
denial must therefore be treated as current status rather than final eviction.
Status persistence retains pending/denied outcomes and canonical receipt-bound
creation metadata. Slot cleanup preserves the signed transaction's durable
principal/org binding, preventing rebinding after expiry, inclusion, or restart.

Explicit unsupported boundaries currently include EIP-7702/delegated code,
SELFDESTRUCT, custom precompiles, transaction-index traces, and privileged
`dry_run=true`. Complete OPS orchestration, admin diagnostics, and the broader
stack acceptance suite remain coordinated parent-task work; node unit tests are
not presented as proof of that entire user workflow.

The extended real-node run `.tmp/ops-reth-smoke-1i0owpq4/result.json` additionally
passed canonical creation status, facts/status recovery after restart, and scoped
admin diagnostics over the private HTTP listener. A banned impersonated user's
same-organization call returned the execution result plus `would_allow:false`;
a foreign registered target returned an error with no output. Diagnostic mode
cannot run a real transaction and guards direct account observations as well as
frames. The former `dry_run=true` unsupported boundary is now removed.

Independent review found two follow-up issues and both received regressions:
getter traversal now checks the original account bytecode before Reth's EIP-7702
normalization can conceal delegation, and renewed admission clears a prior
canonical marker so a post-reorg ticket survives restart. Durable principal/org
binding remains enforced after pending-slot cleanup. Ticket expiry is reported as
current lease status, not final eviction, because a previously pinned candidate
can still settle. OPS must continue receipt reconciliation for denied/expired work.

Final importer facts extend the ABI with `storageDeployer` and `storagePending`
(selector `0x9f0a7e8f`). The signed named principal determines the relationship;
an actual CREATE overlay supersedes stale preregistration metadata while the
registered organization remains authoritative. Constructor rollback removes
those provisional relationships. Cross-language compiler vectors pass.

Candidate previews have a separate ephemeral program/report and preserve the
active policy gate. Runtime regressions prove that an allow-all candidate cannot
bypass active denial, a denying candidate reports its verdict without changing
an allowed application execution, and candidate mode cannot execute a real
transaction. Candidate payloads require an explicit nullable artifact and verify
the artifact runtime digest.

Canonical receipts are no longer treated as finality evidence. Status includes
required `finalized` and nullable finalized hash/number, populated only from
Reth's finalized forkchoice header with canonical block checks. Tests reject
receipt-only, below-height, mismatched-fork, and pending-status finality. OPS
projects ownership only after this evidence. The pinned dev miner's default
finality depth is 64; the local smoke explicitly uses 1. Its restart hash window
begins at the current tip, which is a dev-consensus limitation documented in the
runtime README rather than an external finality guarantee.

After these slices, the complete offline SDK regression suite passed 69 tests.
The candidate wire validation regression was added afterward and is validated
separately alongside the final launcher build and real-node smoke.

The A5 real-node run `.tmp/ops-reth-smoke-c5n359o_/result.json` passed signed
simulation and submission, real CREATE/self-import, canonical finality checked
against a chain header, candidate preview without activation, active-policy
revocation despite an allowing candidate, scoped diagnostics, and restart.

Further independent review found that an unpublished candidate getter could
reveal a same-organization data predicate beyond its active application rule.
The regression reproduced that behavior before the fix. Ordinary candidate
programs now cannot issue child calls or observe accounts/storage (including
BALANCE, EXTCODE*, SELFBALANCE, SLOAD, and TLOAD). That aborts the whole preview
without returning a predicate. Scoped human diagnostics may evaluate the getter.
A generated recordParty integration test proves approved active getters still
work, ordinary candidate getters reject, and scoped diagnostic getters work.

A separate regression reproduced a mismatched signed implementation pin being
ignored by a private proxy getter. The fixed private read driver passes live
account code hashes into authorization for all descendants and account reads,
including precompile records. Diagnostic account guards honor the same pins.
The focused five-suite run passed; generated getter tests now total seven.

Final runtime checkpoint: all **75** SDK integration tests passed in the complete
`cargo test --release --offline --locked --features reth-sdk --test '*'` run
(10.39 seconds including incremental compilation). All-target SDK Clippy with
`-D warnings` passed. The upstream `proc-macro-error2` future-compatibility notice
remains informational.

The final binary smoke `.tmp/ops-reth-smoke-2cgnbx5_/result.json` passed all prior
checks plus independent candidate live-read isolation: ordinary candidate account
reads returned no output, scoped human diagnostic reads worked, active calls
remained unchanged, and current bans could not be bypassed. Call/CREATE landed in
blocks 1/2 with verified chain finality and durable recovery after restart. The
launcher advertises `per_frame_a5`, `candidate_simulation_v1`,
`scoped_diagnostics_v1`, and `finalized_status_v1` alongside the base protocol
capabilities. The full OPS workflow harness is owned by the stack integration
agent and remains separate evidence from this node checkpoint.

Root review identified a simulation override oracle: an authenticated allowed
selector could be combined with caller-supplied replacement bytecode that reads
hidden storage. The actual old binary reproduced it in
`.tmp/ops-reth-smoke-t2saknyg/node.log`. Signed request parsing now rejects every
nonempty state/code/storage and block override in normal, candidate, and admin
modes. The launcher never installs user overrides; tracing options remain
available. The adversarial signed-wire test went red→green, all 11 signed-wire
and 5 private-transport tests passed, and all-target SDK Clippy passed. Actual
rebuilt-node validation passed in `.tmp/ops-reth-smoke-813uz2ye/result.json`,
including hidden-storage code replacement and block override rejection plus the
existing functional lifecycle checks.

## Load measurement (harness path, development miner)

`node/reth/scripts/load.py` against the final guarded binary
(`db99022795bb…`), report `.tmp/ops-reth-load-ng_73021/result.json`, run on
2026-09-17. This measures the whole signed-wire path of the harness — identity
issue, signed submission over the private API, the development miner at 1 s
blocks, and status/receipt reconciliation — not the isolated cost of a policy
frame. It is a correctness-under-load and memory check, not a throughput claim.

| Setting | Value |
|---|---|
| Host | Apple M2 Max, 12 logical CPUs, 32 GiB; shared with the running OPS/explorer stack and Go test runs, no CPU isolation |
| Workload | 4 phases × 3 rounds × 512 signed transactions, 8 senders, concurrency 8, 1000 principals in facts, 150 M block gas, cross-block cache 64 MiB |
| Phases | `plain` (1 checked frame/tx), `nested` (3 frames/tx), `record-party` (live getter read in the policy frame), `churn` (fact deltas published every 0.25 s during the run) |

| Phase | Admitted / mined / correct | Wall s | Mined tx/s | Admission ms p50 / p95 / p99 | Submit→inclusion ms p50 / p95 | Peak RSS MiB |
|---|---|---|---|---|---|---|
| plain | 1536 / 1536 / yes | 139 | 11.0 | 352 / 529 / 1400 | 25 829 / 43 222 | 333 |
| nested | 1536 / 1536 / yes | 144 | 10.7 | 355 / 472 / 539 | 28 787 / 41 088 | 330 |
| record-party | 1536 / 1536 / yes | 139 | 11.1 | 366 / 456 / 510 | 24 996 / 35 026 | 328 |
| churn | 1536 / 1536 / yes | 160 | 9.6 | 452 / 643 / 710 | 27 540 / 43 600 | 336 |

Every phase also verified a denied probe (`admitted: true`, status `denied`) and
reconciled all 1536 canonical statuses. `churn` applied 398 fact publications
during the run (p50 303 ms, p95 611 ms, max 2.7 s, no errors) with no wrong
verdicts. Three checked frames per transaction cost no measurable throughput
against one frame; the live record-party read did not either. Node RSS rose
from ~120 MiB to ~335 MiB in every phase and is dominated by the explicit 64 MiB
execution cache plus receipts/status retention, not by policy state (policy
archive on disk: 32–45 MiB).

What this does **not** show: the roadmap's 5,000 TPS target. The harness is
bounded by its own admission path (~350 ms p50 per signed submission at
concurrency 8) and by 1 s development blocks; inclusion latency is queueing in
that path, not policy evaluation. A throughput claim needs an isolated host, a
block-production configuration matching the deployment, and a per-frame
measurement inside the node — none of which this run had.

## Per-frame cost of a policy check (2026-09-17)

The number the load harness could not give. `node/reth/tests/frame_cost.rs`
(`cargo test --release --features reth-sdk --test frame_cost -- --ignored --nocapture`)
runs the real inspector on the real EVM in-process: the fixture policy from
`internal/policydsl/testdata/lifecycle-v1.json` (compiled with the pinned solc;
three rules — org wildcard, EOA transfer, create), facts for 1 000 and 10 000
principals through the production `FactsPolicy` encoder, and an application
contract that forwards its call to itself so a transaction has exactly 1, 2 or 3
checked frames. 2 000 transactions per configuration after 200 warm-up; the
same transaction on a stock EVM without any policy is the baseline. Apple M2
Max, single thread, `InMemoryDB`, shared workstation. Timing comes from
`PolicyFactory::timed()` (new), which records per active check the fact
preparation time, the policy frame time and the gas the frame used.

| Frames/tx | check() µs mean / p50 / p95 / p99 | of which facts→calldata | gas per check | tx wall µs: no policy → with policy | overhead per frame |
|---|---|---|---|---|---|
| 1 | 17.7 / 17.4 / 20.0 / 22.9 | 1.9 µs | 6 436 | 0.8 → 18.7 | 17.9 µs |
| 2 | 18.0 / 17.5 / 21.5 / 25.1 | 1.8 µs | 6 436 | 1.1 → 37.7 | 18.3 µs |
| 3 | 17.9 / 17.5 / 18.6 / 22.1 | 1.9 µs | 6 436 | 1.4 → 55.8 | 18.2 µs |

(10 000 principals; the 1 000-principal rows are within noise of these — the
fact index is a hash lookup, so principal count does not enter the frame cost.)

Reading: **one checked frame costs ≈ 18 µs of node CPU and 6.4 k node-internal
gas** with this policy, and the overhead per frame equals the check itself — the
inspector adds nothing measurable around it. Against the roadmap workload:
5 000 tx/s × 3 frames = 15 000 checks/s × 18 µs ≈ 0.27 core-seconds per second,
i.e. about a quarter of one core at 1 s blocks (9 % at one frame per
transaction). Policy evaluation is therefore not what bounds the harness's 11
tx/s; the signed admission path and the development miner are.

What the measurement also found: the node printed one `OPS_POLICY_DECISION`
JSON line to stderr for **every allowed transaction** (a PoC diagnostic that had
survived into the runtime). With it on, the overhead per frame was 48–63 µs —
the synchronous serialization and write cost more than the policy check. The
print is now off by default and enabled with `OPS_POLICY_DECISION_LOG=1`; OPS
receives every outcome through the identity record regardless. Before/after:

| Frames/tx | overhead per frame, print on | overhead per frame, print off |
|---|---|---|
| 1 | 62–64 µs | 18–21 µs |
| 2 | 51 µs | 18 µs |
| 3 | 48 µs | 18 µs |

Limits of this measurement: one fixture policy with three wildcard rules — a
policy with many selector and argument rules runs more Solidity per check and
costs more gas, roughly in proportion to the rules the generated code evaluates
for the frame's target, so the acceptance stack's real policy should be
re-measured the same way before quoting a number for a customer configuration;
in-memory state (real state access is paid by the application frame with or
without a policy); one core, no block-building concurrency; a shared laptop.
Reports: `.tmp/frame-cost-report.json` (print on), `.tmp/frame-cost-report-nolog.json`
(print off).

## Where the stack's throughput actually goes (2026-09-17)

With the policy check at ≈18 µs per frame, the end-to-end ceiling the load
harness saw (≈11 tx/s; admission p50 352 ms at concurrency 8, submitting
directly to the node's private API) has another cause. `Runtime::accept_identity`
(`node/reth/src/runtime.rs`) takes the single `ingestion` mutex and, for every
transaction-scoped identity, does `archive.put` (temp file, `sync_all`, hard
link, directory `sync_all`), `set_pointer("tx-…")` (temp file, `sync_all`,
rename, directory `sync_all`) and `remove_pointer("terminal-…")`; canonical
reconciliation later adds another `put` + `set_pointer`. On macOS Rust's
`File::sync_all` is `F_FULLFSYNC`, measured here at **4.6 ms p50 / 8.5 ms p95
per call** (plain `fsync` is 0.03 ms), so one admission costs roughly 20–25 ms
of serialized disk time and reconciliation about as much again — a ceiling of a
few tens of transactions per second on this machine, and a few hundred on a
Linux host with ordinary `fsync`, independent of OPS, the load generator and the
policy.

Consequence for any load test (GasStorm included): until identity durability is
batched — one `sync_all` per block or per bounded interval for all identities
accepted in it, which keeps DECISION §3.4's "identities durable before the payload
is published" — the measured number will be the disk's full-sync rate, not the
system's. This is a design change to the node's admission path, not a tuning
knob; it is the next item before quoting throughput.

## Node durability per transaction, per block and per fact change (2026-11-03)

The admission bottleneck described in the previous section is removed. These
counts are proven by tests against an in-memory filesystem model that counts
every write and `sync_all` (file and directory; the one parent-directory sync
when a new 4096-block manifest directory is created is not modelled) and keeps
only synced state
across a simulated crash (`node/reth/tests/common/mod.rs`):

| Event | Before | Now | Test |
|---|---|---|---|
| Identity admission (`ops_submitTransaction`) | 4 `sync_all` under one mutex, 3 signature checks | **0 storage operations**, 1 signature check, off the async workers | `admission_performs_no_storage_io`, `submission_performs_no_storage_io_and_verifies_once`, `identity_verified_once_per_submission`, `verification_and_admission_run_off_the_async_worker` |
| Candidate execution of a transaction | 4 `sync_all` per build attempt | **0** | `candidate_execution_writes_nothing_to_disk` |
| Produced block | 2 per transaction (envelope) + 4 per transaction (status) + checkpoint re-put of every record + 2 (manifest) | **2** (one manifest file and its directory) | `one_manifest_publication_per_block` |
| Snapshot or delta | checkpoint re-put of every record since the snapshot | **6** (record, record list, head pointer), independent of chain length | `fact_record_written_once_before_install_independent_of_chain_length` |
| Heartbeat | checkpoint re-put | **0**; it travels in the manifests of the blocks it made fresh | `heartbeat_never_written_separately`, `replay_after_snapshot_expiry_uses_embedded_heartbeat` |
| Restart | read and verify every `tx-` identity ever stored | reads the layout marker, the fact head, its chain's record lists and records only | `restart_reads_are_independent_of_history` |

A block manifest embeds the decoded identity envelope (key id, exact signed
payload, signature) and outcome of every transaction, the id of the durable
fact record list, and the heartbeat that made the facts fresh, compressed with
zstd in a single-file segment with a checksummed index. The fact-change cost is
constant in operations; its bytes grow with the record (a snapshot can be large)
and by one id per record in the list. The fixture's 200
transactions compress to less than a third of their JSON envelopes. Facts are
installed only after their records are durable, by one serialised writer; a
candidate block refuses facts without a durable record list.

A record list names only its own record and the list of the generation it
extends (independent review, finding 6). Before, each list named every record
of its chain, so a chain of k deltas wrote about 110·k bytes per delta: at one
delta per second, about 270 GB of lists over the 7-day retention. After 300
deltas the largest list is now 378 bytes and all 301 lists take 113 KB; the
same run wrote a 33 KB list before
(`record_lists_grow_linearly_and_replay_walks_the_chain`, which also replays
blocks built on the first, second and last generation, before and after a
restart). Replay and restart walk the chain back to its snapshot (lists read
with a 4 KiB bound) and check every link: the record and version a list names,
its chain length and snapshot version against the list it extends; then the
restored generation must reproduce each list field for field
(`a_list_that_does_not_link_into_its_chain_is_refused`, which checks which of
the two passes refuses each tampered list). A chain at the limit of 8192
records restores (`the_longest_chain_restores_through_its_lists`, 2.8 s for
the whole file in release). A crash after every storage operation of the third
delta of a chain (v4 on v1 to v3) leaves the
old or the new generation, every earlier block replays, and the chain continues
from what survived (`crash_at_every_step_of_a_chained_delta_keeps_every_block_replayable`).
Replay still re-applies every delta of the chain, and now reads one list per
record as well (at most 8192 of each per replay or restart). Collection keeps
every list of a chain a retained block or the installed facts reach, and lets
the chain go once a newer snapshot is the lowest base
(`a_delta_chain_keeps_every_list_its_retained_blocks_reach`, which fails with
the old "below the lowest facts version" bound). The layout is now 4; a
layout-3 directory is refused (`an_earlier_layout_is_refused`).

Crash cases run in process against the same model: a crash before or after the
manifest's file or directory sync, between a fact record and its head pointer,
and between the head pointer and installation. Every block whose assembly
returned replays after restart, and neither the live nor the restored facts go
backwards (the lease may: heartbeats are not persisted, so a restarted node is
fresh again at the publisher's next heartbeat).

Two builds of one block can publish at the same time (Reth builds an empty
payload beside the one in flight when it has no best payload yet). The build
that loses the link compares the evidence of the manifest that won, as a later
republish does, and is accepted when the transactions, principals,
organizations, signers and outcomes agree, once the winner's directory entry
is durable (`concurrent_publication_of_equivalent_evidence_is_idempotent`,
which crashes right after and finds the winner's manifest); a byte-identical
winner counts as existing too (`concurrent_publication_of_the_same_manifest_is_existing`),
and other evidence is still refused
(`concurrent_publication_of_other_evidence_still_conflicts`).
Before, the losing build compared raw bytes, which include the lease and the
record list, so its block assembly failed (independent review, finding 5).

A live run (`node/reth/scripts/crash.py`, 2026-11-03, seed 1410, 36
transactions, binary `60bc930ad306…`, report
`.tmp/ops-reth-crash-ejo1gfqj/result.json`) stopped the node eight times, with Reth's
persistence threshold set to 0 (not the default), so each new head is written at
once, asynchronously. SIGKILL hit, twice each, a batch waiting in the pool, a
built block with the batch before it became the chain head (lost: it never
became the head), and the first 50 ms after it became the head (lost: not yet
written). Kills lost up to the two newest committed blocks; every block Reth had
reported saved survived. One SIGTERM stop restarted with the batch restored to
the pool from Reth's backup: without identities it did not execute, and its
resubmission was accepted. After every restart the node was ready with its
facts, every status request for a transaction without a receipt (28) was
refused, every transaction in a surviving block reported `included` from its manifest,
every resubmission was accepted and included, and the chain kept importing its
own blocks. A last SIGKILL and restart without new facts read all 36 inclusions
from disk, with no replay or manifest errors.

That run showed an open risk: with `--dev.finality-depth 1` the forkchoice
update that makes a block the head also finalizes it, so the node could report
`finalized: true` for a block that a crash then lost, while OPS treats a
finalized outcome as permanent (registration and visibility). The node now
reports finality only up to the lower of the forkchoice-finalized height and the
height Reth has written (its persisted-block notification, used only while it
names a canonical block; before the first one, the height written at startup),
and never takes it back (`finality_reported_only_up_to_persisted_height`).
`crash.py` now asks for every included transaction's status the moment its
block becomes the head, and after each restart checks that every transaction
reported finalized kept its block. With the cap disabled it failed at once (a
transaction reported finalized had no receipt after the kill). With the cap
(2026-11-03, seed 1410, 28 transactions, binary `681a09f55d44…`, report
`.tmp/ops-reth-crash-s7zw80_7/result.json`) every kill kept every finalized
transaction (28 at the end) and all other checks passed. The startup height
and every persisted-block notification count only while they name the
canonical block, and finality evidence is withheld if the finalized block is
no longer canonical (`stale_finality_is_no_evidence_after_a_reorganization_below_it`).

The node releases a pending identity itself once its canonical block is final
and written, from its own chain, woken by Reth's finalized and persisted
notifications on a maintenance thread (never on the block path); a
reorganization before finality keeps the identity, so the transaction executes
again without OPS (`identity_released_at_finality_not_inclusion`,
`reorg_before_finality_reexecutes_without_ops`,
`release_scans_only_heights_finalized_since_attach`). A block at or below the
final height is never published (`no_block_is_published_at_or_below_finality`).
The node refuses a database sync mode other than durable
(`non_durable_database_is_refused_at_startup`): "written" must survive a host
crash.

A guarded node imports blocks at or below its finalized head on its canonical
chain without manifests: only those blocks' own transactions execute, with no
policy (`finalized_ancestor_without_manifest_imports_with_pass_through_policy`);
unknown finality, a rival hash at the height, a block above finality, a
finalized hash that is not canonical (a prospective forkchoice declaration) or
above the best block, a block below finality that is not canonical, an engine
payload and another network's block still need the manifest
(`every_other_import_needs_its_manifest`,
`another_networks_block_is_never_trusted`). This applies to history the node
already holds; first-time imports have no known finality for their blocks.

## Private listeners (2026-11-03)

Tests in `node/reth/tests/lanes.rs`, over real loopback connections:

| Behaviour | Test |
|---|---|
| Above its cap a listener answers a submission `503` with `Retry-After: 1` and closes the connection, but still serves status; requests within the cap complete | `listener_over_capacity_returns_503` |
| A connection is recycled with `Connection: close` on the first response after its lifetime; a submission in flight at that moment completes | `connections_are_recycled_after_a_complete_response` |
| While every execution connection waits for a fact version, the control listener applies it at once and the waiters are admitted; with one listener, publication over the cap applies too; the control listener refuses execution methods before any work | `control_lane_applies_facts_while_execution_lane_is_saturated` |

The previous listener dropped connections above 128 without an answer and cut
every connection after 60 s, including a request in flight. With overflow
serving and recycling disabled, all three tests fail. `smoke.py` publishes facts
through `OPS_NODE_POLICY_CONTROL_LISTEN` and checks that it refuses a submission.

Unauthenticated peers (independent review, finding 2), and the timeout answer
(finding 3):

| Behaviour | Test |
|---|---|
| A request with a wrong token is answered `401` with `Connection: close`, and the connection closes | `unauthorized_request_closes_the_connection` |
| A connection that starts no request is closed at the first-request deadline; an authenticated one stays open past it | `silent_connection_is_closed_at_the_first_request_deadline` |
| 82 silent connections (more than the cap of 2 plus the 64 overflow places) and 8 failed authentications take no place: two submissions are still served within the cap, a third gets the over-capacity `503` with `Retry-After: 1`, status is served | `unauthenticated_connections_never_take_the_cap` |
| With the cap and the 64 overflow places held by authenticated connections, a further one is answered `503` with `Retry-After: 1` and closed (it was closed unanswered before) | `authenticated_connection_beyond_the_overflow_is_answered_503` |
| Fact publication on an overflow connection held past the processing bound is answered `503` without `Retry-After` (it may have run) | `timed_out_answer_on_an_overflow_connection_has_no_retry_after` |
| A `401`, and the `503` beyond the overflow, are sent only after the request body was read, so a client writing its body in parts never hits a reset | `refusals_before_admission_read_the_body_first` |
| 76 silent connections beside an idle admitted connection and a submission in flight: the oldest waiting connection is closed, the submission completes `accepted`, the idle connection still answers | `evicting_unauthenticated_connections_never_cuts_an_admitted_one` |

The first five failed against the previous listener: a 401 kept the connection
open, a silent connection stayed until the 10 s header timeout, silent
connections took every place at accept (the submissions saw a closed
connection), and the timeout answer carried `Retry-After: 1`. The body test
failed against the first version of this change, which answered before the
body arrived.

## Public RPC guard (2026-11-03)

The independent review (finding 1) found public methods of the `eth` module
that re-execute a block through the guarded executor, so an anonymous caller
could make the node re-verify a block's whole evidence in a loop. Every public
method of the modules the node still serves was checked in the pinned Reth for
a path into the block executor or block building; seven have one and are
refused by name, alone or in a batch, with `-32601` before any work:
`eth_callMany` (with a `transactionIndex`), the four `eth_getBlockAccessList`
forms, `eth_simulateV1` (also off through its block limit) and
`reth_getBlockExecutionOutcome` (up to 128 blocks). The other 98 methods the
pinned Reth registers for the allowed modules (`eth`, `net`, `web3`, `txpool`,
`admin`, `rpc`, `reth`, `miner`, on HTTP and WS, listed from a node started
with all of them) are the reviewed list; the node refuses to start when a
public transport would serve any other method, so a Reth upgrade that adds one
fails closed, and the refused methods are also removed from every transport.
The node also refuses to start with `--auth-ipc`, which serves the engine API
without JWT.

| Behaviour | Test |
|---|---|
| Reth's own public server with the guard, HTTP and WS on separate servers and on one port: each refused method is answered `-32601` and its handler never runs, alone and inside a batch mixed with ordinary methods; the ordinary ones run | `refused_methods_never_run_over_http`, `refused_methods_never_run_over_ws` |
| A refused method sent as a notification, alone, in a batch of notifications or beside a call, never runs (jsonrpsee 0.26 never runs a notification anyway; the test pins that) | `refused_notifications_never_run` |
| An unreviewed public method refuses startup; otherwise the refused methods are removed from every transport | `startup_guard_refuses_unreviewed_methods_and_removes_refused_ones`, `reviewed_and_refused_methods_are_disjoint` |
| `--auth-ipc` is refused at startup | `unsafe_public_rpc_is_refused_at_startup` |

With the guard switched off, both server tests fail (the handlers ran), and
the startup test fails for `--auth-ipc`. `smoke.py` starts the node with
`--http.api eth,net,web3,reth` and every allowed module on WS (so the startup
guard checks the whole reviewed list), sends each refused method to the live
node, alone and in a batch with `eth_getBlockByNumber`, and checks the fixed
error, while block reads, receipts and the public `eth_call` refusal stay as
before.

## Bounded fact wait and self-import (2026-11-03)

| Behaviour | Test |
|---|---|
| A submission whose floor is above the fresh installed facts waits and is admitted when publication brings the version; after the bounded wait it gets `-32012` and nothing is registered | `admission_waits_for_min_version_then_fails_with_32012` |
| Stale or missing facts are refused at once with the generic error | `stale_or_missing_facts_fail_at_once_without_waiting` |
| At most the configured number of requests wait (default 32); more, and a zero wait, get `-32012` at once; `fact_wait_v1` is not advertised with a zero wait | `waiters_are_bounded_and_zero_wait_refuses_at_once` |
| Simulations wait for their floor too | `simulation_waits_for_its_floor_too` |
| A block the node has just published imports once from its recorded, verified execution, without reads or signature checks; any other body, hash or network, a second import and forensic replay read the manifest | `own_block_imports_from_memory_without_reading_or_verifying`, `another_block_body_or_hash_never_uses_the_cached_execution` |
| A rebuild that kept the earlier archived evidence imports that evidence; at most 8 blocks are held | `a_rebuild_that_kept_earlier_evidence_imports_that_evidence`, `the_cache_is_bounded` |

Measured in process (`self_import_cost`, release build, the fixture's policy):
preparing the import of a 2,000-transaction block (reading and verifying its
manifest's evidence, not executing it) took 78 ms from the manifest and 0.5 ms
from memory, so the cache is kept. At or below finality the cache is not used. With the wait disabled the three wait tests fail;
caching a rebuild's execution fails the rebuild test.

## Retention, compaction and fact-record collection (2026-11-03)

Tests in `node/reth/tests/retention.rs`, against the in-memory filesystem
model:

| Behaviour | Test |
|---|---|
| Finalized canonical manifests are compacted into segments; segments past the retention are deleted, and the record list and records no retained block uses go with them; retained blocks still replay | `prune_removes_manifests_after_retention_and_unreachable_records` |
| A candidate still building on older facts keeps their records and publishes its block, which replays | `pinned_old_facts_build_keeps_records` |
| Blocks on unchanged facts share one record list, kept while any of them is retained | `parent_record_list_survives_parent_prune` |
| Discarded builds at a final height are removed; above finality nothing is | `repeated_discarded_payloads_are_reclaimed_below_finalized` |
| A run removes at most 1,024 files in total and reports more work | `prune_run_is_bounded` |
| A retained segment, or an unfinalized block file, alone keeps the older facts it uses | `a_retained_segment_alone_keeps_its_older_facts`, `an_unfinalized_block_file_alone_keeps_its_older_facts` |
| A crash after each storage operation of a prune and collection keeps the installed facts and retained evidence; the first run after a restart collects what the crash left | `crash_during_collection_keeps_the_head_and_retained_evidence` |
| `forever` never deletes canonical evidence | `forever_never_prunes_canonical` |
| A segment lookup reads the footer, the index and one entry, not the segment | `segment_lookup_reads_footer_index_and_one_entry` |
| A crash after every storage operation of a compaction (temp write, link, directory syncs, each unlink) recovers with every canonical block found exactly and no discarded build resurrected | `crash_at_each_segment_publication_step_recovers_with_exact_lookups` |
| The retention setting and an earlier layout | `retention_setting_accepts_forever_and_whole_durations`, `an_earlier_layout_is_refused` |
| Retained blocks on the last delta of a chain keep every list and record back to its snapshot; a newer snapshot lets the chain go once its blocks are pruned | `a_delta_chain_keeps_every_list_its_retained_blocks_reach` |

Collection deletes by version range: snapshot versions strictly increase, so
each fact chain occupies its own version range, and a record list never names a
record older than its chain's snapshot. Lists and records below the lowest
snapshot version over every root (retained segments and
block files, the installed facts, every candidate still building, registered
under the fact-stream lock and read before any listing) are deleted. With the
tests' maintenance disabled, seven of them failed (before the delta-chain test
was added); with pinned candidates ignored
as roots, the pinned-build test fails; with segments and block files ignored as
roots, the two single-root tests fail. Live runs (`crash.py`, `smoke.py`) are
shorter than a compaction batch (256 finalized blocks), so compaction is proven
in process only. `crash.py` passes on this layout (2026-11-03, seed 1410, 36
transactions, binary `3302374c6a66…`, report
`.tmp/ops-reth-crash-ted0o6q2/result.json`).

## Delivery contract on the node (2026-11-03)

Tests in `node/reth/tests/delivery.rs` and the `identity` unit tests:

| Behaviour | Test |
|---|---|
| Every private response names the process's boot; a restart changes it, and the same still-valid envelope is admitted again | `boot_id_changes_on_restart_and_resent_envelope_is_admitted` |
| An expired envelope is refused | `expired_resend_is_rejected` |
| An older identity the registered one dominates is an idempotent success under its own context; a higher floor with a lower expiry, another principal or organization is refused | `older_identity_for_same_principal_and_binding_is_idempotent_success` |
| "Nonce too low" and an underpriced replacement return `-32013` with the reason and release the slot; "already known" is accepted; other pool failures keep the registration | `pool_rejection_releases_slot_and_reports_reason`, `already_known_pool_error_is_an_already_pooled_transaction` |
| "Nonce too low" with the transaction's own receipt keeps the identity and is accepted | `resend_of_an_included_transaction_keeps_its_identity`, `nonce_too_low_with_own_receipt_is_an_inclusion`; live: `smoke.py` check `included-resend-accepted` |
| A delayed failed send never removes a newer identity; a failed renewal restores the identity it replaced; a stale undo token removes nothing, and a replaced or restored lease's old expiry releases nothing | `failed_send_never_removes_newer_identity`, `failed_renewal_keeps_prior_identity_needed_for_reorg`, `expiry_removal_is_conditional_on_context` |
| The pool receives the signer recovered at admission (no second recovery) | `pooled_form_keeps_the_recovered_signer_and_hash` |
| Startup refuses replaying, simulating or block-building public modules, a forwarder and the debug reorg stream; public simulation builds no blocks | `unsafe_public_rpc_is_refused_at_startup`, `debug_reorg_stream_is_refused_at_startup`, `public_rpc_never_builds_candidate_blocks`; live: `smoke.py` check `public-simulate-builds-nothing` |

The startup check for public debug/trace modules compared the selection's
display text, `[eth, debug]`, with `debug`, so it never matched: a node started
with `--http.api eth,debug` ran with the debug module. The check now uses the
typed selection. Before the simulation block limit was forced to 0, an
unauthenticated `eth_simulateV1` request 100 blocks ahead published 99 gap-filler
manifests (`smoke.py`, run without the limit).

## Batched transaction status (2026-11-03)

Tests in `node/reth/tests/transaction_statuses.rs`, against a canonical chain
model, and the `main.rs` unit tests:

| Behaviour | Test |
|---|---|
| Entries in request order (a repeated hash answered at each position), an unknown hash `"not_found"`, the node's boot id, each entry equal to the single call's result plus `pooled` | `batched_status_answers_in_request_order_with_unknown_as_not_found` |
| 1 to 256 lowercase hashes and senders; more, none, uppercase, unprefixed, short or non-string values and other parameter shapes fail the call | `batched_status_takes_one_to_256_lowercase_hashes` |
| The finalized head is capped at the height Reth has written, every entry's finality is decided against it, and a finalized answer releases the slot | `finalized_head_is_capped_at_the_written_height` |
| No finality evidence (and no nonce read) while finality is unknown, only genesis is final, or the finalized header cannot be read | `finality_evidence_is_withheld_when_unknown_genesis_or_unreadable` |
| With senders: each hash's receipt presence (unknown for a failed lookup, whose entry is then `null`, never the registry's "pending") and the senders' nonces, read once per call at exactly the finalized hash; without senders, neither field and no state read | `dropped_evidence_reads_receipts_and_nonces_at_the_finalized_hash` |
| A pending transaction no longer pooled is reported so (eviction); an included one never is; a pooled transaction without an identity is `"not_found"` | `pooled_tells_a_pending_transaction_from_an_evicted_one` |
| A transaction OPS saw included in a block a crash lost (never written) is `"not_found"` after the restart in the batch and `-32014` from the single call, distinct from a failed lookup (`null`, `-32000`); once delivered again it is `pending` (P7 L1, N7) | `a_transaction_in_a_block_lost_by_a_crash_is_not_found_after_restart` |
| Live: after every restart of `crash.py`, every transaction without a receipt (in a block the kill lost, or never included) is `-32014` and `"not_found"`; four of the eight stops lost a block with transactions (2026-11-04, seed 1410, report `.tmp/ops-reth-crash-elhd8luw/result.json`) | `crash.py` |
| The canonical epoch stays on appends and on replaced blocks no answer named, and changes when a block named by a batched or a single status answer leaves the chain; the answer that sees a loss, also one during it, reports it and anchors its own blocks | `canonical_epoch_changes_when_a_reported_block_leaves_the_chain`, `a_change_during_an_answer_is_reported_by_that_answer`, `the_answer_that_reports_a_change_anchors_its_own_blocks`, `a_block_named_below_the_highest_is_still_watched_after_a_change` |
| Named blocks at or below the finalized block are no longer watched | `named_blocks_at_or_below_finality_are_no_longer_watched` |
| A block that left the chain while an answer was prepared is never named in it, also as a receipt of a hash without an entry | `a_block_gone_by_the_end_of_an_answer_is_never_named` |
| The finalized block is fixed before any transaction is looked up: a block finalized meanwhile decides nothing and the nonces are read at the earlier one | `the_finalized_block_is_fixed_before_any_transaction_is_looked_up` |
| A canonical block without local evidence gives `null` | `included_without_local_evidence_is_null` |
| After a restart one call loads at most 16 uncached blocks; the next answers the rest | `a_call_loads_a_bounded_number_of_uncached_blocks` |
| The single `ops_transactionStatus` shares the batched call's lane: eight concurrent single calls run four at a time (all eight ran at once before, independent review finding 4), and a batched call waits behind them | `single_status_calls_share_the_bounded_status_lane` |
| Without a chain or a pool view the call fails | `batched_status_fails_closed_without_chain_or_pool_view` |
| Not served on the control listener; answers while every admission worker is held | `batched_status_is_served_only_on_the_execution_listener_off_the_admission_pool` |
| Startup refuses pruning of the transaction index, receipts or bodies | `pruning_of_transaction_data_is_refused_at_startup` |

With the genesis rule, the cold-block budget, keeping named blocks after a
change, pruning them at finality, dropping blocks gone during an answer, or
reading the finalized block first disabled, the corresponding tests fail. `smoke.py` check `batched-status`
compares a live answer with Reth's public view: the finalized head's number
and timestamp with its header, the sender's nonce with
`eth_getTransactionCount` at that block hash, the receipts with the
transactions' inclusion, each entry with the single call, `pooled` with
`eth_getTransactionByHash` for a pending transaction, and, after a restart, a
new boot id and `"not_found"` for a transaction restored to the pool without
an identity.

Not yet covered here: throughput, which is measured end to end through OPS
separately.


## End-to-end throughput through OPS (2026-11-03)

The V1 `poc/approval-performance/transactions.py` harness offered 5,000
requests/s for 60 seconds through OPS, PostgreSQL, Redis and the real node.
Identity was a local mock; linking, RBAC and preflight were real. V2 used
product defaults in Reth policy mode without preflight. Committed TPS counts
successful receipts observed inside the sending window; late receipts do
not increase it. The measured OPS code was `9279c400`.

Machine: shared Apple M2 Max, 12 cores, 32 GiB, macOS 27.2, OrbStack
PostgreSQL 15. Concurrent builds/tests raised load averages to 10–38; the
later exploratory runs were on battery. These are diagnostic workstation
measurements, not production capacity or a quiet-host acceptance run.

| Case | Best committed TPS | Median committed TPS | Best-run queue-to-commit p95 |
|---|---:|---:|---:|
| V1 signed approvals | 2,094.3 | 1,984.5 | 2.749 s |
| V2 guarded node | 1,788.1 | 1,778.0 | 3.095 s |

V2 reached 85.4% of the same-day V1 best and missed the original 1,962 TPS
and 2.84-second p95 targets. A gate-off run at higher contention measured
2,063.7 TPS. The measured manifest footprint was about 144 bytes per
committed transaction, with no admission syncs, no identity-capacity refusals
and no steady-state renewals. The saved intent let the keeper complete
requests canceled at the sending cutoff.

A separate diagnostic V2 run sampled OPS at about 3.3 CPU cores and the node
at 1.2 cores. The largest V2-specific costs were:

- OPS status reconciliation repeatedly parses each batched JSON response: a
  duplicate-key walk, field validation, decoding, and per-entry decoding.
  Its inclusive CPU samples were comparable to the whole request path.
- The node looks up each polled hash in unpersisted canonical blocks through
  Reth's transaction metadata lookup, scanning transactions across those
  blocks. This was the node's largest sampled user-CPU frame.

Potential improvements are one strict decoding pass, scheduling unchanged
transactions with fewer repeated polls while retaining restart/eviction/reorg
triggers, and a canonical hash-to-inclusion index for unpersisted blocks.
These are proposed optimizations; no throughput gain is claimed for them.

The initial live acceptance run also exposed two correctness failures: lost
unpersisted blocks left transactions provisional after a node crash, and
fact churn caused refusals for an unaffected principal. The definitive
`not_found` status and OPS redelivery fix are covered above and in
`node_crash_redelivery_test.go`; `node_policy_churn_test.go` covers notification
publication, bounded waiting and clock/cache races. Integrated live results
follow below.


## Integrated live recovery validation (2026-11-04)

`poc/approval-performance/live.py` ran against PostgreSQL, Redis, OPS and the
real guarded node on the shared workstation on AC power. Each scenario used
fresh databases and node directories, public development accounts, and
canonical receipts, private execution manifests and tracking rows as its
checks. OPS was built from `bd3c4a7b`; node source was `76eb7a6e`. The later
`f3b59166` change makes the Go congestion simulation's clock deterministic;
it changes test code only.

| Scenario | Result |
|---|---|
| SIGKILL under load (L1) | PASS: 9,000/9,000 accepted transactions included and finalized after three crashes, each under its own principal's identity, with no duplicate finalization. |
| Graceful restart (L6) | PASS: 6,000/6,000 included and finalized under their own identities. |
| Two-minute node outage (L7/L8/L10) | PASS: all 40 allowed transactions renewed, audited and included without client action; all 20 transactions of the principal banned during downtime stopped, were audited and never executed. Recovery-burst fact changes applied in 44.57 / 36.65 ms. |
| OPS downtime beyond fact TTL (L4) | PASS: node became unready after 27.9 s, executed no transactions while facts were stale, then included and finalized all 20 accepted transactions after OPS returned. |
| Reorg (L12) | PASS: the provisional deployment returned to pending, re-executed on the canonical chain and finalized once; ownership was registered once, for the deploying organization, after finality. |
| Fact churn (L5/L10) | FAIL overall on latency. All 18,000 transactions included and finalized; the 9,000 requests during churn had zero refusals; revocation was enforced immediately. |
| OPS failover (L3/L11) | FAIL overall on L11 coverage. All 10,000 transactions included and finalized; lease handoff took 0.93 / 0.25 / 0.36 s and publication after each handoff took 57.41 / 61.74 / 57.77 ms. |
| Congestion (L9) | PASS: 1,200/1,200 included, peak pending 464 against a limit of 564, no observed lease gaps, 639 renewals within the 20/s budget. |
| Overload and inclusion stall (L13) | PASS: backpressure held at 564; 554 transactions stopped at maximum age without observed early lease gaps or excess renewal debt. A finalized competitor consumed one stopped transaction's nonce: only that transaction became dropped, while the other 553 retained stopped bindings. |

During churn, added request p99 was **306.2 ms** (baseline 129.9 ms, churn
436.1 ms), above the 250 ms limit. The mutation-start to observed-node-apply
p95 was **307.01 ms**, above 100 ms. That measurement includes API work and
concurrent version changes. Separately, 94 observed database versions all
reached the node; first-database-observation to node-observation p95 was
163.3 ms. Database polling was every 50 ms and node polling every 5 ms, so
this is polling evidence rather than exact commit-to-apply timing.

The failover run did not establish the intended L11 crash windows: no
undelivered generation was observed after the first two OPS kills, and the
recovery kill happened before any renewal generation was recorded (0 before,
111 after). The preserved transactions validate the exercised handoffs;
interruption between saved intent and transport, and interruption during
renewal, still need deterministic live coverage. The churn and failover
reports remain failed.

The complete database package and the congestion simulation passed race
rechecks after correcting fixture isolation and the simulation clock. The
other packages in the broad Go race run passed, with no detected races.
API drift and repeat-generation checks, both SDK type builds, all 12 SDK
tests and 28 Python harness tests passed. Five changed documentation pages
parsed as MDX.
