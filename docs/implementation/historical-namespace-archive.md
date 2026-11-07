# Historical namespace archive

The archive records approved historical contract facts and namespace transfers.
It keeps these facts separate from the contract's current Git policy owner.
The library and offline command expose archive metadata and statement references;
they do not expose a historical permission decision or a complete history source.
Ordinary calls add no archive rows, jobs or checkpoint RPCs.

`internal/historynamespace` owns the immutable model, strict artifact parser and
semantic digests. `internal/operational/admissionsql` supplies the separate
`ops_history_namespace_v1` schema, owner operations and minimal reader.
Admission migrations 001, 002 and 003 and their schema version remain unchanged.

## Facts and trust

The fixed model `prague-ordinary-runtime/v1` describes surviving ordinary runtime
inside one explicitly approved continuous era. Its entry block/hash/time and
finite end time are immutable network settings. The command does not discover a
chain's fork schedule or extend the model to a future fork.

Before the era, finite attestations use an explicit physical lifetime UUID.
Inside the era, finite attestations and checkpoints share a key derived from the
network, address, ordinary runtime Keccak hash, length and semantic model version.
Labels, submission UUIDs, request IDs and observation clocks do not enter that
key. Each assertion retains its own interval or checkpoint boundary.

An in-era assertion explicitly distinguishes runtime that pre-existed era entry
from runtime born during the era. The initial namespace refers to that entry or
birth. A checkpoint cannot backdate runtime, physical birth or namespace.
An interval cannot straddle era entry.

Finite runtime, physical-start and transfer claims are approved attestations.
The importer validates their structure and original references; it does not
independently prove their canonicality or transaction counts. An archive reader
cannot turn these declarations into canonical facts merely by loading them.

Checkpoint runtime is independently acquired by an owned RPC client. One
operation checks chain/genesis/synchronization, reads a fully hash-qualified
header, reads code using EIP-1898 `blockHash` and `requireCanonical`, then checks
the header again. It permits one block and at most 128 distinct addresses under
one 15-second deadline: at most 136 physical RPC attempts, 1 MiB per code value,
8 MiB decoded code total and 18 MiB of consumed response envelopes. Raw envelope
bytes include JSON whitespace. Requests have no replay body, redirects or retry
loop. The selected RPC node is trusted to return code for the requested block;
this is not a Byzantine state-proof verifier.

The approved raw artifact declares checkpoint claims. Only the matched opaque
RPC proof fills the normalized stored proof digest. That digest binds immutable
source, network, model, header and code facts, independently of observation time.

## Artifact format

An artifact is one regular local JSON file, pinned by its exact approved SHA-256
digest. Symlinks, duplicate keys, case aliases, unknown fields, explicit nulls,
nesting beyond 12 and files above 4 MiB reject. The top-level fields are:

| Field | Meaning |
| --- | --- |
| `apiVersion` | `ops.history-namespace/v1` |
| `cohortId` | Canonical nonzero UUID for the submission |
| `network` | Explicit environment, chain ID, genesis hash and deployment ID |
| `modelId` | `prague-ordinary-runtime/v1` |
| `era` | Entry number/hash/timestamp and exclusive end timestamp |
| `statements` | Explicit nonempty array, at most 4096 entries |

Statement kinds are `pre-era-finite`, `prague-finite`, `prague-checkpoint` and
`transfer`. Lifetimes declare `address`, `runtimeHash`, `runtimeLength` and
`initial`. A label is either `{"kind":"public"}` or
`{"kind":"org","organizationId":"<canonical UUID>"}`.
Finite statements have `start` and `end` cuts; a pre-era statement also has
`lifetimeId`, and in-era statements have `physical`. A checkpoint uses
`checkpoint:{number,hash}` and has no transaction-index field or caller-supplied
proof digest.

`physical` is `{"kind":"preexisting"}` or
`{"kind":"born","birth":{number,hash,transactionHash,index,record}}`.
A born finite interval must start after the birth transaction. Actual canonical
and count qualification is separate from this parsed ordering.

Transfers contain `address`, `segmentKind` (`legacy` or `prague`), `segment`,
`initial`, `previous`, `new`, `effectiveFrom`, and optional `parent`.
Legacy transfers require `legacyBasis`; Prague transfers exclude it.
Parent labels and increasing cuts must agree. Original basis and parent
references may point into an older cohort. The importer checks original
assertion presence without treating it as canonical authority at the edge.

One cohort admits at most one checkpoint block and 128 unique checkpoint
addresses, matching the proof's exact address set. Other finite and transfer
entries may fill the overall 4096-statement limit. Missing, unused or mismatched
proofs reject the whole cohort.

## Original cohorts and capacity

Each immutable statement has one original cohort. An identical normalized
cohort retry returns that original cohort, raw digest and deny status, with zero
growth even at capacity. A different cohort that partially reuses existing
statements rejects atomically; submit only new statements. Old basis and parent
references remain valid references and preserve their original deny linkage.
No operation reparents a row or removes an original deny.

The default hard ceilings are 1,000,000 retained lifetimes, 1,000,000 transfers,
10,000 cohorts, 10,000 revoked cohorts, 32 lifetimes per address and 64 transfers
per segment. Bootstrap may lower these limits. Original, orphan and denied rows
count. A cohort commits in one transaction, with statement batches of at most
128; a cap or error rolls back every row and counter from that attempt.
These are contract-fact limits, independent of ordinary transaction volume.

Import results include lifetime and transfer IDs and segment keys in the
submitted artifact's lifetime/transfer split order. They support later approved
references without manual database queries. They confer no namespace authority.

## Owner command and recovery

`ops-v2-namespace` supports `migrate`, `bootstrap`, `status`, `import`, `revoke`,
`begin-recovery` and `finalize`. It reads its owner DSN from an explicitly named
environment variable. Checkpoint credentials use an explicit reference/header
and environment variable; their values are not returned or logged. RPC transport
does not use an environment proxy or follow redirects.

Mutations require `--acknowledge-drained`. Bootstrap additionally requires
`--acknowledge-never-initialized`: an empty restored database cannot prove that
no earlier archive was lost. `status` returns the source revision and generation
needed by later operations. Mutations bind both values exactly.

For import, pass `--artifact` and `--approved-sha256`. Supply explicit reference
RPC options only when the artifact has checkpoint statements. Read each import
receipt's original cohort and statement references before constructing another
approved artifact. `revoke` accepts at most 256 exact comma-separated cohort UUIDs
and either `source-compromise` or `restore-gap`; it has no un-revoke operation.

Begin recovery persists source unready before validation. Finalize requires an
explicit archive completeness digest and `--acknowledge-complete`. It validates
present rows, semantic digests, cohort membership, parent/basis references,
counts, capacities, schema and access controls. It reads cohort pages of 256,
closes each result set before dependent queries, and retains only one bounded
cohort's contents at a time. Strict parent-cut descent checks the complete graph
without serializing every ancestor path. Missing historical facts and original
node responses cannot be reconstructed from hashes; completeness remains the
operator's explicit restoration attestation.

`--recovery-timeout-seconds` is numeric, defaults to 600 and permits 1 through
1800, checked before conversion to a duration. This finite offline budget is not
a promise to finish every retained corpus on arbitrary hardware. Failure keeps
the earlier unready boundary. Existing admission recovery cannot certify this
source after its global generation changes; namespace recovery must bind and
validate that generation separately.

The reader is a dedicated role with SELECT on the five namespace tables and the
nine existing creation-fact tables. It has no user, travel-record, mutation,
sequence or custom-function access. Startup checks effective PUBLIC, inherited
and column privileges, ownership, RLS, triggers and exact schema definitions.
The owner credential belongs exclusively to offline operations.
