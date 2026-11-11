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

## Coherent namespace fact reads

The minimal reader also provides `DiscoverRequirements` and `ResolvePass` for a
bounded scope of actual included ROOT request coordinates. These are internal
fact APIs. They do not implement a protected-data source, mount a route, grant
current permissions or certify a complete transaction population.

The trusted acquisition caller supplies the exact network/model era, canonical
view identity and head, and sorted unique ROOT hash/block/index/time/target
coordinates. It is responsible for actual signed ROOT membership and target
acquisition. These Go DTOs are not unforgeable proof objects. A state-only read
has no included ROOT; callers cannot manufacture one to claim state authority.

Discovery reads all relevant assertions, original creation associations and deny
barriers. It returns only digests and required canonical block **numbers**, with
claimed hashes as metadata. The caller acquires actual canonical-at-number
headers and hash-list transaction counts outside SQL. An old orphan hash is not
a direction to fetch and bless that orphan. A header alone supplies no count.

Resolve independently reads and re-derives the whole requirements set and
compares its exact expected digest before using the supplied canonical context.
A new or changed requirement, missing count, wrong ROOT binding or unavailable
context fails without a fallback lookup or automatic discovery retry. Each pass
holds one read-only REPEATABLE READ transaction for the entire scope, including
every internal chunk of at most 64 addresses. No node, file or mutable provider
callback runs under that transaction.

All qualified positive assertions for an address/model are compared before
choosing a runtime key. A later valid birth may contradict a claim that ordinary
runtime pre-existed era entry, while supplying no earlier runtime support.
Ordinary calls must be strictly after birth by block and transaction index.
Factory CALL roots use their own target; they cannot borrow a child birth.
Root creation uses only its exact surviving automatic record-zero birth.

A finite assertion supports its `[Start, End)` interval only at an in-model
ROOT or applicable edge. A canonical End beyond the model end remains exclusive
boundary metadata and cannot prove post-era persistence. Its exact hash/count
is still required; an invalid or missing End is not clipped away. A checkpoint
supports ROOT calls only after block K, and transfer cuts at END-K's actual
transaction count or later. It cannot supply an earlier same-K cut.

Each transfer needs an independently eligible original basis at its own cut,
and a qualified, strictly increasing parent chain. Known applicable transfer
and deny barriers remain relevant after the original basis is revoked. A later
checkpoint cannot reset the namespace to the initial label. The same rule
applies across different normalized keys for the same address and continuous
model; orphan cuts, other models and ended pre-era physical UUIDs are separate.
Divergent positive histories conflict regardless of insertion order, including
histories that happen to end at the same label.

Current base and namespace readiness must match the reader's expected recovery
generation. Original immutable coverage retains its historical generation,
coverage digest and capture epoch. Valid historical evidence is not expired by
ordinary worker-head progress, capture heartbeat or lease expiry. Permanent
original epoch denies and durable observer quarantine still apply. Recovery
never rewrites original capture provenance.

A detached result is `KnownOrg`, `KnownPublic`, `Unknown` or `Conflict`, with
basis/transfer references and exact scope, requirements, canonical-context and
whole relevant authority digests. `KnownPublic` has no owning organization.
Protected organization cases must exclude public-only rows, address resolution,
aliases, counts and sanctions-address input; a public transaction does not make
an Actor-to-wallet association public. Unknown relevant population cannot be
reported as a complete empty result. Current Git ownership, current wallets and
Actor membership are not fallback namespace facts.

The acquisition caller must repeat the **whole** scoped pass before exposure
and compare its authority digest alongside its canonical and complete ROOT
population bindings. Independently valid 64-address snapshots cannot be
concatenated. No query state is persisted.

Per-pass ceilings are 10,000 roots, 32,768 canonical block requirements/candidates,
4 MiB canonical input, 8 MiB canonical candidate payloads, 4 MiB discovery output
or 2 MiB resolution output, 512 physical SQL commands, 2,000,000 qualification
work units and one earlier-parent deadline of at most five seconds. SQL lock
waits are capped at 500 ms. `OpenNamespaceReaderWithLimits` permits lower positive
ceilings; the original constructor keeps these defaults. The limits are
conjunctive: a maximum root count does not promise every proof/result shape fits
the independent byte and work bounds. Exact bytes used for digests are capped;
this does not claim an exact peak heap or RSS bound.

One discovery, one initial resolution and one required before-exposure repeat
permit at most three scans under the caller's one earlier deadline: 1,536 SQL
commands, 15 seconds, 6,000,000 work units and 44 MiB of bounded canonical
input/candidate/output payload work. The caller owns that composition and the
separate canonical acquisition budget; this reader performs zero network RPCs.
Failure returns no partial discovery or pass, including a final query-budget or
transaction-completion failure.

The dedicated reader uses a single-roundtrip query mode and no implicit pool
Ping. Its physical command budget includes BEGIN and the final COMMIT or
ROLLBACK; a limit of one fails before opening a transaction. Connection target
selection through `target_session_attrs` supports default or `any` only: the
other modes issue additional connection-validation SQL and are rejected at
startup rather than silently ignored. TLS connection settings are preserved.

## Namespace range predicates

`PrepareRangeScope`, `DiscoverRangeRequirements`, `PrepareRangePass` and
`ResolveRangePass` classify a bounded set of contract addresses over a block
range. `NamespaceReader` exposes the same two read operations through its
existing restricted pool and read-only snapshot protocol. The selected original
head must precede the configured model era's end. Canonical monotonic block time
then permits sparse ordinal classification between the qualified factual cuts.
The point reader continues to require actual included transaction coordinates.

Range results contain half-open intervals in block and transaction-index order,
with explicit organization, public, unknown or conflicting classifications and
their original authority references. Automatic ordinary-call support starts
after birth. Exact record-zero creation coordinates are returned separately;
the eventual data source must match their transaction hash, block hash, index
and created address to an actual ROOT. A next-block exclusive end is an ordinal
boundary, not a fabricated block header. Missing retained transfer support fails
the whole pass, including when an earlier interval had positive support.

One operation allows at most 4,096 addresses and 16,384 intervals plus creation
coordinates, subject to the existing independent candidate, work and encoded
byte ceilings. Discovery and resolution each establish an earlier-parent
deadline of at most five seconds; the caller owns the original deadline across
its complete source operation and before-exposure repeat. No query state or
positive interval cache is persisted. Returned values are detached and range
scope, requirements and authority digests have separate purpose domains.

These predicates establish historical namespace classification. Actual indexer
rows, canonical inclusion, financial values, retained population coverage and
current case, wallet and permission checks remain responsibilities of the
concrete data source. Unknown, conflicting and public intervals supply no
organization-positive predicate or sanctions-clear result.
