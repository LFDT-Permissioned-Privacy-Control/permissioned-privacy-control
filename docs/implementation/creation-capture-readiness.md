# Creation capture readiness

`catalog-runtime-creation-observed/v1` selects runtime source
`ops.runtime-policy/v1alpha7`, the existing native-v4 evaluator and original
capture-time coverage. It requires `captureReadinessProfile: "same-node-caught-up/v1"`
and `operational.creation-capture-coverage/v1`. Earlier profiles keep their
existing behavior and reject this source. Native source versions, Guard wire,
fingerprint and approval lifetime are unchanged.

This integration records approved creation intents, their original capture
coverage, and independently observed ordinary surviving creations. It does not
serve ownership, deployer, pending or historical data permissions. Header
readiness alone supplies none of those permissions.

## What the capture means

The operator explicitly selects a caught-up canonical reference and the exact
credential-specific ingress sources. A source descriptor contains the network
tuple, URL, organization, credential **reference and header name**, evidence
profile and finite Prague interval. It contains no credential value. The
domain-separated source-set digest includes an empty set: that configuration
supports read/simulation startup and rejects every raw-send path before
financial, Guard or broadcast effects.

A live gate checks its selected acquisition client (or original retained Guard
Prepared pair), the signed hash, native approval, execution, View, network and
source binding. One two-second deadline covers the checkpoint, at most eight
physical RPC attempts and confirmation. Requests use header-only
`eth_getHeaderByNumber`; there is no full-block fallback, redirect or POST retry.
Response envelopes total less than 3 MiB. A pending transaction already in the
node pool remains eligible. A bound nonnull receipt suppresses new coverage.

This depends on an **operator-managed caught-up-node assumption**. `eth_syncing=false`,
a null receipt, a recent heartbeat and canonical `A < C` order cannot detect an
unseen global head when both selected nodes lag. Later catch-up cannot repair
that historical uncertainty. SQL first-writer and node trust are explicit.

The first covered v2 seed stores its bounded typed coverage atomically with the
financial decision, plan, reference and work generation. Timing-only retries
return the original observation without spending another slot or rewriting
its digest. PostgreSQL timestamp precision is reflected in canonical encoding.
Legacy v1 references remain permanently uncovered. Missing v2 coverage is
corruption; it is never repaired by a later probe or current wallet proof.

## Worker and fences

`ops-creation-observer run` maintains the canonical prefix and processes at most
one included transaction per Step for one explicitly selected network. There is
one active operation per worker. The network lease lasts 30 seconds; no session
lock or per-job lease is used. The header phase shares one 15-second parent
deadline across at most four reads,
131 requested selectors and twelve network/sync calls: at most 143 physical
attempts and less than 3 MiB of bounded response envelopes.

Steady caught-up operation without due work refreshes one heartbeat UPDATE per
second. A local
monotonic ten-second interval only schedules lease renewal; each Step reads the
actual bounded database lease TTL and renews early if needed for node work and
SQL publication. Database expiry/CAS remains authoritative. Known node errors,
syncing or lag clear capture liveness promptly without erasing the maximum
observed tip height. A partial head137/known-tip140 cannot become ready from a
later lagged tip138. An unpublished future-tip hash is diagnostic; an actual
fork of the stored prefix still requires the exclusive reorg transition.

The worker recomputes complete header hashes before storing them and maintains
one contiguous floor-to-head prefix. Forward publication appends at most 127
headers plus a current-tip recheck. A reorg searches at most 128 heights relative
to the **old** head. It publishes only the verified rollback to the common
ancestor, with capture readiness false; the next Step catches up. A reachable
matching lower head is ordinary node lag, not evidence of a reorg. A proven fork
beyond the search range or below the retained floor quarantines the observer.

All node I/O finishes before SQL locks. Normal prefix movement, lease renewal
and transient liveness updates hold the network transaction advisory **shared**
capture fence. Takeover, reorg, durable quarantine and recovery hold the same
**exclusive** fence before state rows. Startup activation is a closed exclusive
transition from `awaiting-canonical`, after current canonical/source/sync checks,
and rotates the capture epoch. No online operation clears a sticky quarantine.

Covered financial transactions take shared capture fence, then the existing
hash lock, before financial/intent effects. Entry and final checks compare only
durable network/observer readiness, quarantine and exact recovery/trust epochs.
They deliberately exclude moving head, heartbeat TTL, transient `capture_ready`
and lease expiry. Thus an already valid capture can commit after inclusion or
ordinary head progress. An exclusive invalidation either precedes that check
and rejects it, or waits for the actual COMMIT/rollback. App roles retain only
SELECT on observer state; they gain no UPDATE or row-lock permission.

## Included creation evidence

After releasing its bounded SQL work snapshot, the worker renews the lease and
acquires the actual included transaction on the same selected reference. The
separate `reth-prague-included-creations/v1` profile reconstructs protected
type 0/1/2 signed bytes, hash and signer; checks receipt/status/block/index and
hash-list membership; and parses `debug_traceTransaction` using the fixed
callTracer/full-prestate mux. Canonical-height checks bracket acquisition.
Parent/post-block account state is never substituted for transaction-index
prestate. Full block hash lists have their own 8 MiB response bound; they are
not substitutes for the header-only capture and prefix methods.

Only successful ordinary nonempty Prague CREATE/CREATE2 outputs qualify.
Complete ancestor failure and every committed SELFDESTRUCT source-storage
record are checked, including delegated and zero-balance SELF. A beneficiary
is not assumed deleted. Any committed SELF on a candidate excludes it; SELF
under a reverted ancestor does not. Inclusion-hash code must exactly match the
constructor output. Empty, EF/designator/precompile, reverted, ambiguous and
unsupported cases provide no birth authority. Acquisition has one 15-second
deadline and at most 2,060 physical RPC attempts, with no hidden POST retry.

At most 16 original references/plans and 1 MiB of payload enter one immutable
work snapshot. An indexed exact tuple match checks address, raw creator, kind,
initcode hash, value, effective caller and depth, then the complete creation
ancestry. Preflight record ordinals are diagnostic only. A rolling framed path
digest preserves ancestry in linear work; composed matching/hash input is
bounded at two million work units. Factory scope and code pins authenticate the
captured approved intent. They do not claim every included ordinary CALL path
or actual factory entry-code was replayed against policy.

Publication requires original covered-v2 references and canonical
`floor <= A < C <= prefixHead` in one SQL snapshot. It takes shared capture
fence, the same transaction-hash lock, then observer/work/fact locks and finally
capacity. Exact lease, recovery epochs, prefix version/head and immutable
inputs are checked through COMMIT. Revoked original epochs are filtered again
inside this transaction. A newly appended generation stays due; duplicate
immutable rows add no facts or counters. Each birth has no winning actor/org.
Wallet and factory associations append independently. Re-inclusion uses the
new inclusion hash, preserving the orphan row and counting it toward capacity;
only canonical joins can make an association eligible.

Up to 2,048 births/associations publish atomically in batches of at most 128 rows,
under the five-second SQL bound. Capacity/error/cancellation rolls back the
whole fact batch. Scheduling retries are bounded to 1–60 seconds and never send,
enqueue, reapprove or resubmit a transaction. An unchanged canonical inclusion
can acknowledge a new reorg epoch without retracing. A long included operation
may let capture heartbeat expire; dependent new captures then fail closed.

## Offline commands

The command accepts an explicit DSN environment-variable name. `run` requires
the narrow observer role; offline commands require the owner. Reference
credentials use a separately named environment variable and are never printed.
Use `--help` for command flags. Shared network flags are `--environment`,
`--chain-id`, `--genesis-hash`, `--deployment-id`, `--generation` and
`--coverage-digest`. Source startup flags are `--reference-url`, finite
`--prague-start/--prague-end`, `--sources-file` and explicit
`--caught-up-assertion operator-managed-canonical-head/v1`. The bounded closed
source array must be the exact nonsecret descriptors selected by runtime
assembly; it is operational binding metadata, not editable permission policy.

`migrate` requires all five existing roles and `--acknowledge-drained`. It
applies additive schema3 after the byte-identical schema1/2 migrations. Stop all
older pools/processes before migration: their schema check happens at startup
and cannot fence an already live old pool.

`bootstrap` additionally requires a decimal `--floor-height` and exact
`--floor-hash`. It reads and verifies that canonical header on the selected
reference before entering SQL, then accepts only a fresh observer. Prior
observer use, noninitial work metadata, or any v2 plan/reference (even with
missing coverage) rejects fresh bootstrap. Plain A1v1 journal history is allowed
and remains uncovered. Existing schema3 histories use drained recovery instead.

`status` is an owner-only operational read. It does not mint readiness.

`revoke-capture-epochs` requires drained unready recovery, exact current
`--observer-epoch`, a closed `--reason` and a regular `--epochs-file` containing
`{"captureEpochs":["canonical-uuid"]}`. The file is at most 32 KiB and selects
1–256 unique epochs. Every epoch must have an actual original coverage witness.
Rows are permanent, append-only and idempotent; no un-revoke API exists. Online
roles cannot insert, update or delete them. Existing covered seeds from those
epochs remain stored but cannot regain authority through a new heartbeat.

After the existing `begin-recovery` operation, `finalize-observer` requires the
exact observer epoch, `--acknowledge-drained`, `--acknowledge-complete` and
`--acknowledge-capture-trust-resolved`. These attest complete retained operational
and deny history plus affected-epoch selection; present-row checks cannot prove
missing backup facts or original caught-up trust. If that accounting is unknown,
leave the observer quarantined. Ordinary finalization cannot clear a sticky
observer quarantine. Successful explicit finalization preserves original rows
and revocations, rotates epochs, and leaves observer/capture readiness false in
`awaiting-canonical` until independently rechecked by the worker.

Offline finalization keeps the legacy API's 60-second default. CLI scans default
to 10 minutes and have a hard 30-minute ceiling; failure leaves readiness false.
Plans, coverage and observed associations are scanned in bounded pages without
loading the history or issuing nested pgx queries on open rows. Recovery
recomputes retained tuple/qualification digests and exact original
ref/plan/entry/root/actor links. A proof digest does not reconstruct the actual
historical CALL ancestry or prove missing facts: original included acquisition,
trusted worker first insertion and the explicit completeness attestation remain
the boundary. No full-capacity completion time is promised. There is no TTL or
automatic pruning for coverage, denies, prefix, births or associations.

## Storage limits

Schema3 adds narrow observer and future facts-reader roles in the same
operational database. The worker has no travel-rule PII or policy access and
cannot insert plans, references, Origins or coverage. The facts reader cannot
read plans or travel records. Effective column/table ACL checks include inherited
and PUBLIC privileges.

Per-network hard ceilings are 10 million current headers, 2 million immutable
births, 8 million associations, 1.6 million coverage rows / 3,276,800,000 logical
coverage bytes and 1.6 million permanent revoked epochs. These are additional
to A1's plan/ref/work caps, and exclude PostgreSQL/index/WAL/backup overhead.
Lower limits are allowed. Capacity exhaustion returns unavailable; it does not
discard history or resend transactions.
