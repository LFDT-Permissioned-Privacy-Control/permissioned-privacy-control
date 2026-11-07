# Bounded sealed activity source

`internal/activitylog` records completion **metadata** to the existing exclusive
Pebble audit spool. `internal/operational/activitysql` seals it into the lean
audit database. `internal/operational/activitysource` supplies the protected-read
gate with activity pages and method/status summaries from that SQL population.
These are libraries and an explicit owner CLI. The concrete native RPC recording
wrapper is described in [v2-rpc-activity.md](v2-rpc-activity.md); these packages do
not mount a production activity-data endpoint.

The population is `SEALED_RPC_COMPLETIONS_AS_OF_CHAIN_HEAD`: all matching retained
SQL completion rows at one committed chain head. It excludes requests that were
never recorded, failed before recording, remain buffered, or were lost outside
the retained SQL set. A zero-row result describes that SQL prefix. It does not
claim that no requests executed. Local recording failure makes that recorder
unready; it does not rewrite already sealed SQL history.

## Metadata and hot path

A caller must supply actor, selected data organization and policy digest from
the **same** accepted request. The native RPC wrapper captures them from its
original engine View; the recorder itself does not authenticate this input.
There is no user lookup, current-wallet inference or after-the-fact organization
assignment. Unattributed records are allowed but cannot satisfy an attributed
protected query. Recorded time is the original trusted completion observation,
UTC truncated to microseconds, rather than sealing time or proof of delivery.

The closed canonical JSON spool contains version/kind, network, original source
generation/configuration, producer/run/record UUIDs, run ordinal, observation
time, actor/org/policy, approved method label, trusted IP, actual selected HTTP
status, optional numeric JSON-RPC error, and normalized outcome/status. The sealed
variant adds the actual buffer sequence. Both are at most 2,048 bytes. Raw RPC
parameters, payloads, URLs, JWTs and proofs are absent. Only the JSON-RPC error
field can be null. HTTP200 plus a JSON-RPC error is not success.

Reserve is immediate and performs no SQL or per-request filesystem-stat call.
Defaults and ceilings are 256 outstanding slots, 65,536 recovered/pending/held
entries, 128 MiB logical spool bytes, and 512 records/1 MiB per seal transaction.
Each reservation charges one entry and 2,048 bytes before the effect; valid
completion reduces that byte reservation to its actual canonical size. The
caller completes every reserved slot, including denied/error outcomes. A receipt
means the local synced append returned, not that SQL sealing completed.

`Slot.Complete` calls the same synchronous `Buffer.Append`. It has no context,
replacement goroutine, queue or SQL fallback. The slot stays occupied until the
real append returns. A fixed health loop samples local free space and detects
appends older than one second. Required free space is at least the greater of
256 MiB and twice the configured logical spool-byte cap. A stale sample, local
write failure or unhealthy sealer denies new reservations. Recovery does not
force the UTC clock forward.

Close stops admission and waits for actual existing slot completion before
stopping the sealer and closing Pebble. One lifecycle worker owns that shutdown.
A context timeout reports unavailable while the worker retains ownership; it
does not close the buffer under an append or claim SQL drain. Retry Close to
observe the same worker's eventual result.

## SQL roles and initialization

Use a dedicated lean audit database with the existing exact audit001..004
migrations already applied by their normal migration tool. B1's owner tool owns
only additive005. It rejects a missing or unsupported baseline. All four old SQL
files and the old sealer/Drain APIs remain unchanged.

`ops-activity-admin migrate` needs `OPS_ACTIVITY_OWNER_DATABASE_URL`, explicit
`--writer-role`, `--reader-role`, `--retention-role`, and `--drained`. The roles
must already exist: disjoint LOGIN NOINHERIT, no membership/ownership or elevated
role attributes. The command neither creates roles nor infers a global role set.
Credentials are environment values, never command arguments or status output.
Migration retry checks exact installed shape and effective privileges; it does
not silently repair changed grants.

`initialize` additionally requires exact environment, chain ID, genesis hash,
deployment ID, source UUID, configuration digest and capacities. Initialization
is insert-only or exact-idempotent; it cannot reactivate an existing recovery or
overwrite configuration. The derived key is an identity binding, not independent
verification that a connected node has that genesis.

The writer can append bounded metadata and update its selected source head and
counters. The reader gets an owner-backed security-barrier qualified projection,
registry/source metadata and anchors, without raw legacy `request_params` access.
Retention gets only the prunable projection and bounded floor/count/anchor
updates. It cannot update payloads, toggle readiness/generation, or delete runs.
Runtime Open and operations compare the exact PG16 catalog and effective ACL,
including ordinary/permanent/non-RLS relations, view definitions and guards.
Inspection uses role-independent pg_catalog expressions; it requires no extra
catalog/view grant. The database owner and trusted source assembly remain TCB.

One chain is shared per strong network. All writers acquire the same existing
class730076/FNV advisory key **before** reading the source head or allocating SQL
IDs. Later seals therefore cannot insert below an older committed head. The
writer consumes one startup-only ID probe under that lock, before registering a
run or drawing its range. A restored allocator behind any visible committed
head is refused immediately, with no catch-up loop. This creates an ordinary ID
gap, adds no per-request SQL, and leaves the exact role grants unchanged.
Initialize/full recovery additionally check the owner-visible retained and
anchored global maximum without consuming an ID; manual drained repair is
required. Neither path silently calls setval. The
existing format2 hash uses the original canonical metadata bytes and exact UTC
timestamp. Batched inserts and source head/count/byte changes commit together.
Exact replay adds no rows/counters; a different body, run, range or fixed field
under the same sequence fails closed. An uncertain COMMIT is settled by reading
the exact original record, never by creating another UUID.

Writer settlement checks exact canonical body/fixed/index/run/range identity and
the current atomic head continuity. A hex-shaped stored hash alone is not a
cryptographic chain proof. The writer has no anchor grant and does not re-prove
every predecessor during settlement; the drained owner recovery/verifier walks
the retained format2 chain from its actual anchor. Owner/writer integrity remains
part of the named operational trust boundary.

Startup registers an immutable run before appending. A global range has width
2^40 and index1..8,388,607, with at most64 total allocation draws. Already
registered collisions may consume draws; a fresh unregistered range at or below
local allocation history is refused. All original recovered run/configuration/
generation metadata is retained, even after a current configuration change.
Current generation/readiness gates the new transaction without relabelling old
observations. Existing registrations count forever, including unsealed runs and
old generations. Row retention frees no run quota. B1 has no online run cleanup.

## Reads, cursors and audit

Pages and summaries use read-only REPEATABLE READ: maximum five seconds per
operation, two seconds per statement, pool4, work_mem4 MiB, parallel workers0.
The same snapshot checks source readiness, generation, floor and exact head
reference. Pages use original time/producer/run/ordinal/record UUID ordering,
at most100 returned rows plus one lookahead. After-position comes only from the
service's authenticated cursor; adapters have no render/cursor keys. An inclusive
end second includes exactly that microsecond boundary, not the following second.

Summary uses SQL GROUP BY over **all** matching retained rows below the same
head. It has no first10,000 sample or arbitrary month/block-span ceiling. More
than512 method groups, timeout or checked-count failure returns an error with
no partial COMPLETE result. Physical SQL work remains bounded by the deadlines.

Source references name actual committed hashes. A fresh head0 has an explicit
domain-separated empty-prefix reference, whose coverage uses zero-length head
hash bytes. A fully pruned nonzero head uses its real anchor/hash. Stable cursor
identity binds network/source/generation/configuration/head; observation time,
retention floor and later head growth are excluded. Eligibility/freshness is
checked separately. The SQL read transaction closes before the case's exposure
transaction. A new currentness check samples readiness/floor/reference before
the existing case gate commits a receipt binding the exact output bytes.

This sampled gate is not a fleet-wide fence through network delivery. Permission
and case/recipient/expiry checks remain the existing protected-read service's
responsibility. No caller-supplied SQL source or authority flag is accepted.

## Retention and recovery

`prune` uses `OPS_ACTIVITY_RETENTION_DATABASE_URL`, exact network/source/current
generation and an explicit `--retain-from-us`. One transaction removes at most
5,000 eligible **chain-prefix** rows, stopping at the first observation at/after
the floor. UTC rollback may leave older observations after that blocking row.
The effective floor is max(current, requested), including a no-op or stale job.
Floor, deletion intent, exact prefix deletion, anchor and counters commit together
under the shared chain lock. Generic/owner deletion without intent and that lock
is rejected; reserved payload updates always fail. No run is deleted.

An exact retained SQL match is known sealed. An absent original spool entry
observed before the current floor is **not** called sealed: preserve/quarantine
the spool and require offline recovery. An absent entry at/after the floor may
replay only from its original registered range above that range's retained
high-water. Missing below high-water, a foreign entry or malformed provenance
also preserves the spool and faults. Fresh completions whose honest UTC time is
already before the floor suffer the same availability cost.

In particular, seal COMMIT → crash before local deletion → online SQL pruning
can leave an unverifiable old spool at restart. B1 deliberately has no automatic
expired-discard classification or additional per-record receipt table. A drained
operator may preserve/archive that original spool and start a fresh directory/
run, acknowledging that it is outside retained SQL history. Never fabricate an
SQL match or discard the only preserved evidence automatically.

For SQL restore/configuration change: stop workers and preserve spools, read
`status`, then `begin-recovery --generation=<CURRENT> --drained`. This CAS rotates
to a new UUID and leaves ready=false. Read status again. Optional `reconfigure`
uses the **new unready** generation and may change only configuration/caps, with
persisted usage fitting them; network/source/role triple remain immutable. It
does not lower the floor, rotate again or activate the source.

`finalize-recovery` takes the new generation, `--drained` and
`--acknowledge-retained-set`, then streams exact retained chain/run/range/counter/
anchor and allocator validation before readiness. Default timeout10 minutes,
maximum30. It does not repair mismatched counters, advance allocators or prove
the completeness of missing producer spools. Old open stores never rebind.
Ordinary Open/currentness checks use indexed head/anchor and cheap structural
invariants; they do not scan up to a billion rows. Full counter equality belongs
to the explicitly drained recovery path.

Default SQL capacities are 100M retained rows, 64 GiB canonical metadata and
65,536 registrations; ceilings are 1B rows, 1 TiB and 1M registrations. At the
normal 625-byte fixture size, the row cap is reached before the byte cap. If each
unique recorded completion seals once and nothing is pruned, the row capacity
lasts approximately:

| Sealed completion rows per second | Default 100M rows | Maximum 1B rows |
| --- | --- | --- |
| 100 | 11.6 days | 115.7 days |
| 2,000 | 13.9 hours | 5.8 days |
| 5,000 | 5.6 hours | 2.3 days |

These are RPC completion rows, not unique transactions or blockchain TPS. Larger
metadata bodies can reach the byte cap sooner. The limits count logical payload;
table/index overhead, WAL, replication, backups and Pebble amplification require
additional physical capacity. Retention settings and the pruning cadence must
reclaim space fast enough for the actual sealed rate, accounting for a newer
observation that can block prefix pruning. The examples are capacity arithmetic,
not an archival-retention, throughput or latency promise. Monitor row, byte and
run capacity separately; row pruning does not free immutable run registrations.

History/events, finance and live Core collection are separate required
source/assembly work; this activity library supplies none of their provenance.
