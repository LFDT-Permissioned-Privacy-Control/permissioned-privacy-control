# Bounded sealed activity source

`internal/activitylog` records completion **metadata** to the existing exclusive
Pebble audit spool. `internal/operational/activitysql` seals it into the lean
audit database. `internal/operational/activitysource` supplies the protected-read
gate with activity pages and method/status summaries from that SQL population.
These are libraries and an explicit owner CLI. The concrete native RPC recording
wrapper is described in [v2-rpc-activity.md](v2-rpc-activity.md); these packages do
not mount listeners. The assembled operational server exposes the scoped admin
investigation endpoint described below.

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
status, optional numeric JSON-RPC error, normalized outcome/status and a bounded
reason code in new v2 records. The sealed
variant adds the actual buffer sequence. Both are at most 2,048 bytes. Raw RPC
parameters, payloads, URLs, JWTs and proofs are absent. Only the JSON-RPC error
field can be null. HTTP200 plus a JSON-RPC error is not success.

The writer emits v2 with exactly one closed `c` reason code; an unclassified
trusted completion records `not_recorded`. Unknown codes and incompatible
reason/outcome pairs are rejected before append. Examples include method not
allowed, wallet not linked, and the specific Go policy denial. Reasons come from
the actual decision branch, never free-text errors, raw claims, a new evaluation
or a later guess from HTTP status. Successful and unclassified operations need
no invented explanation. Existing v1 bytes omit `c` and remain unchanged; both
versions retain the same 2,048-byte cap and chain-hash algorithm.

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

## Local request concurrency

One operational service shares a local concurrency limiter across RPC aliases,
organization routes and Explorer. It permits at most 50 concurrent requests per
verified actor and 50 across all missing or invalid identities. JWT rotation or
changing the selected organization does not create another actor bucket. Only
active actors occupy memory; their entries are removed after the last release.

The transport performs an extra bounded token verification against the exact
immutable snapshot used by every configured engine, with the same explicitly
supplied assembly clock. This selects a limiter key only. Engines still verify
the original request independently and retain every permission and expiry check.
Raw headers, JWT text, claimed IDs and IP addresses never become bucket keys.

The limiter runs after the original IO deadlines and global service slot, before
body reading and recorder reservation. A local capacity rejection returns HTTP
429 with a finite error response and no request reference. Like the existing
global-cap rejection, it is not a durable access-log event: it does no recorder,
node or source work. Accepted requests keep their local credit through body
reading, durable append and actual output return, including failure and expiry.

These are per-process concurrency limits, not requests-per-second or daily
quotas. The existing global ceiling of 256 and original 20-second IO/operation
bound remain. Replicas and restarts do not share the counters; no Redis or fleet
rate-limiter choice is implied. Invalid-token verification and slow rejection
output remain globally bounded, rather than constituting a network DoS defense.

## SQL roles and initialization

Use a dedicated lean audit database with the existing exact audit001..004
migrations already applied by their normal migration tool. The owner tool
installs the005 storage objects and007 closed v1/v2 guard; fresh installations
also get the006 organization/order performance index. It rejects a missing or
unsupported baseline. The four old SQL migrations and sealer/Drain APIs remain
unchanged.

`ops-activity-admin migrate` needs `OPS_ACTIVITY_OWNER_DATABASE_URL`, explicit
`--writer-role`, `--reader-role`, `--retention-role`, and `--drained`. The roles
must already exist: disjoint LOGIN NOINHERIT, no membership/ownership or elevated
role attributes. The command neither creates roles nor infers a global role set.
Credentials are environment values, never command arguments or status output.
The format transition accepts exact005 or006 prototype catalogs and changes
only their guard to007. A retry validates007. It verifies effective privileges,
keeps existing index presence unchanged, and does not repair changed grants or
rewrite history. The explicit drain belongs to this prototype format transition;
it is not a requirement for every future compatible update.

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
Runtime Open and operations compare the qualified PG16 catalog and exact
effective ACL, including ordinary/permanent/non-RLS relations, views and007
guards. Only the exact nonunique `public.activity_org_page` performance index is
optional. Its known absent/building/valid states are accepted; a different
definition, unique index, extra index or changed mandatory object is rejected.
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

## Organization Access Logs

`GET /api/v2/orgs/{orgId}/access-logs` requires a fresh verified access token and
the selected organization's admin or read-only admin role from current policy.
It reads only that exact sealed `DataOrg`; an actor filter never assigns anonymous
or organization-free records to a tenant. It needs the selected activity reader
and the shared healthy recorder, not a disclosure case, user directory, wallet
lookup or live node/indexer query.
The admin entitlement includes the recorded trusted peer IP, matching the admin
log view. External disclosure IP redaction and level rules are unchanged.

The required `from`/`to` interval is half-open. RFC3339 bounds normalize upward to
UTC microseconds, preserving which stored instants match. Optional `actorId`,
`method`, `outcome` and `requestReference` filters run before the page limit
(default50, maximum100); unsupported or duplicate parameters are rejected. Pages
are newest first with a strict observation/producer/run/ordinal/record key.
Their encrypted cursors bind the caller, organization, current bundle/profile,
all normalized filters, limit and original committed sealed cut, with a fixed
five-minute lifetime. A separate cryptographic subkey/domain derives from the
existing protected admin cursor ring; there is no new credential.

Each investigation reserves shared recorder capacity before reading protected
data. The pinned SQL transaction closes before one synchronous durable completion
with the verified actor, authorized organization, current bundle digest and
trusted direct-peer IP. The exact label is `explorer.admin_access_logs`; it is
not a public Explorer route or business-operation binding. No query/filter,
target-identity or cursor contents are added to the unchanged v1 envelope.
Recorder failure releases no protected response. A separate bound of at most
four investigation responses lasts through delivery; it is not another audit
budget. Current source, access and original expiry are checked after append
and immediately before protected output. Rejected overload can remain unaudited.

Final delivery can still fail or change after durable completion is recorded.
The HTTP field is the selected response status, not proof of final delivery.

The response distinguishes recorded HTTP status, nullable RPC error, normalized
outcome and recorded derived status. The request reference is the recorder's
existing UUID. RPC, Explorer and investigation responses return their completion as
`X-OPS-Request-Reference` after successful durable completion; it does not mean
the row has already sealed, and never adopts a client correlation header. The
page reports its sealed head, capture time and retained floor without a fleet
total. Below-floor requests or continuations return `410 history_pruned`, not
an empty or silently shortened history. Current access and activity source are
checked again after closing the original read transaction and before output.
Sealedv1 has no recorded reason and projects `not_recorded`. New sealedv2
projects its validated closed reason code with a fixed friendly UI label. No
present policy evaluation or coarse outcome is substituted for historical cause.
This adds no raw error text, claims or request parameters to the page.
The compiled recognized-request population includes the investigation label;
RPC-only lists and summaries exclude it. Adding this reserved label changes the
population digests, so older population-bound cursors must restart. Legacy v1
codec and spool recovery remain valid. Older recognized-request readers omit
the new reserved label; this is not identical old/new population visibility.

Fresh first-V2 deployments start with007 and the fixed v2 writer. Moving an
existing unreleased005/006 prototype to this format requires stopping its old
readers/writers, running `ops-activity-admin migrate` with the owner environment,
explicit existing roles and `--drained`, then starting a compatible dual-reader
image. No history, source identity, generation, run, key or spool is reset.
005/006/007 name qualified catalog profiles, not a mutable version row.

**Rollback floor:** after the first durable v2 append to a local spool, rollback
must use a dual v1/v2 reader image with007. Waiting for SQL sealing does not delay
that requirement. V1-only native prototypes cannot read that spool/history.
`downgrade-to-005` remains restricted to exact006 and rejects007; dropping an
index cannot undo a metadata-format change. The stream format digest changes to
`ops.activity.sealed-metadata/v1-v2`, so older format-bound continuations restart;
original payload and chain-hash bytes remain intact. A real mixed fleet requiring
old binaries would need an explicit compatibility-first rollout; the first V2
release does not add a write-version knob or a bridge release by default.

Within the007 compatibility profile, the database owner can maintain the known
performance index while OPS readers/writers stay active:

```sql
CREATE INDEX CONCURRENTLY activity_org_page ON public.access_logs
 (chain_name,org_id,activity_observed_us DESC,activity_producer_id DESC,
  activity_run_id DESC,activity_ordinal DESC,activity_record_id DESC)
 WHERE activity_kind=1;
-- Or, to remove/rebuild that optional index:
DROP INDEX CONCURRENTLY public.activity_org_page;
```

Run each as a separate owner statement outside a transaction. A cancelled build
may leave that exact index invalid; owner removal/rebuild is still needed for
performance, but it does not make the security schema unqualified. No runtime
process receives DDL privileges or creates indexes. Queries retain their existing
bounded page and time limits when the index is absent/building; latency may rise.
Large-range/export capacity is not promised.
