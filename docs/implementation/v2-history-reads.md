# Ordinary history reads

The history consumer serves the ten transaction, receipt, block, count,
by-index and log JSON-RPC methods through the current approved Go policy
snapshot. It uses current verified claims, the selected organization's method
and credential, current wallet links and immutable transaction `visibleTo`
rows only when that method consumes their listing or log-unlock authority.
Participant-only block and count envelopes perform no share read or recheck.
It does not use historical deployment ownership as an ordinary read
grant. Historical disclosure namespaces are a separate authority.

## Select the actual consumer

Prepare and validate the approved bundle with `--consumer history`, or use
`policyprofiles.HistoryOptions` in trusted startup assembly. Load it with those
same trusted options. The profile/evaluator identity stays unchanged, while
the approved requirements explicitly include `runtime.history-read/v1` and,
when enabled, `privacy.visible-to-history`.

Default preparation/loading rejects these requirements. The audited RPC
constructor also rejects a history-enabled snapshot unless it receives the
concrete history engine with the same snapshot, network and recorder. A
capability in an approved document cannot substitute for that actual consumer.

`HistoryConfig` binds the complete organization/credential client map derived
from the approved method catalog. Missing, extra or foreign entries fail at
construction. Each client uses the same selected query limits. An absent
organization selector is accepted only for a token mapped to one organization.
An absent bearer can use only an explicitly approved anonymous builtin and
the independently selected default client; an invalid bearer never becomes
anonymous. Anonymous history has no wallet, grant or share authority.

## Admission and rendering

The shared `readprivacy` decisions preserve the RPC surfaces:

- Transaction objects require participation, or under standard mode the
  destination's current owning-organization admin or an actual `visibleTo`
  listing. An admitted RPC transaction retains its verified signed fields.
- A standard receipt can additionally be admitted by an entitled log, except
  for deployment receipts. Strict receipts require participation. Receipt logs
  are independently filtered and masked, and the returned bloom is zeroed.
- Blocks, counts and block receipt arrays include participant transactions
  only in both profiles. Counts reflect that filtered population. By-index
  lookups use the actual original index, never the filtered array position.
- Blocks always zero their bloom, gas used, blob gas used and reported size
  fields. Their original header identity is retained.

The richer Explorer row masking rules are separate from these RPC transaction
envelopes. RPC log masking changes topics and data; it does not reinterpret an
admitted RPC transaction or receipt's top-level addresses as Explorer fields.

Before any new log payload or log-derived entitlement, one supported,
nonanonymous event layout must uniquely match the current approved ABI and the
actual topics/data. Unknown, malformed, ambiguous or undeclared layouts are
omitted even for admin, wildcard and `visibleTo` unlock. Every downstream
dynamic-payload, parameter, strict indexed-self and address-mask helper receives
that single matched event ABI. Matching describes the declared layout, not a
proof of which Solidity statement ran or a universal classifier of arbitrary
bytes as addresses. V1 rendering is unchanged.

The standard unlock requires both the emitter's actual current eligible grant
and that transaction's genuine listing. Generic address visibility and another
transaction's listing confer no event grant. Strict mode performs no share
read or recheck and permits construction without an unused share source.

## Source observations and limits

Canonical complete blocks reuse `HistoryBlockClient`. Direct transactions and
logs use bounded typed batches; log acquisition deduplicates actual parent
transactions, receipts and headers instead of fetching a whole block per log.
Plain transaction lookups do not fetch an unused receipt. Requested receipts
and log parents still require their actual receipt evidence. Signed envelopes,
senders, hashes, fee fields, transaction locations and
receipt/log associations are checked before rendering. Receipt status versus
pre-status state root presence is preserved. Sparse receipts preserve actual
block-global log ordinals while independently bounding their local log count;
complete-block acquisition keeps its aggregate ordinal and count checks.

Numeric and resolved latest/safe/finalized observations are rechecked by their
selected numeric header. A genuinely found by-hash orphan has a distinct
`Located` observation and a by-hash recheck. It does not become a canonical
block token or C2 ROOT proof. Pending data has a separate presence-aware model:
actual null hash/nonce/miner and actual transaction location fields are retained.
Its typed parsing container's computed header hash is not published as a
canonical pending hash. Pending receipts require a coherent actual body/receipt
set; a missing auxiliary body still probes the requested receipt method, and
backend errors remain unavailable. There is no synthetic pending log
population.

Only an actual null lookup becomes not found. Missing required parents,
contradictory locations, malformed rows, partial batch errors and exceeded
limits fail the whole operation. They do not become a successful empty result.
The configured node remains a trusted data source; these checks are not
consensus or Merkle inclusion verification.

Default whole-operation limits are 20 seconds, 64 physical HTTP attempts,
512 batch RPC items, 32 MiB of response wire, 16 MiB of charged retained/work
payload, 512 sparse parents, 256 headers, 20,000 logs and a 4,096-block log
range. A batch has at most 64 items. Complete blocks also retain CB1's tighter
per-block limits. The 8 MiB result ceiling also bounds selected complete-block
and receipt-set reads. Each batch response is bounded before parsing by its
selected item caps plus finite envelope allowance. Complete-block decoding
receives a lower retained-data allowance before allocation, reserving the
remaining allowance for the composed location/log wrappers. These are
conjunctive bounds, not promises that each maximum
can be reached simultaneously. A caller can select lower limits.

Acquisition, canonical composition, metadata/layout preparation, rendering and
final probes spend the same counters. The matcher reserves its selected
ceiling before ABI/grant copies and parsing. Counters are not reset for a
recheck, and no temporary acquisition context replaces the original deadline
or cancellation fence. Logical payload charging is not an exact heap/RSS
measurement. Ordinary oversized queries require a narrower request.

## Durable completion and final delivery

The existing audited RPC service owns one recorder and one concurrency limit
across native, state, metadata and history operations. It reserves once,
completes once and waits for the actual synchronous local append. There is no
history-specific queue or per-transaction capture write.

After append, it rechecks the selected source, the original share positives
and current wallet set, the same concrete node/network after mutable SQL, and
then the same original token/view and caller fence after the last I/O. Failed
or uncertain append and failed final checks withhold protected bytes. Neither
JWT lifetime nor authority is renewed during this process.

The durable completion describes the captured operation outcome. A later
delivery gate may withhold its response without rewriting that recorded
outcome; a success completion is not proof that a client received data.
