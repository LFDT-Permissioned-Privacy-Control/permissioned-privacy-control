# Event disclosure

An auditor opens a disclosure case, selects **Events**, and reads the
logs allowed by its Git-approved standing rule. The same case screen is available
in Admin and Explorer. Customer approval is not required. Ordinary Explorer access
and case access remain separate permissions. Disclosure never adds events to
ordinary `eth_getLogs`, receipts or Explorer lists.

## Which events are included

The list contains logs from the transactions already covered by the case:

- The actual signed parent transaction's sender or destination must match a
  currently proved wallet of a selected case target, within the address and
  inclusive time restrictions.
- The parent must be canonically included and positively attributed to the
  case's data organisation at its actual transaction coordinate.
- Each emitting contract must independently belong to that organisation at that
  coordinate. Foreign, public, unknown or conflicting ownership grants no access.
  A contract created by the positively qualified parent may emit at its exact
  creation coordinate.

The creation exception covers the top-level deployment's proved creation
record. A contract newly created inside a nested call has no positive ownership
interval at that parent's ordinal and its same-transaction logs remain withheld.
This does not exclude logs from already attributed nested contracts.

For example, a bank payment transaction can emit logs from both the payment
contract and a nested bank contract; both qualify. Logs from a foreign contract
called by that transaction are withheld. Missing, inconsistent, unready or pruned
source evidence fails the read rather than silently reporting an empty history.

This is **events from disclosed transactions**, not all activity involving a
customer. A relayer's transaction does not qualify merely because a customer's
address appears in a topic or encoded payload. There is no heuristic participant
detection, live `recordParty` lookup or Partior participant registry.

## Payload and privacy

Both the standing rule and case must explicitly authorise `events`. Selecting
Full transactions does not add Events authority.

Full Events returns the complete raw topics and data for each qualifying log,
with actual emitter, transaction hash and block hash. The payload may include
other parties in the same batch. Administrators must account for this when
authoring the standing rule. This is complete-record disclosure, like Full
transaction disclosure with its raw calldata and counterparties. It is not the
embedded-address masking used by ordinary event reads, or a promise to reveal
only fields concerning the case target.

Explorer uses the same log-card presentation, local event-format decoder and
topic controls as ordinary logs, with an explicit **Disclosed** badge and case
privacy level. A known canonical format can be decoded locally; this describes
the format, not an attestation about the emitting contract. Unknown or malformed
formats retain their exact raw evidence. Case cards do not fetch an ABI through
ordinary contract endpoints or turn disclosed addresses into ordinary-access
links. Custom approved-ABI enrichment needs its own case-authorized source;
the current case API does not supply one. Admin presents the evidence using its
existing card and badge components. Neither display performs authorization or
field-level redaction.

Pseudonymous and Redacted levels omit all topics, data and hashes. They retain
block number, transaction index, block-global log index, block time and a
case-bound opaque event ID. The emitter is a keyed label or `[PRIVATE]`.
No emitter wallet locator or ownership shortcut is supplied. Public chain
coordinates may still allow correlation; these levels do not promise anonymity.

## API and continuation

Use the existing protected-read operation:

```http
POST /api/v1/disclosure/cases/{id}/read
Authorization: Bearer <OPS access token>
Content-Type: application/json

{"v":1,"resource":"events","view":"list","limit":25}
```

Its result is `{v:1, population:"EVENTS_FROM_DISCLOSED_TRANSACTIONS", items,
nextCursor}`. Each item has `eventId`, `blockNumber`, `transactionIndex`,
`logIndex`, `blockTime`, `emitter` and `payload` (`disclosed` or `withheld`).
Full items additionally have `transactionHash`, `blockHash`, `topics` and `data`.
Actual empty topics/data are `[]` and `"0x"`; withheld fields are absent.

Coverage is `RETAINED_AT_READ` with population
`RETAINED_SAME_ORG_EVENTS_FROM_DISCLOSED_TRANSACTIONS`. The original canonical
upper block, network, dataset epoch, run floor, wallet snapshot, complete
namespace revision, case/rule/query and rendering generation bind continuation.
Changes invalidate the cursor rather than mixing historical authority.

Limits are 100 returned events, 100 candidate parents, 1,024 scanned logs and
128 distinct scanned emitters per operation, within the existing five-second,
128-block, 32 MiB wire, 16 MiB charged retained-work and 2 MiB response bounds.
Payload copying and encoding expansion are charged before reading raw fields.
A capacity boundary returns a continuation before the next unconsumed entry;
an individually oversized event fails. The charged-work bound is not a process
heap/RSS guarantee.

A cursor may resume inside a receipt. Hidden logs and empty receipts may produce
an empty page with **Continue**. Finishing a resumed receipt produces an
after-parent continuation; one further empty terminal page may be necessary to
establish exhaustion. Consumers must follow `nextCursor` rather than infer the
end from item count. Downloads contain only the displayed page.

The source uses the Indexer service API to enumerate candidates and complete
node receipts to qualify them. OPS does not query the Indexer database, add an
event store, or modify the Indexer API. Each page rechecks current authority,
namespace and canonical headers at both final gates. The existing durable
`exposure_prepared` audit commit is required before returning any protected bytes,
including empty advancing pages; unknown or failed commits return no page.

Deploy compatible OPS and Explorer builds before enabling Events in standing
rules. Existing cases and audit rows are preserved; no SQL migration is needed.
After the first Events exposure is recorded, a rollback build must still
understand that audit-summary resource. Disabling new Events cases alone does
not make an older reader compatible with already recorded Events summaries.
