# Protected disclosure reads

`disclosurecase.NewWithData` adds a protected-read gate to the existing case
administration library. `disclosurehttp.NewWithData` exposes its five administration
routes and one additional operation:

```http
POST /api/v1/disclosure/cases/{id}/read
Authorization: Bearer <OPS access token>
Content-Type: application/json

{"v":1,"resource":"activity_summary","view":"report"}
```

The `ops-v2` command does not mount this handler. The library requires an owned
`disclosuredata.Sources` implementation; it does not supply an audit/history data
adapter or establish the provenance of arbitrary external data. Its source
interfaces are internal application boundaries, not a way for HTTP callers to
provide data, endpoints, verified flags or permissions.

The original `disclosurecase.New` and `disclosurehttp.New` remain metadata-only.
The metadata-only HTTP constructor rejects a data-enabled service, so it cannot
bypass that service's admission and deadline checks.

## Authorization and cases

Git-approved standing rules define permission. A case records concrete targets,
resources, addresses, a data interval and a disclosure level. Creating a case does
not ask the customer to approve it and does not manufacture permission in SQL.

Every protected operation checks the current verified recipient, current group
eligibility, open case status and one current rule covering the **whole original
case scope**. Narrowing an individual query cannot repair a failed whole-case
check. The effective end is the earliest of the recorded expiry, creation time
plus the current rule's duration ceiling, and current rule expiry. Administrative
access to archived case metadata does not grant access to protected data.

The new service uses a distinct case namespace bound to environment, chain,
genesis, deployment and restore epoch. The shared `networkidentity` helper
preserves the existing operational network-key encoding. Key derivation does not
verify a connected node. Existing metadata-only cases are not silently promoted
into this namespace; an explicit import must establish the intended binding.
Reusing an old operation's idempotency key in another namespace returns conflict.

## Closed query and projection

The query has literal version `1`, a resource and a view. Optional target,
address, time and level fields can only narrow the original case. List requests
accept a limit of 1–100 and an authenticated cursor. Transaction detail requires
Full access before hash/locator value checks or source lookup. Address resolution
always projects the current authorized level; its opaque ID is not permission to
obtain the raw address.

Recognized resource/view pairs are:

| Resource | Views |
| --- | --- |
| `addresses` | `list`, `resolve` |
| `transactions` | `list`, `detail` |
| `activity_logs` | `list` |
| `activity_summary` | `report` |
| `sanctions_report` | `report` |
| `compliance_report` | `report` |

`events:list` is recognized but has no output implementation in this library.
The data constructor rejects a selected rule requiring it. This guard does not
substitute for implementing and qualifying event privacy in an assembled release.
Activity and summary data do not claim to support arbitrary address filters;
address-restricted activity scopes are rejected rather than broadened.

Full projection can include the defined addresses, actor identifiers, transaction
hash/value and qualified detail fields. Lower levels omit those fields and use
keyed labels or `[PRIVATE]`. Canonical block/index fields can still permit public
chain correlation; field projection is not a cryptographic anonymity guarantee.

The wire `gasPrice` is the mined receipt's effective price. Signed legacy prices
and EIP-1559 maximum/priority caps are separate source facts. A signed fee cap is
not reported as the paid price. Source adapters must qualify real receipts and
signed envelopes; missing fields and synthetic success defaults are not accepted
as authoritative data.

## Sources, cuts and bounded work

Source descriptors bind exact network, epoch, generation, format, coverage and
immutable cut references. Activity, history and financial records must reference
the correct source kind. Wallet facts define current associations and `Mine`, not
historical authorship or data-organization ownership. The one wallet snapshot
contains at most 4,096 total tuples across query targets and, when needed, the
viewer. The viewer cannot add an address to the target scope.

Source observation time is excluded from stable cut identity. Re-observing
unchanged facts later does not invalidate pagination or refresh an old proof.
Owned sources check current freshness, recovery and fault state separately.
Cursors bind the case, recipient, original rule/bundle, semantic query, source
plan/cuts, wallet facts and actual render-key generation. The service authenticates
the cursor before source work and passes its detached after-position explicitly;
sources receive no cursor or render keys.

Rows must be strictly ordered, unique and after the authenticated position.
A page must establish a full page plus lookahead or actual source exhaustion.
Reaching a work budget returns an error, never a false end or partial complete
report. Address resolution consumes a complete bounded candidate set rather than
only its first page. Full detail matches a locator only against the returned
transaction's qualified in-scope target participants.

Reports are returned by the same POST operation with a fixed attachment filename,
`ops-disclosure-report.json`, and `Cache-Control: no-store`. There is no report GET
or open blob URL. A complete activity aggregate can use one exact scoped SQL
COUNT/GROUP BY at a qualified source cut; it need not transfer every raw record.
The data library imposes no unrelated block-span ceiling on monthly activity
queries. Actual adapters remain responsible for complete populations and finite
statement deadlines.

The HTTP service admits at most eight operations immediately across all handlers
sharing it, including administration routes. A ninth returns unavailable before
body/store/source work. New handlers enforce five-second body/write deadlines;
the server mount also needs header, read, write, idle and header-size limits.
At a deadline the connection may close without an error JSON body.

Raw facts and expanded output each have a 2 MiB aggregate variable-byte budget
and a 16,384-entry work budget, checked before deep scans, copies, aliases or
encoding. Repeated references are charged repeatedly. Checked arithmetic avoids
size overflow. Standard JSON escaping has a finite conservative encoded-length
bound, and actual output including its newline must still fit 2 MiB. A canonical
1 MiB hex detail is not rejected merely by multiplying it by a worst-case escape
factor. Owned adapters must apply equivalent aggregate budgets before they
materialize large fields.

## Durable exposure and recovery

The service prepares a detached bounded response and commits an
`exposure_prepared` event under the case row lock before returning any bytes.
The locked check repeats current access and case version. An unknown commit
releases no response. The final byte gate checks fresh token/rule time again;
an event can remain prepared but unsent after expiry, a crash or socket failure.
It does not prove client receipt. Exposure and revocation serialize at the case
transaction; this is not a claim of instantaneous fleet-wide revocation.

Private exposure metadata binds the semantic query, stable source set, render
context, exact output bytes/hash and attempt ID. The hash includes the final
newline. Public case-audit projection does not expose these private digests.
Legacy summaries remain readable metadata; an old action name without the new
closed metadata is not a qualified new output receipt. The existing SQL schema,
role grants and retention behavior are unchanged. SQL timestamp reads are
represented in UTC without changing the stored instant.
