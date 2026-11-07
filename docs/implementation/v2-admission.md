# Native transaction admission storage

`internal/admission` connects the existing financial `compliance.Checker` to an
immutable approved compliance catalog and narrowly scoped operational storage.
`internal/operational/admissionsql` is its explicit PostgreSQL adapter;
`internal/compliancehttp` exposes eleven administration routes. These packages
do not mount a transaction send endpoint or assemble a complete V2 server.

## Financial and privacy effects

The trusted raw orchestrator supplies an authenticated current View, an opaque
verified signed transaction, and its qualified signed execution. It must already
check method, native execution, read profile, wallet resolver binding, and Guard
readiness. `CheckAndRecordRaw` alone grants no execution permission.

One transaction holds a transient advisory lock on `(network, transaction hash)`
and runs the real Checker once. It commits the unused travel-record claim,
financial decision event and relevant qualified privacy facts together, before
any Guard enqueue or node broadcast. Infrastructure or audit failure rolls all
of those back. A genuine denial with a successful event commits that denial
without returning publication authority. An ambiguous commit returns no receipt;
only a fresh client request may retry. Nothing is replayed automatically.

Travel-record idempotency is `(network, organisation, ActorID, transaction hash)`.
An already used record remains bound and must still cover current beneficiary,
token, currency and value. Its original expiry does not invalidate a same-scope
retry. An incompatible bound record cannot be replaced by another unused record.
Different actors or organisations need their own records. This scoped behavior
is an explicit V2 addition: selected V1 Guard-push and unsigned-preflight paths
did not use the optional node-policy worker's global transaction claims.

Qualified privacy origins require a captured, user-proved signer association for
the same actor. An unlinked relay creates financial/request audit only. A later
ordinary relay by actor B preserves actor A's origin and never appends B's wallet
evidence under A. A first nonempty `visibleTo` list creates one immutable,
globally scoped share row with at most 32 canonical ActorIDs. Empty lists reserve
nothing. Changed sender/list conflicts; lists are never unioned. Nonempty sharing
requires a proved signer association and cannot cross an existing data-org fence.

An origin contains its primary compact anchor/wallet witness inline. At most 1,023
additional distinct witnesses are allowed per hash. Repeated witnesses retain
their first decision/source timestamps; each current receipt independently uses
the current financial check and quote set. Raw transactions and traces are not
copied into these tables.

## Time and valuation

The source and operational network bind environment, canonical positive uint64
chain ID, genesis hash and deployment ID. Actual node-genesis verification remains
a server assembly responsibility. Each operation is bounded to five seconds,
with a one-second lock timeout, three-second statement timeout, and a separate
one-second rollback context. Each narrow pool permits eight connections.

Quotes are immutable trusted observations captured before opening the SQL
transaction. Both observation and provider timestamps must be current and
nonfuture. Only quotes actually used for valuation gate commit and the first
external effect. Missing/stale observations follow the approved unknown-price
and monitor rules. No SQL price cache or HTTP request runs inside a transaction.
The actual provider adapter is a separate assembly dependency.

`DecisionAt` is sampled after acquiring the hash lock. An unused record must be
eligible then and still eligible immediately before commit. Current JWT and used
quote freshness are checked before allowed commit and again by
`RawReceipt.RequirePublishable` immediately before the first external effect.
An already enqueued Guard approval retains its original TTL; receipt checks do
not renew it, cap it to JWT expiry, or implement background redelivery.

Valuation retains the Checker's float64 limits. SQL uses unscaled `NUMERIC` with
one finite, nonnegative, bounded shortest-decimal conversion for both values and
comparison parameters. This avoids adding cent rounding but does not make
float64 arithmetic exact. Existing rounded imported values remain rounded values.

## Administration

All routes are under `/api/v2/orgs/{orgId}/compliance/`:

* `GET config`, `tokens`, `address-thresholds`, `sanctions`, `quotes` show selected
  approved source settings. They have no corresponding policy write routes.
* `POST travel-rule-records` accepts a target ActorID, bounded originator and
  beneficiary PII, transfer type, optional token address, beneficiary and positive
  integer amount. The service computes fiat value, currency and expiry.
* `GET travel-rule-records` lists metadata; `GET travel-rule-records/{recordId}`
  returns that one record's bounded PII; `DELETE` removes only an unused record.
* `GET events` lists scoped decision metadata.
* `POST preview` accepts `{originatorActorId, signedTransaction, renewal?}`. It
  derives hash/from/to/value/input from verified protected signed bytes, runs the
  real read-only Checker preview and returns no send receipt. Naming a target
  ActorID establishes neither membership nor execution authority.

True organisation admins can write; admins and readonly admins can read.
Operator/local-admin claims and contract-admin flags do not bypass that test.
There is no user directory lookup. Lists are limited to 100 rows and use encrypted
15-minute cursors bound to endpoint, network, generation, coverage, organisation,
viewer, manifest and page size. HTTP construction requires an explicit nonzero
AES-256 keyring. Requests reject duplicate, unknown, incorrectly cased and null
fields. Creation bodies are limited to 256 KiB, preview to 2 MiB, raw queries to
16 KiB, each PII object to 64 KiB/depth 16 and responses to 2 MiB.

The initial signed execution boundary supports existing destinations. Creation,
multi-org execution parity, canonical protected-history reads and complete
provider/UI/server assembly require their own explicit implementations; this
component does not substitute for those release requirements.

## Schema, retention and recovery

Schema 1's five operational data tables are `travel_records`, `compliance_events`,
`qualified_tx_origins`, `extra_privacy_witnesses` and `tx_shares`. Two metadata
tables hold schema version/checksum and network readiness/coverage. None stores
approved policy, users, groups or memberships.

The explicit [creation-intent profile](native-creation-intent.md) adds four
operational journal tables through offline schema 2. Their separate immutable
reference, capacity and recovery rules apply when that profile is selected.

Run `ops-v2-admission-migrate` offline with an explicitly named DSN environment
variable. `migrate` assigns pre-existing app, reader and retention roles;
`bootstrap-empty` accepts only a previously empty network. Startup verifies the
schema, expected indexes/trigger and effective privileges, including access to
unrelated/legacy tables. Schema-1 app writes are restricted to inserts, unused-record
deletes and the two monotonic record-use columns. An independent reader cannot
write. Migrator/database/backup operators remain trusted: forged operational
facts can affect privacy and compliance despite policy being file-authoritative.

`RETENTION_COMPLIANCE_LOGS` and `RETENTION_TRAVEL_RECORDS` default to seven years;
zero means keep forever. `RETENTION_CLEANUP_INTERVAL` defaults to one hour and
`RETENTION_COMPLIANCE_CLEANUP_BATCH` to 1,000 (maximum 1,000). Cleanup removes old
unreferenced events and expired unused records only. Used records and their
events, origins, shares and witnesses are retained until a qualified finality and
archive retirement protocol exists. That conservative retention costs storage.

Recovery requires draining all replicas and workers. `begin-recovery` marks the
network unready with a new generation. Restore all five data tables, constraints
and event identity sequence using offline owner tooling, then run `finalize` with
an explicit completeness acknowledgement and externally recorded coverage digest.
Present record bindings, quote/witness shapes and recipient digests are checked.
Stable facts survive generation changes. Missing dependent history must not be
treated as permission to manufacture ownership or borrow another record.
An internally coherent incomplete backup plus a false operator attestation cannot
be detected from these rows alone. A failed or oversized validation remains
unready; recovery is not an online fleet activation mechanism.
