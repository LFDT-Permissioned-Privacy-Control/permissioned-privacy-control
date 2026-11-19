# Retained financial evidence

The finance disclosure reader borrows the operational admission reader connection pool. It reads the original admission event actor and organization, recorded decision, policy and quote. It reads no travel-rule PII and makes no price-provider or chain request. Its existing SQL reader role retains its established admission-table read permissions; the adapter does not add grants or make that role a database-owner-proof boundary.

The declared population is `RETAINED_ADMISSION_DECISIONS_AS_OF_SNAPSHOT`: all retained rows matching the exact organization, target actors, inclusive time interval and optional from/to address filter in one read-only repeatable-read observation. An admission-only observation has no known addresses and cannot match an explicit address filter. A zero result means no matching retained rows, not that no operation occurred or that a customer is compliant. Rows describe recorded admission decisions before delivery; they do not establish execution, mining, KYC or legal compliance.

The retained profile also supports `compliance_report` with `view: "list"` for
admission decisions. Its version-2 result returns `items`, `nextCursor`, an exact
decimal-string `matchingRetainedCount`, `observedAt` and
`pagination: "live-keyset"`. The count comes from finance, independently of
activity request totals. Each page contains at most 100 decisions ordered by
recorded decision time descending, then ID descending. A single read-only
repeatable-read observation counts matching rows and selects one bounded page.
The reader validates only those selected bodies and a one-row lookahead; it
does not scan or retain every matching body. Existing row/body limits, SQL
timeouts and the five-second operation deadline still apply. A timeout fails
explicitly rather than returning a false end.

List reads require only the finance source. They do not query node, Indexer,
wallet, activity or sanctions sources. The version-2 `report` result still
requires its original five sources. It returns their activity and sanctions
summary, `kyc: "not_evaluated"`, and a finance summary containing the matching
retained count, observation time, coverage and the `compliance_report/list`
detail selector. It does not inline financial bodies and does not fail merely
because more than 100 decisions match. Detail remains available through the
paged list. The legacy data profile rejects that list view.

List coverage is `RETAINED_AT_READ` with `sourceBasisDigest`. Every continuation
and final source check verifies the source identity, generation, readiness and
the sampled returned rows' content and continued scope. Normal matching appends
do not invalidate an already sampled page or report. The count is exact as of
that response's observation; a later page or Refresh can show a different count.
Pagination is live, so intervening additions or changes can alter later pages.
It is bounded interactive browsing, not an immutable snapshot or a large export
service. A page download contains that page only.
Actor and time filters narrow the case on the server; time bounds are inclusive
UTC seconds. Changing either filter starts a new read.

Each page's source reference binds its actual observation and sampled rows.
Event IDs preserve row identity, not commit order. The authenticated `df1`
cursor binds the case, recipient, filters, rendering keys and stable source
identity, plus the exact last decision-time/ID tuple; it does not promise a
frozen cohort or use a maximum ID as a commit frontier. Prototype `dd2` finance
cursors are rejected and require a fresh read. Other resources keep their
existing cursor semantics. A final check rejects a sampled row that was changed,
removed or moved outside scope. Aggregate reports recheck source context without
recounting. These are sampled checks: a later change can occur after the check.
No transaction or connection is held across rendering or exposure audit.

Retention and owner recovery keep their existing operational semantics. Finance
retention does not maintain a historical completeness watermark, so this reader
makes no assertion that earlier deleted or missing history was preserved. It
creates no table, index, role, grant, retention watermark or background worker.
Reports require the other qualified source components and the disclosure case
authorization, expiry and exposure-audit checks.

Exposure audit records retain their existing version-1 fields and canonical
encoding. The qualified-total scalar accepts canonical decimal uint64 values;
it is not subject to the renderer's 16,384-container-entry memory budget. It
must still be at least the bounded returned-row count. A compatible rollback
reader must include this validator correction before reading audit records with
larger totals; no SQL schema migration or history rewrite is required.
