# Retained financial evidence

The finance disclosure reader borrows the operational admission reader connection pool. It reads the original admission event actor and organization, recorded decision, policy and quote. It reads no travel-rule PII and makes no price-provider or chain request. Its existing SQL reader role retains its established admission-table read permissions; the adapter does not add grants or make that role a database-owner-proof boundary.

The declared population is `RETAINED_ADMISSION_DECISIONS_AS_OF_SNAPSHOT`: all retained rows matching the exact organization, target actors, inclusive time interval and optional from/to address filter in one read-only repeatable-read observation. An admission-only observation has no known addresses and cannot match an explicit address filter. The complete compliance report accepts at most 100 matching rows; larger complete reports require a narrower request. A zero result means no matching retained rows, not that no operation occurred or that a customer is compliant. Rows describe recorded admission decisions before delivery; they do not establish execution, mining, KYC or legal compliance.

The retained profile also supports `compliance_report` with `view: "list"` for
admission decisions. It returns `items`, `nextCursor` and an exact decimal-string
`matchingRetainedCount` from finance, independently of activity request totals.
Each page contains at most 100 decisions and uses an authenticated ascending ID
keyset. Every request scans and validates the entire bounded matching cohort,
retaining only page bodies and compact row digests. It preserves the existing
8 KiB row, 1 MiB retained-body and 2 MiB cumulative hash-input limits, with a
16,384-row scan ceiling, SQL timeouts and the original five-second operation
deadline. A large cohort fails explicitly rather than returning a false end.

List reads require only the finance source. They do not query node, Indexer,
wallet, activity or sanctions sources. The original `report` view still requires
its original five sources and remains complete-or-error at 100 decisions. The
legacy data profile rejects the new list view.

List coverage is `RETAINED_AT_READ` with `sourceBasisDigest`. Every continuation
and final source check recomputes the whole original cohort reference. Changes
require an explicit restart; the reader does not automatically retry or combine
different observations. This is bounded interactive browsing, not an immutable
snapshot or a large export service. A page download contains that page only.
Actor and time filters narrow the case on the server; time bounds are inclusive
UTC seconds. Changing either filter starts a new read.

The source reference hashes the entire scoped row set and source state. Event IDs preserve row identity, not commit order. A fresh check recomputes the complete predicate and catches a late commit with a lower ID as well as a scoped append, deletion or change. These are sampled checks: a later change can occur after the check. No transaction or connection is held across rendering or exposure audit.

Retention and owner recovery keep their existing operational semantics. This reader makes no assertion that earlier deleted or missing history was preserved. It creates no table, index, role, grant, retention watermark or background worker. Reports require the other qualified source components and the disclosure case authorization, expiry and exposure-audit checks.
