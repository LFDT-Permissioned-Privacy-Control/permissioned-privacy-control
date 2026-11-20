# Explorer statistics and transaction history

The native overview shows viewer-scoped transaction, account and token counts.
Token and address pages use the same typed count results. Counts describe the
rows permitted by ordinary reads; disclosure cases do not enlarge this scope.
The API also retains separate statistics for one visible transaction page.
A page sample is never promoted into a total.

`GET /api/v2/explorer/stats?limit=25` returns:

- `observedTransactions`: transactions emitted on this page after current privacy
  filtering and removal of the pagination lookahead.
- `observedBlocks`: distinct blocks represented by those transactions.
- `observedParticipantAddresses`: distinct visible `from` and `to` addresses in
  those transaction responses. Masked zero-address placeholders are excluded.
- `page`: the ordinary opaque continuation information, with
  `coverage: "OBSERVED_VISIBLE_PAGE"`.

The three observed fields are decimal strings. They are page samples, separate
from the optional `counts` results described below. For example, an empty
visible page has three zero counts, but it can still have a continuation. These
zeros describe the page; they do not claim that no other transactions exist.

Use the returned `page.next` as `cursor`, with the same `limit`, to examine the
next page. `hasMore: null` with `scanLimited: true` means the bounded read cannot
yet determine whether another visible transaction exists. Even
`hasMore: false` only ends that traversal; the current page's counts never become
an all-history total.

`GET /api/v2/explorer/stats/tx-history?interval=day&limit=30` groups the emitted
visible transaction page into `{timestamp, count}` buckets. Both values are
decimal strings; `timestamp` is the bucket's start in Unix seconds. Supported
intervals are UTC hours, UTC days and UTC weeks starting on Monday. The first
partial week at the Unix epoch starts at zero.

The chart response is `{items, page}` and uses the same
`OBSERVED_VISIBLE_PAGE` coverage. `limit` bounds visible transactions, rather
than the number of time buckets. A bucket can appear on two consecutive pages;
each count covers only that page's transactions. Empty intervals are omitted,
not filled with zeros. The Explorer UI displays one page's bars at a time and
labels this scope beside the chart.

Both operations use the same current identity, wallets, shares, approved privacy
rules, included-parent qualification and canonical-source rechecks as the
transaction list. They retain the original request budget and deadline and pass
through the same durable activity Recorder before response bytes are released.
Page samples and chart buckets use the transaction projection. Optional counts
use the bounded readers below; no unrestricted history scan is performed.
Continuation remains bound to the original identity assertion, selected policy,
wallet revision, index binding and upper anchor. Retained index rows remain a
source boundary; the response does not certify complete blockchain history.
The Explorer policy domain is `ops-explorer-current-read/v2`; cursors from the
earlier timestamp-only history response are rejected.

## Viewer-scoped counts

`counts` contains named results such as `transactions`, `accounts`, `tokens`,
`holders`, `tokenTransfers` and `internalTransactions`, as appropriate to the
resource. Each result identifies `population: "ORDINARY_VISIBLE_ROWS"` and uses
one of these forms:

| Result | UI | Meaning |
| --- | --- | --- |
| `status: "exact", value: "1234"` | 1,234 | Exhausted the stated retained range, or counted one current indexed observation. |
| `status: "at_least", lowerBound: "1234"` | ≥1,234 | Counted this many permitted rows before the bounded scan stopped. |
| `status: "unavailable"` | — | No qualified count; this is not zero. |

Historical numbers include a `SNAPSHOT` range with `fromBlock`, `throughBlock`
and `headHash`. `coverage` distinguishes complete retained range, scan limit,
pruned history and history not indexed yet. An exact retained-range count does
not claim older history exists in the index. Current address, token and holder
counts instead use `consistency: "CURRENT"`, `coverage: "current"`; they are not
an atomic historical snapshot with a separately fetched page. Numeric results
include their actual `observedAt`. Tap or focus a displayed count for these details.
Legacy scalar count fields are present only when their matching result is exact.

CURRENT counts use one finite typed Indexer API observation over the original
caller's complete eligible Full-address set. OPS never queries the Indexer
SQL database. Historical counts run the ordinary privacy projection, including
its participant, sharing and event rules, and retain each contributing source,
wallet and node proof through delivery. Every submetric needs its own ordinary
RPC permission and credential. One shared budget bounds the request. Count-only
failure drops the optional numbers; the base page still has to pass its own
final checks and original deadline. Large authority sets or histories may therefore yield an
unavailable count or a lower bound. List continuations do not accumulate totals.

Token supply and optional USD price are current indexed source metadata, shown
only under ordinary Full token visibility. **Indexed supply** is not a live
`totalSupply()` call or a historical balance certificate. Values remain exact
decimal strings; unknown supply/price remains absent rather than zero. Portfolio
values use those returned prices without inferring a complete portfolio total.
The all-transfer type control filters at the source before pagination, and its
cursor is bound to that selected standard.

The Home **Avg Block Time** card uses only the one ordinary block page already
returned to that browser. It averages positive timestamp differences between
consecutive-height neighbours, excludes genesis and gaps, and shows the usable
interval count and sampled page range. Fewer than two usable headers gives no
value. This is a sampled display, not the legacy last-100-row SQL average. It
adds no endpoint or permission and never combines separate polls or pages.
