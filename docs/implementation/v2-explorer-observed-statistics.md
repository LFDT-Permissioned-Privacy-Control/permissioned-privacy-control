# Explorer statistics and transaction history

The V2 overview shows counts and a chart for one bounded page of transactions
that the caller can currently read. It does not use the indexer's global SQL
counters. A page is not a total for the chain, an organization or a time period.

`GET /api/v2/explorer/stats?limit=25` returns:

- `observedTransactions`: transactions emitted on this page after current privacy
  filtering and removal of the pagination lookahead.
- `observedBlocks`: distinct blocks represented by those transactions.
- `observedParticipantAddresses`: distinct visible `from` and `to` addresses in
  those transaction responses. Masked zero-address placeholders are excluded.
- `page`: the ordinary opaque continuation information, with
  `coverage: "OBSERVED_VISIBLE_PAGE"`.

The three counts are decimal strings. The response does not provide global
`totalTransactions`, `totalBlocks` or `totalAddresses`. For example, an empty
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
No additional SQL aggregate query or unrestricted history scan is performed.
Continuation remains bound to the original identity assertion, selected policy,
wallet revision, index binding and upper anchor. Retained index rows remain a
source boundary; the response does not certify complete blockchain history.
The Explorer policy domain is `ops-explorer-current-read/v2`; cursors from the
earlier timestamp-only history response are rejected.
