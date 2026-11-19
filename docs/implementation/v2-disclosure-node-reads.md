# Node reads for protected disclosure transaction pages

Protected disclosure transaction lists accept explicit page sizes from 1 to 100.
The Admin UI requests 25. An API request omitting the limit retains the existing
normalized default of 50. A node-capacity limit can produce a shorter page with
a cursor at the last returned transaction; it does not imply exhausted history.
An address-selection witness never advances that cursor.

Each read caches complete CB1 block observations only for that request. Range
ownership checks, candidate transactions and the selected point-ownership
support reuse those observations. A shared set performs network/header checks
before and after its block/receipt reads. It preserves the original request's
cancellation and deadline, including when an acquisition child has finished.
The standalone block reader keeps its original ten-request contract.

CB1 validates the selected node's full returned transaction and receipt arrays,
signed transaction data, positions, header binding, gas totals and log blooms.
It does not recompute transaction/receipt trie roots or verify consensus. This
is the existing selected-node trust boundary, not an inclusion-proof API.

The whole read keeps these limits across acquisition and both delivery checks:

| Limit | Value |
|---|---|
| Canonical numbers committed to node work | 128 |
| Physical node attempts | 931, bounded by 7C+35 for C committed numbers|
| Body acquisition sets | 3; a body number is never reacquired|
| Header-only support batches | 2 |
| Response wire bytes | 32 MiB |
| Charged owned work | 16 MiB |
| Protected output | 2 MiB |
| Original operation lifetime | 5 seconds |

The attempt allowance is higher than the previous 64-attempt implementation.
This is a bounded capacity tradeoff to serve practical pages; it is not a
throughput guarantee. The existing service concurrency gate still applies.
Decoder ownership includes normalized receipts and logs; it is not a Go RSS
measurement. Failed dispatches, before-fetched unused suffixes and discarded
planning candidates do not refund calls, bytes or touched-number credits.

Acquisition reserves 262 attempts, 4,243,456 wire bytes and 256 KiB of owned work for
the two final node checks. Each final source pass has up to one second, clipped
to the original remaining lifetime. Acquisition also reserves time for its own
post headers. Required mixed body/header support is budgeted jointly before I/O.

Point support is discovered before acquisition. If a full prefix cannot fit,
at most eight metadata-only planning passes halve it; only the chosen prefix
fetches support. Final namespace checks compare the original requirements
before any further support acquisition and reuse known support. Both final
node checks read fresh canonical headers by number. A changed requirement,
reorg, malformed response, unavailable source or mid-I/O timeout fails the
whole read. Capacity checked before optional I/O can shorten a page; an I/O
failure cannot masquerade as a successful shorter result.
