# Included block history source

`rpcexecution.HistoryBlockClient` acquires the complete transaction array and
receipt set of one included block from an explicitly selected node reference.
Its immutable observation supplies actual signed inputs, senders, destinations,
ROOT creation presence, fees, receipts and logs. It creates no authorization,
historical namespace verdict, disclosure source, SQL state or execution grant.
`EthereumHeader()`, `Uncles()` and `Withdrawals()` return detached typed copies
for later full-block rendering. Reported size and total difficulty preserve
absent, explicit-null and present states in `HistoryFieldPresence`, including
their digest binding; neither value is invented from filtered or missing data.

The constructor checks the reference profile, credential binding and recomputed
network key. A selector is a fixed number or nonzero hash. Number zero is valid;
pending and moving tags have no representation here. A hash lookup is followed
by a numeric canonical check at the same height.

Acquisition performs at most ten physical RPC attempts: one four-request
`HeaderClient.Read`, the full block by hash, its entire receipt set by hash, then
another four-request numeric header read. Both header reads check chain ID,
recomputed genesis and exact `eth_syncing=false`. The complete RLP header hash
must agree throughout. No trace request, repair, retry, redirect or fallback
occurs. Missing, duplicate, malformed or reordered rows reject the whole block.
An empty observation requires an actual empty transaction array, empty receipt
set and matching gas/bloom/header observations.

Node honesty is an explicit trust boundary. Header hashes are recomputed, but
transaction/receipt tries and consensus rules are not re-executed or proved.
This observation says that this node returned a complete population for this
block; it does not prove all-chain or period coverage. Independently acquired
blocks are not a common C2 canonical view merely because each passed a check.

History decodes signed types 0–4, including unprotected historical legacy and
its Frontier signature rules. It verifies canonical signed bytes, recovered
sender, network binding, hash and exact inclusion position. History values
cannot be converted through this API into admission `VerifiedTransaction`;
protected send admission retains its existing type and replay-protection rules.
Unknown future transaction/header formats reject. Set-code authorizations are
signed transaction data and grant no OPS identity, group or permission.

Receipts preserve either explicit status 0/1 or an exact 32-byte post-state root,
with separate presence-aware getters. A root receipt has unknown success. Both,
neither, null or malformed alternatives reject. Only explicit status zero
requires empty logs. A receipt creation address is checked against the signed
top-level CREATE; it proves neither runtime survival nor a child creation.
Each log retains its actual emitter, topics and data and has exact block,
transaction and contiguous global log-index associations. Removed logs reject.
Receipt blooms and the combined block bloom must match those actual logs.

Fee fields retain uint256 precision. Legacy/access-list effective prices match
the signed gas price; dynamic types use `min(cap, baseFee + tip)` without integer
wrap. Receipt gas deltas and final cumulative gas match the block. Blob gas and
prices are retained and checked against signed bounds and block totals; this
does not add a consensus fork or KZG verifier to the source.

Default conjunctive ceilings are ten seconds, ten physical requests, 8 MiB per
block/receipt response and 17 MiB of total raw response bytes, including JSON
whitespace. There are at most 10,000 transactions, 20,000 logs, four topics per
log, 2 MiB per transaction/receipt JSON value and 512 KiB per canonical signed
transaction. Access lists, storage keys and authorizations have independent
bounds. The existing parser also enforces depth 32, 120,000 values/members and
8 MiB scalar text, so nominal collection ceilings do not promise every shape
fits. All limits can only be lowered.

The normalized payload budget is 16 MiB. It charges canonical signed bytes,
decoded input/access/blob/authorization data, logs, variable header extra data,
withdrawals/uncles and fixed metadata allowances. This is not a Go heap/RSS
bound. Block wire/parser values are not retained into receipt acquisition;
detached getters allocate separate caller-owned copies. Public serving still
needs its own final byte and concurrency limits.

`Recheck` repeats one numeric header read, with at most
`min(selected MaxRequests, 4)` attempts, `min(selected Timeout, 5s)` and
`min(selected MaxTotalWireBytes, 64 KiB)` raw response bytes. Native header
envelope caps remain 16 KiB and chain/sync caps 4 KiB. Acquisition plus one
recheck costs at most fourteen requests and 17 MiB + 64 KiB, with component
time ceilings totalling fifteen seconds under the same earlier caller fence.
These are bounds, not a latency SLO.

An observation retains only the original caller's Done channel and optional
deadline, never its context values, auth/request state or the acquisition child
context. A bounded local cancellation bridge honors that original fence during
recheck; a fresh longer context cannot reset it. Passing a shorter context also
limits the operation. Owner/source mismatch, canceled/expired fences and a
changed canonical header fail closed without replaying block bodies.

The finite actual-node check exercised legacy ROOT CREATE and CALL/log history,
empty genesis, numeric/hash selectors and canonical rechecks on Reth 2.5.2,
commit `5a6940e351fed80458fe6c9da8581cbe4b8bd036`, cached image
`sha256:3b46426a440732302431d2640ab393de45372416882f9f689f4cf5ed7fd121bf`.
Types 1–4, unprotected legacy and post-state receipt outcomes have controlled
signed/TLS fixtures; those fixtures are not real-backend qualification for
other types, nodes or fork profiles. No throughput measurement is implied.

Ordinary history, Explorer and visibleTo serving apply their own participants,
current rights, emitter privacy, ABI rules, namespace and live-view checks.
Pending and positive EOA attribution need their actual source semantics.
State reads use current Git/A3 rights and their historical-method floor; they
do not require a fabricated ROOT or a historical end-state extension of C2.
