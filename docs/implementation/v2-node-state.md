# Bounded node state reads

`rpcexecution.StateClient` parses five state-read methods and returns validated
observations. It has no HTTP route, caller identity, SQL connection, execution
VM, authorization decision or response-delivery permission.

| Method | Parameters | Result |
| --- | --- | --- |
| `eth_getBalance` | Address, optional block | Canonical uint256 quantity. |
| `eth_getTransactionCount` | Address, optional block | Canonical full uint64 quantity. |
| `eth_getCode` | Address, optional block | Hex data, including empty code, bounded to 1 MiB decoded. |
| `eth_getStorageAt` | Address, slot, optional block | Exactly 32 bytes of hex data. |
| `eth_getProof` | Address, ordered storage keys, optional block | Closed account and storage proof shape, with the exact requested address and ordered key values. |

Each opaque query retains its target, storage-key spellings and decoded widths,
normalized parameters, and original block-input form. Each observation retains
that same query and its digest with the source and result. Scalar results do
not identify their address or block by themselves. Public slice accessors return
detached copies; the opaque query can be reused without mutation.

An omitted or null block becomes `latest` on the wire. Named `latest`,
`pending`, `safe`, `finalized` and `earliest`, signed-63-bit block numbers,
32-byte hashes and closed EIP-1898 objects are supported. A hash object can
require canonicality; a number object can also contain a named tag. Original
object input remains distinguishable from a scalar tag: `HistoricalInput()`
preserves the legacy input guard's classification even for
`{"blockNumber":"latest"}`. This classification does not prove the state
point's canonicality or establish historical ownership. `pending` is passed
through explicitly and is never replaced with `latest`.
A node may reject a selector, including a pending proof for a state without a
block proof. Such a failure returns no observation and does not trigger a retry
against another selector.

Storage keys follow the node's hex-key semantics: optional prefix, odd digit
padding, and at most 32 decoded bytes. The query preserves the original spelling
for later access checks. Transport normalization preserves whether a proof key
is a full 32-byte data value or a shorter quantity; empty hex keys denote zero.
Order and duplicate keys are retained. A proof with no keys is account-only.
The account proof can be null or an array; the storage proof is an array, and
each storage entry requires its own array of proof nodes.

The client checks the bound chain ID and hash-recomputed genesis header, then
performs the selected state read. The operation makes at most three physical
RPC calls with the same credential and one five-second deadline, shortened by
the caller's deadline. It uses the shared read transport with no redirects,
retries, fallback sources or replayable POST bodies. The `rpc-state/v1` source
tag cannot activate an execution acquisition profile. These checks qualify the
configured network, not the selected state or a canonical head; environment
and deployment ID remain approved operational inputs.

Default limits are 128 KiB of parameters, an 8 MiB result response envelope,
1024 storage keys, 128 nodes per proof, 70000 proof nodes in total, 4096 decoded
bytes per node, and 4 MiB of decoded proof data. Configuration may lower these
positive limits. Collection limits apply before append; byte allowances are
checked before hex decoding. Queries parsed under larger limits are checked
against the selected client's input limits before I/O. The shared JSON reader
also bounds depth, object members, total values and decoded scalar text.

These limits compose: not every possible 1024-key proof fits the wire limit,
and hex encoding and envelope overhead can exhaust that limit before the
decoded-proof ceiling. Wire, decoded text, query-digest work, detached getters,
JSON encoder buffers and physical RSS are different costs. The caller owns
concurrency and output lifetime; this library adds no queue.

The caller must authorize the actual target, selected organization, raw method
and storage slots before invoking the client, and bind the resulting query and
source to the same request before delivery. Proof nodes remain opaque: Merkle
nodes can embed neighboring leaves, so matching requested storage keys does
not establish that proof bytes contain no other values. This client verifies
neither Merkle proofs nor proof-node confidentiality. Current and historical
permissions, canonical state selection, pending-state privacy, auditing and the
final permission check before output belong to the serving consumer.
