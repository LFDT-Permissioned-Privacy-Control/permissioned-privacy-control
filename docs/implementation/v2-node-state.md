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

## Core permission and delivery

`rpcengine.StateEngine` is that consumer for the immutable
`RuntimeCreationObserved` profile. It uses current approved Git permissions for
the target even when the requested state is old. It does not evaluate bytecode,
invent historical data ownership or use a SQL user or policy directory.

The separately approved StatePolicy explicitly lists anonymous methods and
preregistered addresses. Its digest binds the bundle manifest, normalized
definition and full actual method map, including aliases and required claims.
Missing lists, null, unknown keys and duplicate keys reject. Anonymous access
can name only canonical balance, code and nonce methods, requires an absent
Authorization header and rejects historical input. An invalid supplied token
cannot become anonymous. Aliases, storage and proofs cannot be anonymous.

An authenticated read requires a mapped organization, the exact raw method
grant, the union of raw and canonical required claims, and the selected
organization's explicitly bound node credential. Metadata's six free builtins
create no state exception. Readonly administrator status grants no target,
method or historical access. Numeric, hash or object block input requires
administrator status in any mapped organization; contract administration alone
does not satisfy that floor.

A positive current Git read/admin grant makes no association SQL query and
cannot be vetoed by an earlier creation's different namespace. An explicit
selected organization cannot borrow another organization's ordinary Git grants.
An explicit preregistered address permits its selected owner organization's
deploy/admin claim to read before mining, without granting target
administration. An address-scope entry only identifies an owner. The nine
precompile addresses retain their static read exception after mapped-org,
method and source checks.

When Git grants no read, the optional `creationfacts.CurrentAddressReader`
can supply retained, positively qualified A2 creation associations.
`admissionsql.AddressReader` borrows the existing restricted facts-role pool
and independently selected network, generation, coverage, source-set and
reference bindings. One SELECT reads current readiness and the target's
original birth, authority reference, qualification and capture evidence in one
MVCC snapshot. Missing, revoked or inconsistent evidence rejects. An empty
projection means no positive association; it never means unregistered or
public. Each SQL pass has a lower-only 250 ms timeout, 64-candidate ceiling and
256 KiB candidate ceiling, with no transaction held across node, disk or socket
work. It introduces no SQL schema, role or policy setting.

A genuine matching WALLET actor grants plain reads and no administrative or
upgrade rights. It preserves the deployer exception with a different selected
mapped organization when the actor is also a current-owner member. FACTORY
associations identify a namespace and have no wallet actor. Without a current
Git owner, an unambiguous positive namespace can identify the owner and its
selected organization administrator can administer the target. Conflicting
dynamic owners, actors or births reject. The original capture's short validity
window describes admission-time evidence and never expires retained deployer
rights. Current readiness, generation, source, revocation and canonical
evidence are checked separately. Unknown accounts receive no general public
balance/nonce fallback from sparse creation evidence.

The association also retains the original observer head's number and hash
from that same SQL snapshot. After SQL recheck, the exact originally selected
StateClient checks that head by number on its own backend, validating and
recomputing the complete returned header's hash. A lagging observer cannot
continue granting an orphaned creation while that backend reports a different
canonical branch. Normal observer progress is allowed while the original
ancestor and target facts remain valid. This adds one physical RPC and at most
16 KiB of header result, with the client's lower-only timeout and earlier
original operation deadline. An A3-backed successful read therefore makes at
most four physical RPCs across acquisition and delivery; Git-only reads keep
their three-call acquisition. There is no retry or header-by-hash fallback.

This is a final sampled canonicality condition under the trusted-node boundary,
not an atomic statepoint, consensus verification, mining guarantee or protection
from a later reorg. One concrete StateClient endpoint must provide a logically
consistent backend; a load balancer across inconsistent nodes breaks that
assumption. It adds no historical namespace or state-root consumer.

A plain reader can read only the four existing infrastructure storage slots,
using their exact original full 32-byte spelling. Other slots require target
administration. A short numeric spelling is never padded into a permission.
Every raw `eth_getProof` requires target administration, including an empty
key list. This deliberately tightens V1 because proof nodes can embed data
beyond the requested slot. A conservative presence guard also requires a
nonempty account proof plus positive nonce, balance, code hash or storage root.
Both zero and canonical empty hashes count as empty, covering the observed
geth and Reth absence forms. Genuinely empty accounts may be rejected. This
typed trusted-node observation is not Merkle-proof or consensus verification.

The [recorded wrapper](v2-rpc-activity.md) shares one exact snapshot pointer,
recorder and HTTP limit across native, metadata and state engines. State retains
the original View and credential source, completes the real Pebble append once,
rechecks any original creation association, and checks the same original View
and context again after all SQL and node recheck I/O before protected output. It never refreshes
identity, retries an action or replaces the selected recorded outcome after
late delivery failure. Notifications settle once and return no body. State
envelopes are at most one MiB; the shared outer handler preserves native raw
transactions' two MiB limit and the shared sixteen MiB wire ceiling.
