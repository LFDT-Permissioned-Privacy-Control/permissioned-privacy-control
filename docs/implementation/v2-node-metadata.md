# Node metadata client

`rpcexecution.MetadataClient` parses bounded parameters and returns validated
metadata results. It reuses the existing RPC transport and header decoder. A
result is an observation, not an authorization decision. The caller selects an
approved source, authorizes the method before calling it, and checks the same
original request View before publishing protected bytes.

| Methods | Result |
| --- | --- |
| `eth_accounts` | Ordered node-managed addresses, including duplicates; addresses are normalized to lowercase. These are not the caller's linked wallets. |
| `eth_blockNumber` | Block height through `MaxInt64`. |
| `eth_chainId` | Full positive uint64 chain ID matching the configured network. |
| `eth_gasPrice`, `eth_maxPriorityFeePerGas` | uint256 fee quantities. |
| `eth_feeHistory` | Bounded actual fee arrays and ratios, including shorter or empty history. |
| `eth_syncing` | `false` or bounded quantity-valued progress telemetry. This does not establish that a node is caught up. |
| `net_listening`, `net_peerCount` | Boolean and full uint64 count respectively. |
| `net_version` | Decimal network ID, which can differ from the chain ID. |
| `web3_clientVersion` | Bounded client version string. |
| `web3_sha3` | Local Keccak256 of validated caller bytes, with zero node I/O. |

For remote methods, each query verifies the chain ID and hash-recomputed
genesis header using the selected credential. `eth_chainId` reuses its verified
result, for two physical RPC calls in total; the other remote methods use at
most three. The backend must support the header-only
`eth_getHeaderByNumber` operation. A local hash has only configured source
metadata and makes no live-network claim. Environment and deployment ID remain
approved operational inputs; deriving the network key does not prove them to a
node.

Queries share one five-second deadline, shortened by an earlier caller deadline.
There are no retries, redirects, credential changes or fallback sources. Counted
POSTs have `GetBody=nil`, including when the credential uses an idempotency
header. RPC errors and malformed responses return safe categories without node
messages or error data.

Default ceilings are 1 MiB minus 512 bytes of parameters, a 1 MiB outbound body,
an 8 MiB selected RPC response envelope, 4096 account entries, 1024 fee-history
blocks and 100 reward percentiles. Configuration can lower these ceilings. An
opaque query parsed with larger limits is checked again against the selected
client before work. Fee percentiles are finite, strictly increasing values from
0 through 100. A zero block count, omitted rewards, shorter actual ranges and
optional pre-fork fee fields retain their distinct meanings.

The two network checks add at most 20 KiB of response envelopes. Result parsing
bounds collections before appending entries, caps values and members at 120000,
and bounds logical decoded scalar text alongside the owned wire-result copy.
The public result getter makes a separate detached copy. JSON encoder buffers,
collection overhead, transport buffers and garbage-collector residency are
additional memory costs; these limits are not an RSS promise. The caller owns
HTTP concurrency, authentication, anonymous policy, recording and final output
delivery. This client provides no HTTP route or policy profile.
