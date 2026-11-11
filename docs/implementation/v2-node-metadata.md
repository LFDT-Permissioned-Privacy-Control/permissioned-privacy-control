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
| `eth_syncing` | `false` or progress telemetry with three required uint256 quantities. The two optional warp counters may be null or uint256 quantities; optional `stages` may be null or up to 64 closed `name`/`block` entries, with nonempty UTF-8 names up to 128 bytes without ASCII controls and uint64 block quantities. Other bounded scalar quantity telemetry is allowed. This does not establish that a node is caught up. |
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

## Metadata permission engine

`rpcengine.NewMetadata` binds these twelve operations to an immutable
`RuntimeCreationObserved` snapshot. It creates no wallet, financial admission,
Guard or native execution resource. Startup checks every concrete client's
strong network, metadata source tag, credential reference and configured bounds.
Its clients map must contain exactly the organization/reference pairs selectable
by approved group grants for the six group-gated builtins and every metadata
alias. A raw org-free builtin grant creates no group-client requirement. An empty
selected reference still needs an explicit binding; it never falls back to the
default client's credentials.

The authenticated raw builtins `eth_blockNumber`, `eth_chainId`, `eth_gasPrice`,
`net_listening`, `net_version` and `web3_clientVersion` use the default client.
Their JWT must verify and remain live, but they need no mapped organization,
group grant or operational claim. Their activity organization remains empty even
on an organization-specific URL. The other six builtins and every alias require
an explicitly selected mapped organization, or exactly one mapped organization
when none is selected. They also require the exact raw-name grant, all declared
raw and canonical operational claims, and an unambiguous selected credential.
Group claims come from the approved bundle and source-qualified token mapping;
there is no Core user-directory or mutable KYC-row lookup.

Builtin spelling is case-insensitive without whitespace trimming. Operator
aliases are exact-case. Aliases cannot shadow a builtin, use a globally blocked
name, or start with `eth_`, `net_`, `web3_` or `engine_` in any case. An alias to
an org-free builtin still requires its own group grant and explicit client.
Only these closed typed metadata operations can dispatch; declaring another
method does not create passthrough behavior.

Anonymous access requires a separate approved `MetadataPolicy` document:

```json
{
  "apiVersion": "ops.rpc-metadata-policy/v1",
  "kind": "MetadataPolicy",
  "bundleManifestDigest": "sha256:<selected manifest's 64 lowercase hex digits>",
  "anonymousMethods": []
}
```

The array is required; an empty array grants nothing. It may list only canonical
metadata builtins, never aliases. Compilation checks an expected raw document
SHA, exact fields and bounds; the expected SHA alone does not prove Git approval.
Trusted startup assembly supplies the approved selection. The effective
permission digest includes the selected manifest, canonical policy and the
entire actual method catalog's names, targets and required claims. Changing a
method map without changing its version string still changes this digest.

Only an absent Authorization header can select this anonymous branch. A present
empty, malformed, duplicate or invalid bearer assertion is rejected. Anonymous
operations use the default client and carry no invented actor or organization.
An anonymous metadata policy grants no call, state or history access.

## Observed operation and wire bounds

The shared `rpcenvelope` parser preserves the legacy proxy parser API and adds a
bounded raw mode for metadata: one MiB, depth 32 and 120000 values, including
dropped metadata and unknown members. It preserves numeric ID precision and
omitted versus null values. Duplicate and ambiguous members, malformed Unicode
and malformed envelopes are rejected. Request `visibleTo`, `privateFor` and
unknown members cannot become metadata-client arguments.

The metadata wire accepts absent, null or `"2.0"` protocol versions. An invalid
envelope selects `-32600` with a null ID. For a valid envelope, unknown methods
select `-32601` and invalid typed parameters select `-32602` before identity
verification; authorization failure selects `-32001`, and node or recording
failure selects `-32002`. These errors have no node text or `error.data`.
A valid method-shaped envelope without an ID is a notification, including when
a later parameter, authorization or unknown-method check fails. It emits no body;
an explicit null ID receives a response.

The opaque operation retains the original verified runtime View, or a private
approved-anonymous branch, and a typed validated observation. The public
observation's detached result copy is created only after the actual recorder
append. A successful notification validates then drops its observation before
append. Owner, source, result type and size are preflighted without a result copy.
The original View is checked again immediately before protected output. Token
expiry during append withholds output without rewriting the selected completion
or rebuilding identity.

`rpcactivity` supplies the shared real recorder and output-lifetime limit. An
engine alone does not enable a production listener or provide durable recording.
The final response ceiling is sixteen MiB. The named worst-case request, result,
detached result and encoded response buffers total about 49 MiB per active
response; encoder work, transport buffers, View state and GC residency are
additional. The existing concurrency limit must be sized for deployment memory.
These limits do not establish an RSS, throughput or latency guarantee.
