# Signed transaction and retained Guard evidence

`transactioninput.DecodeRaw` verifies signed protected legacy, EIP-2930 and
EIP-1559 envelopes against an explicit positive chain ID. Its fixed input profile
rejects blob and set-code envelopes, unprotected transactions, invalid signatures,
noncanonical RLP and values wider than uint256. The default maximum is 512 KiB
before hex decoding. All returned bytes, numbers and access lists are detached.
Recovering an Ethereum signer identifies the signed transaction, not the OPS
actor who submits those bytes.

`guardbridge.NewPair` owns a preflight-only Guard service and its supplemental
node client. Both use the same copied startup node binding, selected credential
and trusted transport. Its profile is exactly `geth-prague-guard-retained/v1`,
with an explicit finite Prague timestamp interval. It reads no environment
configuration for node type or hash mode and does not create a delivery lane.
The Guard bridge accepts only protected legacy and EIP-1559 transactions, matching
the existing Guard preflight restriction.

`Pair.AcquireSigned` uses the original Guard call/prestate trace and header.
The service privately seals the originating service and approval binding;
another service's result or a changed exported approval cannot be substituted.
The returned opaque value retains its exact prepared approval request-locally.
It exposes no borrowed mutable prepared result. Acquisition and exact-anchor
code supplements share one default ten-second deadline.

The cross-package `TrustedGuardEvidence` DTO is trusted orchestration input.
Its exported fields do not prove a service origin or a valid approval. Pair
checks its private service seal before constructing the DTO; the execution
client independently checks the signed root, chain, header, profile, fork,
resource limits and complete execution evidence. HTTP requests and arbitrary
trace providers must never supply this DTO. The pure runtime packages do not
import the Guard service or its legacy trace projection.

The original `eth_getHeaderByNumber` request, nonce override, tracers,
fingerprints, wire domains, producer readiness and approval TTL remain intact.
Optional header number/time inspection never introduces an old preflight error:
absent, malformed, repeated or oversized quantities make retained evidence
unavailable. Explicit `0x0` is present. The optional inspector copies at most
20 bytes per quantity. A new native qualifier refuses unavailable evidence.
The existing Besu result does not supply this qualified header and cannot be
used through this bridge.

New retention first limits the original mux envelope to 32 MiB, then each raw
call/prestate subtree to 16 MiB with duplicate-aware closed parsing. Original
subtree bytes and number spellings are preserved. These limits bound additional
retention; they do not add a bound to the legacy RPC response acquisition.
Approval queues continue to hold the original compact approval only.

The retained Guard prestate profile includes storage because the original
tracer enables it. Storage is checked and discarded for code classification,
with at most 4,096 slots per account and 65,536 overall. Keys and values must
be exact 32-byte hex words; semantic duplicates, including changes in hex case,
are rejected. The call-only profile continues to reject storage. A present
account with omitted code is known empty under the owned code-enabled profile;
an absent account needs a bounded code lookup at the original header hash.

Signed evidence remains distinct from a simulation. The existing call-only
acquisition, catalog and native admission engine reject the signed retained
scope. This library creates no accepting send profile, HTTP route, broadcast,
approval renewal, wallet link, SQL write or permission. Creation, lifecycle and
delegation-designator evidence is explicitly unsupported by this profile.
