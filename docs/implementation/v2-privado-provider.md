# V2 Privado proof provider

`internal/identitybroker/privado` verifies real AuthV2 holder proofs and required
`credentialAtomicQuerySigV2` predicates through the pinned iden3 SDK. Its output
is an opaque, expiring `VerifiedProof`. The package issues no OPS token and
opens no database. The existing Azure broker/source/family and HTTP contracts
remain closed to Privado until deliberately composed with this provider.

## Explicit startup trust

`New(Options)` receives an immutable `identity.Catalog`, selected profile IDs,
trusted network bindings, pinned JSON-LD documents, a clock and an optional
caller-owned transport. It accepts at most 64 selected Privado identity/role
profiles, eight required networks and sixteen predicates per role profile.
Unknown, duplicate, missing or conflicting selections reject at startup.
Every verifier ID must parse and round-trip as a canonical DID. Holder and
credential-issuer DIDs use the existing typed iden3 primitives; no identifier or
membership row is created.

Each network binding supplies the exact HTTPS RPC endpoint, expected positive
chain ID and state-contract address. The holder profile's state-contract
address must match. Every declared issuer network must have a binding too.
These are trusted startup inputs: the pure identity catalog does not itself
prove that arbitrary endpoint/secret options came from approved files. Runtime
composition must establish that provenance.

Optional `CredentialBinding{RefID,Header,Value}` is supplied by trusted assembly.
The provider reads no environment variables. It copies and validates the
resolved value, uses it only at the bound endpoint, and exposes neither it nor
its hash/length in metadata. Public metadata binds the catalog, selected public
profiles, document hashes and public network/credential-reference plan.
Changing resolved secret material alone does not change that public digest.

Pinned documents are limited to sixteen entries, 1 MiB each and 2 MiB total.
A role profile's exact context URL and SHA-256 must match supplied bytes. The
loader returns a fresh decoded document per lookup and has no filesystem,
HTTP, IPFS or global-loader fallback. Dependencies must be supplied explicitly.
It does not derive facts from presentation metadata or DID documents.

## Saved request and proof authority

`CreateRequest(RequestContext)` constructs one exact SDK authorization request.
The caller generates a fresh canonical request UUID and 32 unpredictable bytes,
then saves their context with its real recipient/pending-state protection.
Creation and expiry are floored to integral UTC seconds; expiry must remain
strictly live, ordered and at most 300 seconds after creation. The signed
message contains a versioned domain, request ID and nonce. Identity-only scope
is empty. Role scope requires every configured predicate, exact issuer/context/
type/equality query, SigV2 circuit and revocation checking.
The wallet accept profile advertises only Groth16/AuthV2 using the protocol's
singular `circuitId=authV2` parameter, checked with the pinned SDK parser.

The canonical scope JSON is capped at 32 KiB at startup. Another 32 KiB covers
the envelope: callback at most 2048 ASCII bytes, verifier DID at most 1024,
their worst-case JSON escaping, fixed UUID/message/headers and bounded times.
The exact final `AuthorizationJSON` is also checked against 64 KiB. Oversized
selected profiles reject before transport/proof construction; issuers and
required predicates are never truncated. This bounds the canonical protocol
bytes, not the future operational store's entire encrypted row or an outer
JSON serialization that base64-encodes byte fields.

Callback URL is trusted saved context: canonical HTTPS, no userinfo/fragment,
with a bounded public correlation query permitted. It is never fetched by this
provider. The integrating broker must bind its exact approved origin, route
and query shape, excluding recipient/completion secrets and provider tokens.

`Request` is serializable, detached operational input, **not proof by Go type**.
`Verify` reconstructs the same request from current selected source, profile
digest and public plans and compares the complete canonical bytes/context.
The caller restoring it must authenticate its real pending record, source and
recipient binding. The library has no request-consumption registry: enforcing
one use and committed completion belongs to that operational protocol. A proof
for an older/different request cannot satisfy the new unpredictable message.
Renewal additionally requires exact verified ActorID equality with the actor
saved in the authenticated renewal context.

Errors return no evidence. Busy, transport and cancellation failures are
separate from invalid/expired evidence. The provider consumes no pending record
and revokes no session itself; the integrating operational protocol owns those
effects and must not treat an unavailable state endpoint as a successful check.
The generated getter boundary retains generic RPC and malformed ABI failures as
provider unavailability even when the SDK wraps them. Its known missing-state
errors still use the unchanged SDK genesis/invalid-evidence rules.

## Real verifier and bounds

Each attempt has its own SDK verifier, request maps and resolver context. The
default package manager is replaced with an empty manager before registering
only AuthV2. No JWS, plain envelope, AuthV3 or alternative circuit fallback is
registered. Verification uses the original compact bytes and embedded keys;
the strict parser is a structural guard, never a second proof verifier.
The inner body's optional `typ` may carry exactly the ZKP or plain protocol
label: the standard ZKP packer preserves that body label. It never replaces the
mandatory protected outer ZKP/AuthV2 envelope or selects a plain verifier path.

Compact JWZ is limited to 1 MiB: decoded header 2 KiB, authorization payload
512 KiB and outer proof 16 KiB. The exact outer header requires Groth16,
AuthV2, ZKP media type and the known circuit critical-header declaration.
Closed envelope/body/scope/proof fields reject duplicates, case aliases and
unknown authority fields before SDK assertions. Depth is at most sixteen,
nodes 8192, object members 64, arrays 128 and general strings 8 KiB. Known
proof shapes are narrower: three AuthV2 signals, 77 SigV2 signals and bounded
canonical field coordinates. Ignored attachments/DID documents/presentations
have separate byte caps and cannot add facts or undeclared fetches.

Four immediate admission slots cover the entire attempt, including structural
parsing and big integers. The original caller context and a twenty-second
operation deadline reach every state call, including the SDK packer's current
use of `Background`. Each owned HTTP call also has a three-second timeout.
Synchronous Groth16 CPU work has no cancellation interface: cancellation gates
I/O and publication; it does not claim to interrupt a primitive mid-call.

State resolution reuses SDK `state.Resolve` and `ResolveGlobalRoot` over the
standard generated contract getters. Historical issuer signing/auth state
retains standard known-state validity, so unrelated subsequent issuance does
not force reissuance of a valid credential. Holder GIST and required issuer
nonrevocation state must be latest in this selected profile. Replaced states
reject even if their transition timestamp lies in the future. A bounded index
of the parsed public-signal lookup roles restricts resolver calls; those
unverified routing values cannot produce evidence without unchanged real
`FullVerify`. A pair used for both auth and nonrev must satisfy currentness.

Every used network gets one chain-ID check within that attempt. The transport
allows only nonbatch `eth_chainId`, the two exact state getter selectors at
the bound contract and `latest`, and one conditional same-contract `getCode`
after an empty call result. Limits include physical generated-binding calls:
eight chain checks plus 33 getter calls, with one terminal empty-result code
fallback, at most 42 requests. Counters/deadline are shared across networks and
never reset on a failure. Bodies are bounded before decoding. Transparent
replay of a sent counted POST is disabled, including when a
credential uses an `Idempotency-Key` header. Redirects and
ambient proxies are disabled. Default strict/explicit relaxed egress uses the
existing `netguard` semantics, including its relaxed loopback behavior. A
caller-owned transport remains trusted infrastructure with its own TLS/dial
responsibility; the provider still enforces endpoint/method/body/count bounds.

Role timestamps must lie within the challenge window, explicit thirty-second
clock tolerance and original 300-second age limit. `ClaimsAsOf` retains the
oldest relevant proof/challenge time; `SourceVerifiedAt` does not reset it.
`NotAfter` is the earlier of request expiry and that original age cutoff.
SigV2 proves credential validity at its proof timestamp; it does not expose an
arbitrary hidden credential expiration date. That cutoff must not be described
as an extracted credential expiry. Identity-only proof produces zero grant
facts; role facts are only configured predicate IDs after all required proofs
and state checks succeed. Consumers must call `RequireCurrent` before issuing
or publishing credentials. `Provider.RequireProof` additionally checks that a
result came from that same selected provider instance; equal public metadata
alone does not identify its resolved secrets or trusted transport.

## Qualification and build

The scoped tests use actual TLS, typed ABI replies, the actual SDK state
algorithm and real Groth16 verification. An old public SigV2 numeric fixture
from pinned SDK `TestVerifyMessageWithSigProof_NonMerkalized` verifies as a
crypto primitive while its original timestamp is rejected by the production
freshness gate. It is not a fresh role-provider positive.

`OPS_PRIVADO_FRESH_PROOF=1` enables one short native AuthV2 functional test using
the existing Makefile-pinned public artifacts. It creates a new in-memory test
identity from exactly 32 bytes each `0x42`; no user's identity/seed is read.
There is no artifact download or benchmark. This validates the concrete provider
with a newly generated proof and owned TLS state server. It does not qualify a
real wallet application's UI, network deployment or role credential workflow.

The pinned SDK lexically imports proving/witness utilities. Production builds
can select `-tags=prover_disabled` with `CGO_ENABLED=0` to disable its unused
native C prover while retaining the same real Go Groth16 verifier. The tagged
test accepts an explicitly labelled public fixture from the native fresh test
and verifies that same still-fresh proof through the concrete provider/TLS path.
No success stub replaces proof verification. The provider boundary excludes
SQL drivers, legacy session infrastructure and EVM/state/rawdb packages;
standard SQL value-conversion helpers in Ethereum primitive types are harmless.

Actual recipient-bound operational challenges, wallet callback/completion,
fresh proof renewal, SQL recovery/consumption, HTTP/helper and issuer composition
require integration. Fresh SigV2 credentials and a real supported wallet's
five-minute renewal flow remain explicit qualification requirements. This
library alone is not a delivered Privado login or complete V2 release.
