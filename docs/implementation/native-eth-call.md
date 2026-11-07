# Native eth_call integration

`internal/rpcengine` provides a single-request POST handler for authenticated
`eth_call`. It builds its own request-view factory from the selected immutable
bundle, chooses the request organization and its exact method/credential grants,
then calls `rpcexecution` and the existing `policycore` evaluator. It has no SQL
directory, legacy server constructor or second `eth_call` forwarding path.

The explicit `catalog-runtime-call/v1` profile uses native-v2 source and requires
both hashed `identityCatalog` and `runtimeCatalog` files. The latter has version
`ops.runtime-policy/v1alpha1`, kind `RuntimePolicy`, `readProfile`, explicit
`intraOrgGrantTracing`, `sharedInfrastructure`, `addressScopes` and
`nodeEvidenceProfile: "geth-prague-call/v1"`. Shared entries have an address and
optional lowercase 32-byte code hash. Static scopes have an address and
organization ID. Required arrays, exact keys, non-null values, file/count/byte
budgets and inferred capability equality are checked by the shared compiler
used for preparation and pinned loads. Older profiles reject the extension.

Static scopes validate event-address constants. They never create a registered
contract, ABI, read association, runtime owner label or operational claim. Runtime
contract authority requires approved registry ownership and qualified nonempty
code. The native evaluator remains the sole target/selector/argument matcher.

Only exact `eth_call` is handled. Batches, notifications, aliases, custom methods,
client overrides, creation roots and unsupported transaction fields are rejected.
String, numeric and null IDs are retained without floating-point conversion.
The complete accepted call, including gas, fee, nonce and access-list fields, is
preserved. Any supplied `from`, including zero, must match an active actor-bound
wallet snapshot before node work. Omitted `from` means zero simulation context.
Neither case supplies a cryptographic signer; signer-dependent rules deny while
an independently matching rule can still permit a call.

The trusted node binding fixes the organization, chain, credential references
and finite Prague interval `[start, end)`. The transport never follows redirects
or guesses credentials. The adapter verifies chain ID, resolves the requested
header, and uses its exact hash for the mux trace and every follow-up code read.
Explicit historical selectors require true organization admin. Pending anchors
and timestamps outside the qualified interval are unsupported.

One mux executes `callTracer` with complete nested calls and logs, alongside
`prestateTracer` with code enabled, storage disabled, non-diff mode and
`includeEmpty: true`. A present account with omitted code is known empty; a
missing account requires a bounded code lookup at the same hash. Code hashes
alone are not enough to detect delegation designators. The Prague profile fixes
precompile addresses 1 through 17; later-fork anchors cannot reuse that set.
Node honesty and the supplied fork qualification remain trusted deployment
inputs; a profile label does not independently prove either.

The opaque acquisition owns normalized inputs, root-checked tree, anchor and
qualified code together. Every repeated or reverted frame retains its opcode,
depth, effective caller, storage context, calldata and value. Each group supplies
only its own operational mask, and only for proved registered storage in the
selected organization. Foreign code/storage, shared flags, implementation
ownership, read grants and admin flags cannot lend another group's authority.
Shared code-hash mismatches have no fallback.

After every applicable authorization check, the handler returns the root output
from that same trace. Canonical `execution reverted` returns code 3 and bounded
revert bytes; other execution errors return a generic -32000 failure. Inconsistent
revert metadata is invalid evidence. Denied calls receive no execution output or
node/policy reason. Expiry and cancellation are checked before result exposure.

Default engineering limits include a 1 MiB request, 16 MiB node response, 8 MiB
aggregate code, 256 anchored code lookups and one ten-second acquisition deadline
covering all node work. Admission checks the conservative frame/group/rule/sort/
linked-address work product before materialization and synchronous evaluation.
These limits are not throughput or hard realtime guarantees.

The call-only constructor/profile is an eth_call integration slice. It rejects CREATE, CREATE2, SELFDESTRUCT
and encountered EIP-7702 designators until their evidence is qualified. It does
not install production routes, provide broker/wallet storage, deliver send/Guard,
history or enterprise workflows, or establish complete runtime readiness. Final
assembly must provide global/concurrent backpressure before exposure. Existing
Guard wire, fingerprints and approval lifetime are unchanged.
The separately selected [raw-send profile](ops-v2-raw-send.md) preserves this
simulation behavior while adding its own signed admission and financial gates.

Run the scoped checks with:

```sh
go test -race ./internal/rpcengine ./internal/rpcexecution ./internal/nativeadmission ./internal/policybundle ./internal/policyprofiles ./internal/policycli
go test ./internal/archtest
```
