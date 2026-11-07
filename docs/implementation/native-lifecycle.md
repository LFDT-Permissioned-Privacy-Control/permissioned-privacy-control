# Native lifecycle execution

`catalog-runtime-lifecycle/v1` selects native policy
`privacy.gateway.fm/v1alpha4`, evaluator `policycore/native-v1alpha4` and runtime
source `ops.runtime-policy/v1alpha4`. The shared prepare/load compiler and CLI
select it explicitly. Existing profiles and the optional EVM backend reject
this version. It is a bounded RPC component, not a complete server assembly.

`rpcengine.NewLifecycle` mounts ordinary `eth_call` simulations and signed raw
CALL or CREATE in either approved `ops-preflight` or `guard-v1` mode. The root
organisation still selects one node, credential, anchor and financial context.
Nested organisations never trigger another execution or change that context.
Unsigned root deployment, other RPC methods, durable deployment ownership and
historical privacy consumers are outside this component.

## Code at the time of each frame

Acquisition owns one complete tree and a sparse per-address timeline. Constructor
`FrameCode` is attempted initcode; the account's `RuntimeCodeAt` is empty while
the constructor runs. Successful output becomes runtime only when that frame
returns. An empty installation retains nonce 1. A successful child remains
visible inside its parent even when that parent eventually reverts; changes
are undone at the failed parent's exit.

`CodeInfo.FreshnessNonce` exposes initial same-execution nonce evidence or a
fresh account's reservation 1 for zero-versus-nonzero freshness checks. It does
not interpret later creator increments or report an exact nonce at every frame,
and must not be used to derive creation addresses.

SELFDESTRUCT does not clear code or nonce during the transaction. Eligible
same-transaction deletion is a final survival annotation. Marks roll back with
failed ancestors; existing contracts retain their runtime. The reported value
is a source-balance observation, not proof that money moved or code was deleted.

A failed creation without `to` can recover context only from unanimous original
`from` values of its immediate children. The original missing `to` stays missing.
A childless failed attempt remains unresolved; no zero address or account epoch
is invented. A signed root CREATE independently derives its destination from
the recovered signer and signed nonce.

## Permissions for creation and temporary contexts

V4 `targetClass: create` requires selector `*`, explicit `create`/`create2`
call types, and the matching group's own source deploy/admin claim. It can
authorize an empty-initcode attempt. A known registered destination keeps its
organisation even if the creator belongs elsewhere. An unresolved attempt
cannot match an address or deployment-context rule.

`targetClass: deployment-context` requires explicit call types and the matching
group's own deploy/admin claim. Omitted `codeAddress` means code and storage are
the same address. Borrowing code requires its exact approved `codeAddress`.
Registered foreign code requires membership and, when configured, contract
association. Code created in this execution requires its independently
authorized creation; a foreign namespace also requires membership in that
namespace. Unrelated unregistered runtime grants nothing. These temporary
namespaces never replace registry ownership or supply ordinary admin masks.

Ordinary literal/org rules require positive runtime at their storage address.
Deployment-context upgrades additionally require explicit `allowUpgrade`, the
same group's upgrade/admin claim, and a positive-runtime implementation in the
same organisation or execution namespace. Another group's claims cannot help.
Genuine fixed Prague precompiles can be explicitly borrowed; binary precompile
input and constructor initcode are not inspected as contract upgrade calldata.
Precompile upgrade grants reject during compilation.

Shared-runtime code pins remain strict, and shared-code delegation always
denies. A future runtime pin is skipped only for positively known empty runtime
at the exact active constructor epoch: CALL-self, or nonexecuting constructor
storage borrowing positively qualified private code. The explicit context rule
and its own deploy claim remain required. Borrowed code's pin and access checks
still apply. Unknown/other empty accounts and post-constructor empty runtime
receive no exemption. SELFDESTRUCT beneficiaries always use strict pin-first
validation, followed by shared/precompile, registered association, actual
execution namespace, or genuinely unregistered empty-account checks.

## Financial and Guard boundaries

Signed root CREATE uses the same Checker and read-only preview as CALL. Its
financial destination is independently derived and its financial calldata is
`0x`, so transfer-shaped initcode cannot become an ERC20 transfer. Native value,
signer and transaction hash remain unchanged. Nonempty `visibleTo` rejects
before recipient or node work. The same record claim, strict audit, known
COMMIT receipt and final live checks precede any queue or broadcast effect.

The Guard pair retains the original sealed Prepared, physical retained-evidence
profile, fingerprint, approval bytes, hash modes and TTL. New lifecycle consumer
profiles describe independently qualified evidence; they do not rewrite the
physical Guard format. A failure before COMMIT queues and broadcasts nothing.
An ambiguous result after the first external effect remains outcome unknown.

New and old evidence-profile rows use the existing SQL TEXT columns and
canonical readers/recovery checks. Safe bundle rollback uses the new binary
with an older approved bundle. An older binary does not understand lifecycle
row profiles and can fail unready when reading them; old-image rollback is not
qualified. Retained facts are never deleted or rewritten to make an old image
accept them.

## Bounds and verification

The new acquisition profiles cap traces at 4096 records/depth 256, raw trees
8 MiB, mux 16 MiB, input 1 MiB/aggregate 4 MiB, and 8192 prestate accounts.
Anchored and every retained created-runtime version share an 8 MiB code budget,
with 1 MiB per account and 8 MiB aggregate CREATE output. Code/count supplements
share 256 queries against the same block hash and one 10-second deadline.

Sparse forward/undo transitions are capped at eight per record. The immutable
precomputed qualification bound is
`N + T + 16*N*(1 + ceilLog2(1+T))`; it joins all mapped native and association
work under the existing 2,000,000 limit before materialization. Native passes
cache at most six indexed fact queries per record; matching performs none.

```sh
go test ./internal/policycore ./internal/executionfacts ./internal/rpcexecution
go test ./internal/policybundle ./internal/policyprofiles ./internal/policycli
go test ./internal/rpcengine -run TestLifecycle
go test ./internal/policybackend/evm -run TestAllBackendEntryPointsReject
go test ./internal/archtest
```

RPC tests mount actual handlers, wallet proofs and PostgreSQL with loopback node
and producer protocol fixtures. They qualify component semantics and ordering,
not a production node backend or complete deployment. Creation observations and
admission origins do not establish durable ownership or historical visibility.
