# Native multi-organisation CALL authorization

`catalog-runtime-multi-org/v1` selects native policy version
`privacy.gateway.fm/v1alpha3` and runtime source `ops.runtime-policy/v1alpha3`.
The shared checker, prepare/load compiler and CLI select this profile explicitly.
Existing source versions, constructors and the optional EVM backend do not accept
the new version.

`rpcengine.NewMultiOrg` mounts `eth_call` and raw submission in either approved
`guard-v1` or `ops-preflight` mode. It uses the same acquisition, wallet,
financial-transaction, approval-delivery and broadcast boundaries as the bounded
raw consumer. This component does not implement other RPC methods, CREATE or
SELFDESTRUCT, historical privacy filters, identity renewal or server assembly.

The selected root organisation determines the node binding, credential,
acquisition anchor and financial context. Nested calls do not switch them.
Each private CALL or STATICCALL uses its registered owner's native program and
the actor's groups in that organisation. A qualified shared nested target uses
its parent's authority. A registered shared root still selects its registered
owner. Caught and reverted frames remain part of the complete decision.

DELEGATECALL and CALLCODE use the storage owner's program. Borrowing private
code from another organisation requires an explicit literal storage/code pair,
membership in the code owner's organisation, and current contract association
when `intraOrgGrantTracing` is enabled. A mapped ReadGrant with mode `none` can
establish this association but permits no events. The storage owner's literal
rule decides the selector and arguments against the separately referenced code
ABI. An `org` wildcard cannot borrow foreign code; shared-code delegation denies.
There is one native matcher, with each frame routed to its owning program.

Registry isolation survives empty runtime code: a registered address cannot be
reclassified as an unregistered EOA. Operational masks and upgrade destinations
still require actual qualified runtime code. An empty registered account gains
neither literal-contract nor org-wildcard execution authority. Each frame receives
only its
authority organisation's group masks, qualified for its storage; another
organisation's admin or upgrade claims cannot supply them. The root anchor never
becomes a substitute for the nested frame's authority organisation.

The trusted runtime supplies `Frame.CodeAccessible`; it is not a policy or RPC
field. Separate ABI references carry no membership, grant or storage ownership.
The complete mapped-group/rule/wallet work and distinct foreign-code association
scans share the admission work limit. Repeated targets reuse one request-local
association result. No partial response is released after a denial or expiry.

The first v3 runtime schema includes optional `priceFeed`. Omission selects no
feed; explicit null and an unused plan reject. The compiler calls the shared
pure normalizer once, then builds the request plan once against the same approved
compliance catalog. The runtime catalog exposes immutable Definition/Plan values
and source, plan and compliance digests. Its semantic digest includes the
normalized feed definition, and requirements include the exact credential ref.
The loader resolves no secrets and starts no HTTP provider. Assembly must use
these same values when constructing the feed and financial service.

The legacy importer/converter is unchanged. It does not invent cross-org proxy
relationships or add literal grants. Source authors must explicitly approve
those rules. Exact-selector rules pin the executing ABI; wildcard and empty
rules retain their explicit semantics without argument decoding.

Focused verification:

```sh
go test ./internal/policycore ./internal/policybundle ./internal/runtimepolicy
go test ./internal/rpcengine -run 'TestMultiOrg|TestRegisteredEmpty'
go test ./internal/policybackend/evm -run TestAllBackendEntryPointsReject
go test ./internal/archtest
```

The RPC tests use owned local PostgreSQL instances and loopback node/producer
protocol fixtures. They check actual handler/native/financial ordering and do
not qualify a production node backend or a complete v2 deployment.
