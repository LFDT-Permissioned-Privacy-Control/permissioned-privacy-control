# Unsigned deployment simulation

`catalog-runtime-simulation/v1` selects runtime source
`ops.runtime-policy/v1alpha5` and unsigned evidence `geth-prague-simulation/v1`.
It uses the existing native policy/evaluator version 4 and the same temporal
execution engine described in [native lifecycle execution](native-lifecycle.md).
Prepare/load and the CLI select this profile explicitly; older source accessors
and constructors do not reinterpret it as their own version.

`rpcengine.NewSimulation` supports ordinary `eth_call`, unsigned root-deployment
`eth_call`, and the existing signed lifecycle submission modes. An absent or
JSON-null `to` selects deployment. A literal zero address, empty string or `0x`
does not select deployment and retains its rejection. The strict envelope,
fees/type/access-list/input aliases and override restrictions are unchanged.

An explicit `from`, including zero, requires the current actor's active proved
wallet before node work. Omitted `from` means the zero simulation account with
no wallet or cryptographic signer proof. Empty initcode needs an explicit native
create rule and that rule's own deploy/admin group claim.

## One organization and one anchored nonce

Deployment first selects the explicit mapped organization or the actor's only
mapped organization. An ambiguous selection denies before any node work. The
selected method permission, credential, wallet and historical-admin checks run
before acquisition.

The client selects one block header, then reads the sender's account nonce at
that exact block hash. It derives the expected CREATE address from that nonce.
The request's `nonce` stays unchanged in node input and is never used as address
proof; no state override is added. `FreshnessNonce` is also not an address source.
A present full-prestate sender must agree with the independent initial nonce;
an absent sender retains the owned initial nonce without a latest-state requery.

One trusted scope callback checks the derived address against the same captured
View before tracing. A registered foreign root denies, even if the actor also
belongs to that organization. The request never changes organization, node or
credential. A nil callback is invalid before node work; false produces only a
generic authorization denial. The RPC engine independently checks the acquired
root context again before native evaluation/output.

The root nonce query consumes one of the existing combined 256 code/count
lookups, with the same response bounds and total 10-second acquisition deadline.
It is not a separate budget. Ordinary CALL needs no extra nonce query. The
qualified mux tree, code timeline, group-specific rules, pins, rollback and SELF
checks remain the same implementation. Reported destinations and recovered
child contexts must agree with the independently derived root.

## Output and effects

Only output from that same fully authorized execution can return: constructor
output on success, bounded revert data for a real revert, or a sanitized generic
execution error. Current access and context cancellation are checked before
output. Supplying `from` never supplies a cryptographic signer to a rule.

Simulation creates no financial decision, record claim, origin/share/candidate,
Guard approval or broadcast. Signed CALL/CREATE on this catalog retains the
existing lifecycle signed/Guard evidence IDs, financial projection and receipt
ordering. The physical Guard format, fingerprint and TTL do not change.

The component does not implement estimation, access-list output, node-owned
send, other RPC methods, durable ownership or a complete mounted server. Those
protocols need their own consumers; `callTracer.gasUsed` is not an estimate.

```sh
go test -race ./internal/rpcexecution -run TestSimulation
go test ./internal/policybundle -run TestSimulation
go test ./internal/rpcengine -run 'TestSimulation|TestLifecycleActualRoot'
go test ./internal/archtest
```

HTTP tests use actual wallet proofs and PostgreSQL with bounded loopback node
and Guard fixtures. Production backend qualification must separately demonstrate
nonzero state nonce versus a different request nonce, no-to constructor output
and reverts, and complete mux/full-prestate behavior on the selected node.
