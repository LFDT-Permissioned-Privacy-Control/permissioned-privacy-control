# Native raw-transaction admission

`rpcengine.NewRaw` provides authenticated `eth_call` and
`eth_sendRawTransaction` handlers over one selected immutable policy bundle.
These library handlers are not mounted by the legacy server. They require
server-level connection limits, backpressure and verified node/network binding
when assembled into a service.

The explicit `catalog-runtime-raw-send/v1` profile requires identity, runtime
and compliance global files. It uses native execution policies at
`policycore/native-v1alpha2`. It rejects disclosure globals and unsupported
creation, lifecycle and delegation-designator evidence. This bounded profile
does not represent the complete release feature set.

The runtime file has this closed shape:

```json
{
  "apiVersion": "ops.runtime-policy/v1alpha2",
  "kind": "RuntimePolicy",
  "readProfile": "standard",
  "intraOrgGrantTracing": true,
  "sharedInfrastructure": [],
  "addressScopes": [],
  "nodeEvidenceProfile": "geth-prague-call/v1",
  "rawSubmissionMode": "ops-preflight"
}
```

`rawSubmissionMode` selects either `ops-preflight` or `guard-v1`. A request
cannot choose a mode, node, credential or evidence provider. The older runtime
source and call-only profile retain their previous meanings and reject this
new source. `RuntimeCatalog.Source()` returns only v1 source, and returns zero
for a v2 catalog; callers inspect `RawSource()` explicitly to retain its mode.
The shared prepare/load compiler derives and checks all required capabilities.

`NewRaw` compares the selected manifest and compliance digests, network,
evidence mode and wallet resolver namespace/recovery state before constructing
its source-derived raw bindings. The service origin, environment, chain,
genesis and deployment must describe the same trusted assembly. These checks
do not independently prove the remote endpoint's genesis: assembly must verify
that node against its configured network.

Raw transport retains the `eth_sendTransaction` method classification. A
`eth_sendRawTransaction` grant alone grants no handler access. Native rules remain
mandatory, including for organisation admins. Only the selected organisation's
groups permitting the classified method select its credential; conflicting
references deny. Call credentials are selected independently.

The raw path performs these steps:

1. Parse a single strict JSON-RPC request and verify its current OPS access
   token, organisation, classified method and credential.
2. Capture one bounded snapshot of the actor's user-proved wallet associations
   and resolve any sharing recipients. A successful empty snapshot permits
   policy-authorised relaying; store failure does not use stale associations.
3. Acquire complete anchored execution evidence for the exact signed bytes.
   Run the same native materializer and evaluator over every observed frame,
   including caught or reverted descendants.
4. Call the actual atomic admission service with that same view, transaction,
   execution, wallet capture and audience. Its financial audit, claim and
   applicable origin/share effects commit together. Its receipt proves this
   operational commit; it does not replace native policy authorization.
5. Match the process-local receipt and check its publication gate. In Guard
   mode, enqueue the untouched approval from the exact originating Pair.
   Enqueue refusal prevents broadcast. Then broadcast the signed transaction
   once through that same selected node credential.

OPS preflight supports protected transaction types 0, 1 and 2. It traces at one
captured header hash with all signed gas, fee, access-list and nonce fields,
overriding only the sender nonce with its signed value. Guard mode supports
the retained protected type 0/2 contract and original hash modes 0/3. It uses
the original Guard preflight snapshot and unchanged producer wire, batching,
TTL and retention. There is no readiness fallback to OPS preflight and no
approval acknowledgement wait. A root revert does not skip native checks; an
otherwise permitted signed transaction may still fail on chain.

Simulation never obtains the signed-transaction signer from a supplied `from`.
Its explicit-from association check remains in place. For a signed request,
the recovered signer is available to signer predicates; actor-linked predicates
still require that actor's captured user-proved association. Signed bytes alone
do not prove actor ownership, authorship or an exclusive wallet association.

The accepted sharing fields are top-level `visibleTo`, top-level `privateFor`
and `params[1].visibleTo`. Standard mode requires arrays of canonical ActorIDs
or exact Ethereum addresses. It bounds the combined raw count at 32 before
lookup or deduplication, rejects ambiguous address mappings and freezes sorted
ActorIDs. `params[1].privateFor` is unsupported. Strict mode refuses any accepted
field's presence, including null or an empty array, before wallet/node/SQL work.
Malformed legacy metadata is rejected rather than silently dropped.

Nonempty sharing requires a user-proved signer association, nonempty calldata
and anchored root runtime code. It does not require source registration or
promise an emitted log. The first nonempty qualified global share remains
immutable; an earlier empty attempt reserves no recipient list. A share/origin
row alone does not authorize arbitrary logs or historical data. Historical
visibility additionally needs its contract/read filters and qualified canonical
inclusion strictly after the captured admission anchor. Operational SQL writers,
restore operators and the trusted node/orchestrator remain part of the trust
boundary.

Only an exact returned transaction hash matching the signed bytes is success.
After an approval queue accepts work or raw broadcast starts, every other node,
transport, cancellation or malformed-response outcome is
`-32004 submission outcome unknown`, with the verified `transactionHash` in
error data. The caller can reconcile that hash. No background task automatically
resubmits it. A known queue refusal is `-32002` and sends no transaction. Raw
checker, node, tracer and SQL reasons are not returned.

Acquisition has one 10-second deadline. Ordinary evidence retains its existing
trace/code budgets; new bound Guard delivery caps each HTTP response at 34 MiB
before RPC decoding, then applies the original retained-evidence limits.
Broadcast has a 5-second deadline and a 1-MiB response cap. Raw HTTP bodies are
at most 2 MiB with signed bytes at most 512 KiB; calls retain their 1-MiB limit.
Startup allows at most 8 raw credential references per organisation, 64 selected
raw bindings, 256 producer lanes and 1,000,000 retained approvals in aggregate.
These are engineering bounds, not throughput or availability guarantees.

Each delivery Pair owns unregistered existing Guard metrics. Assembly must use
unique bounded pair/organisation labels or aggregation before registering them;
registering identical collectors directly would collide. Closing the raw engine
refuses new admissions and drains already accepted Guard work under the existing
per-service limits.
