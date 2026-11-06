# Native execution evidence

`internal/executionfacts` parses a bounded, ordered Geth `callTracer` tree and
checks its root against independently normalized request inputs. It preserves
calldata, values, errors, caller/storage contexts, parentage and lifecycle
effects. It supplies evidence for a native policy consumer; parsing does not
authorize a request or prove that a node supplied complete, honest evidence.

The runtime selects one opaque profile: `GethCallTracerProfile()` for
`onlyTopCall=false, withLog=false`, or `GethCallTracerWithLogsProfile()` for the
existing signed-approval acquisition with `withLog=true`. The latter validates
and retains bounded logs as metadata, without granting native permission.
Existing Guard fingerprint configuration and bytes are unchanged. A consumer
must preserve the original prepared trace rather than issue an independent
replacement trace or reconstruct a tree from lossy call targets.

`Tree.Records()` returns detached copies. Delegate calls inherit EVM caller,
storage and value; their raw tracer `from` is retained separately. CALLCODE
retains its distinct opcode and explicit value, including under inherited
static status. Failed or caught frames remain in the tree.

`NominalCodeAddress` is the trace target, not proof of the executed code account.
For example, an EIP-7702 designator can redirect execution. A runtime must resolve
code provenance under its qualified node/fork profile, or reject unsupported
delegation before constructing native policy frames. Creation executes initcode,
not an assumed surviving deployed-code hash.

A failed creation may omit its destination. Its context remains explicitly
unknown and its nested frames remain present. An independently derived root
creation address can supply context, with that source recorded separately from
reported `to`. A runtime must resolve unknown execution contexts or reject them;
zero addresses and child-derived guesses are not recovery mechanisms.
SELFDESTRUCT remains a lifecycle/beneficiary effect, not a synthetic CALL or an
invented native policy opcode. Its runtime admission and fingerprint handling
require explicit support. These are compatibility requirements, not successful
deployment or lifecycle qualification claims.

`Tree.Outcome()` returns the detached root output, reported error and revert
reason from this same trace. Omitted Geth output means empty return data.
Disclosing that outcome requires every applicable policy and privacy check;
the accessor does not permit a second, unchecked execution or reveal a policy
denial's internal reason.

Initial budgets are 8 MiB raw JSON, 4,096 operations, depth 256, 1 MiB input per
operation, 4 MiB total input and 4 KiB per error/revert string. The log-bearing
profile also bounds logs to 4,096 and their total data to 1 MiB. Incremental
parsing rejects duplicate, unknown, null, malformed and oversized fields without
returning a partial tree. Smaller explicit budgets can be used by callers.
These limits are engineering caps, not throughput measurements.

Tests include actual, short Geth 1.14.11 traces captured with solc 0.8.35 targeting
Cancun, including static CALLCODE with nonzero value, caught failed creation and
LOG0. Their source and provenance are in `internal/executionfacts/testdata/`.
They establish those fixture semantics; they do not qualify other node versions,
producer enforcement or a complete OPS runtime. Production imports exclude the
policy compiler/VM, storage adapters and legacy server/RBAC packages.

Run `go test ./internal/executionfacts -race` and
`go test ./internal/archtest -run TestNativeExecutionEvidenceDependencyBoundary`.
