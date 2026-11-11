# Mined client traces

`NewCreationObservedWithMinedTrace` adds `debug_traceTransaction` and approved
aliases to the CreationObserved engine. Other constructors keep their existing
method families. The request takes a nonzero transaction hash and optional
call-tracer configuration. OPS chooses the actual internal tracers; it does not
forward caller-supplied JavaScript, overrides, log capture or replay selectors.

The selected organization must grant the exact requested method and credential.
A request without an organization selects the sole mapped organization; multiple
mapped organizations require an explicit choice. An alias needs its own grant.
The original verified identity, policy revision and operation deadline remain in
force through recording and delivery.

## Visibility

With the `strict` read profile, the caller must currently own a linked wallet
matching the signed transaction sender or its noncreation recipient. OPS returns
only the root frame. A historical contract creation does not require a current
deploy rule for this root-only view. Current foreign ownership still blocks the
read; unknown CALL targets are not treated as public.

With the `standard` profile, a linked participant, current target-contract admin,
or recipient of the transaction's admitted `visibleTo` declaration may request a
trace. Each root and nested frame must also satisfy the current selected
organization's contract and function rules. This applies even when ordinary
intra-organization call tracing has a less restrictive setting. Visibility alone
does not grant private nested values: parent storage permissions control nested
input/value, and the frame's storage permissions control output/revert data.
These values also require the selected storage-read method. Logs are omitted.

Current approved Git permissions take priority. A dynamic creation association
must match the actual replayed runtime hash and length, and its birth must
precede the transaction. A birth in the same block needs the same block hash and
a strictly lower transaction index. These are current access permissions for a
historical read; they do not assert historical bank ownership.

## Source binding

OPS reconstructs the signed transaction using the history decoder, checks its
receipt and position in the block's hash list, recomputes the Ethereum header,
and checks that header by number on the selected node. Types 0–3 and unprotected
legacy transactions are supported by this purpose. Type 4, delegated execution
and blocks outside the approved Prague window are unavailable for native traces.
Ordinary history methods retain their separate capabilities.

One `debug_traceTransaction` request uses a fixed MUX containing `callTracer`,
`prestateTracer` and `flatCallTracer`. The flat child supplies the actual replay's
block hash, block number, transaction hash and index from the same inspector as
the other children. Every localized entry must explicitly match the selected
transaction position, including index zero; the first and sole root has an empty
trace path. Missing context fails closed. This prevents a replay from a transient
alternate inclusion being mislabeled with an earlier observed position.

The flat child is discarded after context validation. Only the call child is
projected. Code and account nonce evidence come from the actual transaction-index
prestate and the existing creation timeline. OPS never substitutes block-end,
parent or latest code/nonce queries. A required account missing from prestate
makes the operation unavailable.

These checks rely on a logically consistent trusted node. They do not verify a
Merkle inclusion proof or provide an atomic node-to-client snapshot.

## Limits and delivery

The operation has one earlier-parent deadline, at most 20 seconds; both source
stages share an earlier-parent acquisition deadline of at most 15 seconds. One
budget covers all source requests and final checks: at most 24 physical POSTs and
32 MiB of response envelopes, with no retries. MUX output is at most 16 MiB; the
call and flat children each have an 8 MiB ceiling. The flat child additionally
has at most 4096 entries and 256 path components. Existing native trace, code,
work and projection limits also apply. The extra context child adds bytes and
inspector work and can make a large trace unavailable within the same limits.

After projection, OPS retains the sanitized response and small original source
checkpoint, without the execution tree, code, signed input or raw MUX. It performs
one synchronous Recorder append before releasing protected output. It then
rechecks the original wallet version, any consumed admitted share and creation
associations; checks the original network and mined/observer headers on the same
client; and checks the original identity and deadline last. Revocation, reorg,
expiry or recording failure withholds the protected response.

A successful EVM-reverted trace remains a trace result object and is recorded as
an evaluation failure. Hidden transaction-specific failures use fixed public
errors. Notifications are recorded without a response body.
