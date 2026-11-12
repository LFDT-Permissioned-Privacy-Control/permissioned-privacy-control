# Execution utilities

`RawOptions.Utilities` enables `eth_estimateGas`, `eth_createAccessList` and,
when `NodeSigning` is explicitly enabled, `eth_sendTransaction`. It composes with
the same CreationObserved engine and approved snapshot, including mined traces.
An omitted utility option keeps the previous method families. Each requested
method or alias requires its own current group grant and credential.

The caller has one original identity, policy revision and earlier-parent
operation deadline. An explicitly supplied `from` must be a currently linked
wallet. Historical input selectors require an administrator in an active mapped
organization. `pending` execution is unavailable; it is never replaced by latest.
All source executions use one captured block hash and selected credential.

## Gas estimation

OPS runs a bounded local search. Every actual gas probe produces genuine native
simulation evidence and must pass the current Go evaluator before the search
continues. A permitted high-gas execution cannot authorize a different branch at
an intermediate gas limit. The returned limit is one that actually succeeded;
it is not the root's gas-used value or a forwarded node estimate.

The upper limit respects the block limit, a supplied gas cap and available funds
when fees are supplied. The search stops within one percent of the successful
upper bound. It may be more conservative than a backend's estimator and does not
promise the globally smallest gas limit for contracts with nonmonotonic
`gasleft()` behavior. Failed or unqualified probes return fixed errors.

## Access lists

OPS derives a bounded conservative list from the first checked execution's
prestate account and storage touches. Current read rights determine which
addresses may be returned. Storage keys additionally require the storage-read
method and current target admin rights, except the existing four public
infrastructure slots. A call grant alone does not expose private storage keys.
Private entries are omitted rather than replaced with invented addresses.

OPS then actually executes the call again at the same hash with exactly that
filtered list and checks this second execution through the same evaluator. The
response's `gasUsed` comes from that second execution. The generated list is
usable and can contain extra entries; it is not promised to match a backend's
optimized list or to enumerate every touch of a gas-dependent second execution.
Extra entries can increase transaction gas cost.

## Node-owned signing

This capability requires a backend supporting side-effect-free
`eth_signTransaction` and the selected account. OPS checks the linked sender and
intent before asking for a signature. Missing nonce and fee defaults come from
the same bound node; missing gas uses the checked local search. Both Reth's raw
bytes response and geth's `{raw, tx}` response are supported. OPS independently
verifies the signed envelope against every filled field and never returns or
logs signed raw bytes.

The verified transaction then enters the existing signed-raw pipeline with the
same original identity, wallet proof and deadline: native policy, operational
admission/compliance, creation capture, and the configured Guard v1 or OPS
preflight mode all remain required. Broadcast is an ordinary raw submission with
an already known hash. OPS never falls back to an unchecked `eth_sendTransaction`
call. A backend supporting only that method does not qualify for this capability.
An uncertain broadcast is not automatically retried; its existing known-hash
outcome semantics apply.

## Delivery and bounds

Default simulation/search limits are 32 probes, 256 physical source requests and
128 MiB of response envelopes. Node-owned default reads and signing use a fixed
bounded number of calls; the subsequent signed-raw/Guard pipeline retains its
existing separate source limits. All stages share the original operation deadline. Existing per-trace,
code, rule-work, current-facts and response limits also apply. No retries run in
the source adapter. Only a projected response and small source checkpoint survive
into recording. The real Recorder append, original wallet/current-facts checks,
same-node network/header samples and final original identity/deadline checks gate
protected output. Node-owned sends retain the existing durable signed-raw effect
and delivery rules.
