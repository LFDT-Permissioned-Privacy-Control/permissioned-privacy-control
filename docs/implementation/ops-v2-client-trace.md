# Simulated client traces

The CreationObserved engine serves `debug_traceCall` through a concrete owned
result and the synchronous RPC Recorder. An approved group must actually assign
a trace method to enable this family. The audited service requires every
supported trace method and alias in the Recorder's method set. The existing
call/raw operation binding stays separate.

The request uses the selected organization's exact raw method grant and
credential. An `eth_call` grant does not grant tracing; a target method grant
does not grant its alias. Builtin spelling is normalized, while custom aliases
retain their exact names. Unlinked supplied senders are refused. Historical
selectors require an organization-admin group in at least one current mapped
organization, together with all selected-organization rights. Contract admin
and readonly-admin do not satisfy that historical floor.

V1's canonical call contains only `from`, `to`, `data` and `value`. The `input`
alias must agree with `data`. Empty or null destinations mean creation;
quantities and hex addresses are normalized before acquisition. Gas, fees and
other unknown call fields are ignored. Caller trace configuration is never
forwarded. Arbitrary tracers, logs, state/block overrides, positional replay
and ambiguous keys are refused. Harmless unknown configuration is ignored.
Pending simulation is unsupported and is never replaced with latest.

One actual native mux acquisition supplies both permission checks and the
returned call tree. The original unsigned callTracer child is retained during
acquisition; its accessor copies only that child. It does not reparse or copy
prestate. The existing native matcher evaluates the actual selectors,
arguments and lifecycle rules. Client tracing additionally requires current
read association for every relevant owned storage target, regardless of the
ordinary intra-organization tracing setting, and stays in one selected
organization. Delegated implementation ownership is checked separately from
the storage grant. Registered creation destinations require association;
unregistered freshly created code receives no automatic client trace grant
for later calls. Ordinary call/raw creation behavior is unchanged.

The existing strict tracer projection and redactor return only call-frame
fields. Native evidence rejects unsupported shapes before projection; logs and
private mux data never appear in the result. The top frame's values remain.
Nested input and value belong to the parent's storage context; nested output
and revert reason belong to the frame's own storage context. Reading those
values requires the selected `eth_getStorageAt` method and current contract
read-admin permission. Plain wallet association and readonly-admin supply no
private-storage bypass. Hidden fields use fixed marker pairs independent of
their presence or size. A root EVM revert remains a trace object, with an
evaluation-failed completion rather than an eth_call-style RPC revert error.

The original operation deadline is at most twenty seconds, clipped by the
parent. Native acquisition, current facts, wallet and output budgets remain
bounded. The raw mux is at most 16 MiB and the retained unsigned child at most
8 MiB before projection; these are separate from existing tree/code budgets.
The whole public response is bounded by 16 MiB, including its original raw ID.
Escaped text and redaction framing are checked before whole-output allocation.
These are logical byte bounds, not a process-memory guarantee.

Only the redacted result and small original authority/source metadata survive
the actual synchronous Recorder append. A wallet snapshot required by the
sender or selected program is reloaded by its original version, followed by
all original A3 checks. The original selected client then samples its full
network and required numeric observer/execution headers. The same original
View and context are checked last. Append failure, expiry, unlink or a source
change withholds the entire trace. There is no background replacement append,
second trace, node retry or source query inside a financial transaction.
