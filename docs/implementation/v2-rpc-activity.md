# Recorded RPC operations

`internal/operational/rpcactivity` wraps the native RPC engine and the durable
activity recorder. It supports `eth_call`, `eth_sendRawTransaction` and the
optional twelve-operation [metadata engine](v2-node-metadata.md) on the
`RuntimeCreationObserved` profile. It is a library: it does not mount a production
listener or replace the other authentication and operational HTTP handlers.
Existing direct engine constructors, methods and HTTP adapters keep their
behavior; they do not acquire activity recording merely because this package
exists.

`New` checks the concrete engine's accepted network key against both the
configured strong network and the recorder. Environment and chain ID alone are
insufficient: genesis and deployment also contribute to the key. This is a
configuration binding, not an independent probe of the connected node. Actual
node/network qualification belongs to the assembly that activates a listener.
The recorder must contain the configured engines' approved method labels and the
two fixed invalid labels, and have a healthy, qualified source. A handler accepts a configured organization ID or empty
organization inference. Per-request membership and permission still come only
from the original accepted runtime View.

`Config.Metadata` can be used by itself without constructing native admission,
wallet or Guard resources. Supplying both engines requires the very same
snapshot pointer as well as matching network, profile, manifest and organization
metadata. An equal manifest string cannot disguise different method maps.
Both engines and every mounted alias share one recorder and one HTTP limit.
The native-only constructor path retains its existing behavior.

## Operation and delivery

Every handler alias from one service shares an immediate HTTP limit derived
from the existing recorder's `InFlight` value. There is no second numeric
concurrency setting or waiting queue. One service owns the supported aliases for
one recorder/network; creating several services is not a way to multiply this
bound. The final assembly must enforce that topology.

The handler establishes real read/write deadlines, capped at twenty seconds or
the earlier parent deadline. A ResponseWriter wrapper must support `Unwrap`.
Unsupported deadline control rejects before reading the body or doing node work.
The handler reserves recorder capacity before parsing, identity, node acquisition,
financial admission, Guard enqueue or broadcast. Capacity rejection performs no
business action and has no fabricated completion row.

The engine executes once and returns an opaque result bound to that engine and
the **same original View**. It captures the actual actor, successfully selected
organization, manifest and closed completion class at the original finish sites.
The raw creation path retains the actual decision from its one native pass;
only the existing opaque approved check supplies permission. Native reasons,
requests, JWTs, execution traces and response payloads are not activity metadata.

The wrapper preflights the sealed response without copying its ID, then calls
`Slot.Complete` synchronously. There is no action retry, append retry, replacement
worker or per-request SQL write. The true uncancellable Pebble append owns its
slot until it returns. SQL sealing remains asynchronous.

After successful local append, the engine serializes the sealed response and
checks the original View again, using the current clock and request context,
immediately before the first protected write. Expired or cancelled operations
withhold both successful output and revert `error.data`. They do not refresh or
rebuild identity. This boundary does not promise a token stays live throughout a
slow socket write; the socket has its own deadline.

The recorded HTTP status means the **selected application response before
recording**, rather than eventual wire delivery. JSON-RPC errors normally select
HTTP 200 and retain their numeric error code; their outcome is still failure or
denial. Later disk, expiry or socket failure cannot turn an executed or committed
action into an unexecuted denial. Emergency delivery is HTTP 503 or connection
failure. After a broadcast attempt its safe error preserves `-32004` and the
original verified signed transaction hash. It never resends the transaction.
A local receipt proves synced local append, not SQL sealing, mining or delivery.

## Metadata and bounds

The native labels are `eth_call` and `eth_sendRawTransaction`. Metadata adds its
canonical builtin labels and exact approved aliases, bounded by the recorder's
existing 512-label and 100-byte grammar limits. Strict parser
rejections use the fixed label `rpc.invalid_request`; HTTP method/body failures
use `rpc.invalid_transport`. These labels do not claim an unknown method actually
executed. The recorder never receives arbitrary caller method names, paths,
parameters, token claims or error text. Normalized outcomes distinguish invalid,
unauthenticated, denied, evaluation failure, unavailable, unconfirmed and success.
HTTP 200 with a JSON-RPC error is not success.

Metadata records the composite effective permission digest. Its authenticated
org-free builtins retain the actual actor and an empty organization; approved
anonymous metadata has neither actor nor organization. A policy digest identifies
the selected rules and does not by itself establish an organization or principal.
Valid notifications still settle once through the actual recorder and emit no
response body, including when recording or later delivery fails.

Only a valid direct `RemoteAddr` supplies IP metadata. Forwarding headers add no
authority. Invalid or zoned addresses become unknown/empty. Valid mapped IPs are
unmapped at ingress. Existing original mapped IP bytes in a recorded envelope
and its hash stay unchanged; the protected source normalizes equivalent IPs when
projecting output. Empty IP stays absent, and lower disclosure levels redact IP.

Request limits stay at the engine's existing one MiB call and two MiB raw limits.
Metadata applies its stricter one MiB envelope limit after the shared outer body
read, and drops request metadata before typed acquisition.
A canonical escaped JSON ID can occupy almost six or twelve MiB respectively.
The sealed response has a checked aggregate preflight and a sixteen MiB final
wire ceiling, including newline. Only the known result/error branches are
serialized. A detached ID or response copy is not held across disk append.

Bulk trace, code, receipt, transaction and wallet acquisition objects are not
retained in the opaque result. During append it retains its bounded response and
original View. After append a returned wire buffer adds at most sixteen MiB per
active handler; the HTTP limit remains held until write return, even though the
recorder slot has already been released. Standard JSON encoder working buffers,
request headers, View maps, allocator overhead and GC residency are additional
memory. These bounds are not a process RSS guarantee. In particular, the existing
maximum/default 256 slots is not automatically a safe deployment memory choice:
opaque response plus returned wire alone can approach eight GiB at simultaneous
maxima. Assembly must size the existing recorder limit, catalog, listener header
bound and process memory together. No throughput or latency target follows from
this library.

Stop new HTTP ingress before draining the recorder. Recorder shutdown waits for
real reservations and append work; a timeout retains spool ownership and does
not authorize closing the engine or SQL pools beneath outstanding calls. The
same lifecycle operation can be observed again. This wrapper provides no new
spool replacement or recovery path.
