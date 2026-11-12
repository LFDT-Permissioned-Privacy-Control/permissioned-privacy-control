# V2 operational server

`cmd/ops-v2-serve` composes the native Go permission engine, identity broker,
wallet linking, Guard v1 admission, recorded RPC/Explorer reads and protected
disclosures. This executable links the operational SQL adapters. It does not
import the legacy server or make SQL the source of configuration authority.
The separate `cmd/ops-v2` remains the configuration authoring and validation CLI.

Build this delivery explicitly with `make build-v2` (installed frontend
dependencies required), or use `docker build -f Dockerfile.v2 -t ops-v2 .`.
The native image contains the server, offline commands and central browser
assets at `/app/web`; set `webDirectory` to that path and mount the approved
files, TLS keys and durable activity directory. Its entrypoint is
`ops-v2-serve`; override the entrypoint to run an offline command with the
appropriate separate credentials. The existing `build`, `build-prod` and
`Dockerfile.backend` targets select the legacy server.

Native builds use `production,prover_disabled` and disable CGO. The latter
disables the unused C proof generator, not the real Go Groth16 verifier. The
native runtime image contains neither `solc` nor the optional EVM backend.

## Configuration and startup

The deployment selects immutable approved files, then starts the server with
the exact digest of its runtime JSON:

```sh
ops-v2-serve --config /etc/ops/server.json --sha256 sha256:EXPECTED_HEX
```

The runtime file has `apiVersion: "ops.server/v2"` and
`kind: "OperationalServer"`. Unknown, duplicate, null and incorrectly cased
fields are rejected. The complete field definitions are in
[`config.go`](../../internal/operational/v2server/config.go),
[`data_config.go`](../../internal/operational/v2server/data_config.go) and
[`protected.go`](../../internal/operational/v2server/protected.go).

The main sections are:

| Section | What the deployment supplies |
| --- | --- |
| `listen`, TLS files, `webDirectory` | TLS listener and the built central browser assets. |
| `core` | Approved creation-observed runtime bundle, its manifest digest, environment and chain ID; loaded with the delivery profile. |
| `brokerSelection` | Separately approved multi-provider broker bundle with matching identity catalog, environment and chain ID. |
| `broker`, `wallet`, `sso` | Deployment namespaces, expected recovery epochs/generations, secret environment references and pinned SSO source files. |
| `data` | Fixed node endpoints and credentials, Guard mode bindings, restricted operational readers/writers, activity spool/source, index binding, cursor/pseudonym keys and pinned read policies. |
| `protected` | Case-store epoch, historical namespace model era, fixed data-organization node sources and separate administration/render/data-cursor key rings. |
| `explorerOrganizationId` | Optional validated deployment organization. If omitted, an Explorer request must have exactly one verified mapped organization; ambiguity is denied. |

DSNs and private keys are supplied through the named environment variables,
not literal JSON fields or request parameters. Binary keys use canonical
unpadded base64url with the exact length required by the consuming component.
Node credential headers and approved provider/price-feed secret references
must match their selected sources.

Startup validates both bundles, pinned policy files, keys, TLS, store bindings
and concrete adapters before opening the listener. There is no config watcher,
SQL settings fallback, mutable policy API, user directory or membership table.
Each request derives its groups from verified claims and the selected Git rules.
Membership evidence is bounded to five minutes; renewal cannot reset the age
of stale provider evidence.

## Operational storage and workers

Initialize stores using their offline administration commands and distinct
owner credentials. Serving credentials must have only the component's checked
application/reader rights; the server performs no DDL, grants or bootstrap.
Existing stores must be recovered using their component's recovery procedure,
not initialized as empty to bypass lost revocations or admission facts.

| Component | Durable operational state | Setup and reference |
| --- | --- | --- |
| Broker | One-use login/proof transactions and refresh families. | `ops-v2-identity-migrate`; [identity broker](v2-identity-broker.md). |
| Wallet | Proof-backed links, challenges and permanent revocations. | `ops-v2-wallet-migrate`; [wallet](v2-wallet.md). |
| Admission/creation | Used approvals, declarations, decisions and creation observations. | `ops-v2-admission-migrate` and creation-observer tooling; [admission](v2-admission.md), [current wallet source](v2-current-wallet-source.md). |
| Historical namespace | Qualified historical ownership/cohort facts and permanent denies. | `ops-v2-namespace`; [history](v2-history-reads.md). |
| Activity | Sealed request completions and their local durable spool. | Apply the repository's exact lean audit migrations 001–004 offline first, then `ops-activity-admin migrate` applies 005; [recording](v2-rpc-activity.md). |
| Disclosures | Operational cases, revocations and exposure audit records. | `ops-v2-disclosure-migrate`; [protected data](v2-protected-data.md). |
| SSO | Bounded one-use application handoffs. | `ops-v2-sso-migrate`; [SSO storage](v2-enterprise-sso-storage.md), [runtime](v2-enterprise-sso-runtime.md). |
| Explorer index | Retained indexed candidates, never policy authority. | A separately managed indexer and restricted selected-schema reader. |

The server runs its activity sealing and health loop. The deployment separately
runs the required indexer, creation observer and selected retention workers.
Keep owner/retention credentials out of the serving environment and preserve
the original spool across restarts; do not start a second spool owner.
The native image does not contain the baseline audit migration files or a SQL
client. Apply that prerequisite from the repository with separate offline
tooling; `ops-activity-admin` is not a replacement for migrations 001–004.

Schedule the `cleanup` subcommands of `ops-v2-wallet-migrate`,
`ops-v2-admission-migrate` and `ops-v2-disclosure-migrate` with their separate
retention DSN environment references. Each invocation performs one bounded
batch and exits; the interval settings do not start a scheduler. They reuse
`RETENTION_WALLET_CHALLENGES_*`, `RETENTION_COMPLIANCE_*` /
`RETENTION_TRAVEL_RECORDS`, and `RETENTION_DISCLOSURE_*` respectively. Admission
cleanup also requires the exact network/generation/coverage binding. Wallet
cleanup never removes links or revocation history, and admission cleanup keeps
used approvals and their evidence. Use the separate broker/SSO cleanup and
activity pruning commands for those stores.

`/rpc`, `/rpc/{org_id}` and the root RPC path share one activity Recorder with
`/api/v2/explorer/`. A protected disclosure uses its separate durable case audit
before exposure. A known successful commit is required where a component
returns a commit receipt. An uncertain commit can have durable effects without
a successful response; preserve the original idempotency key and inspect the
component's durable state rather than inventing a new operation.

## Privacy and feature limits

Disclosure authorization comes from standing Git-approved rules. A permitted
case is checked and audited automatically; there is no customer approval step.
The Explorer adapts its protected views to the existing case/read API rather
than introducing a second grant authority.
Full transaction rows include a case-bound `addressId` for an actual in-scope
target participant. It permits detail navigation in a transaction-only case;
it does not grant the separate address-browsing resource.

History-backed protected data is labelled `RETAINED_AT_READ` with a source-basis
digest. It is not a promise that every historical record is retained. Sealed
activity uses its separate `COMPLETE_AT_CUT` contract. Protected reports are
bounded to 4,096 eligible target addresses and 100 retained finance decisions;
an oversized scope fails instead of silently producing a complete report.
KYC is explicitly `not_evaluated`. Known-public, unknown and other-organization
addresses do not become protected target data through a counterparty match.

Ordinary Explorer pages use opaque cursors and exact decimal strings. Hidden
amounts are null; missing/private singleton records have the same unavailable
result. Totals that cannot be established for the permitted retained population
are omitted. Token transfers come from qualified token event logs; native-value
transactions and retained internal frames have their respective views. The
selected indexer remains trusted for candidate enumeration and retained internal
frame contents; an included parent receipt does not prove every internal frame.

Both Guard v1 transaction modes retain their existing approval lifetime and
used-approval rules. Native access lists are conservative usable lists, checked
again with the exact returned list; they need not match an optimized backend
list byte for byte. Node signing requires side-effect-free
`eth_signTransaction`; there is no send-first fallback. Partior's captured
participant workflow and live `recordParty` rules are excluded from this
delivery. The optional EVM policy backend remains separate from native V2.

## Rollout and recovery

Drain an instance, select the approved bundle/runtime digest and compatible
operational generations, then restart it. Return it to traffic only after
startup and the deployment's functional probes pass. Repeat for the remaining
instances. There is no application-level claim that different in-memory
configuration revisions across a rolling deployment are one atomic update.
DevOps owns traffic separation and coordinated rollback.

Retain the previous immutable files and their digests for rollback. Rolling
back configuration must not restore old operational SQL snapshots or discard
wallet revocations, used approvals, case revocations or activity spools. Storage
restore and lost-state recovery require the explicit drained recovery/epoch
procedures of each component. Liveness alone does not establish current node,
SQL, observer or index coverage; request-time source and authority checks remain
in force.
