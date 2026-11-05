# Headless OPS SDK

The TypeScript SDK in `sdk/` uses the same named-principal REST and JSON-RPC
interfaces as the dashboard. MCP is not required. It has no runtime dependency;
Node 22+ supplies `fetch`. The checked-in component and operation types are
generated from the repository's OpenAPI 3.1 artifact.

## Use the skill and helpers from one source release

The OPS skill in `.claude/skills/ops/SKILL.md` instructs the agent to run the SDK
examples. Supply a complete OPS source checkout or source archive from the same
explicit release tag/commit as the deployment. It includes the skill, SDK
source/examples/lockfile, matching OpenAPI artifact and referenced documentation.
Copying the skill alone does not supply those files. The SDK is excluded from the
backend image; run its helpers on the operator/agent machine.

With Node 22+ and npm installed, build the client once from that source:

```sh
export OPS_SOURCE_ROOT=/absolute/path/to/ops-source
cd "$OPS_SOURCE_ROOT/sdk"
npm ci
npm run check:generated
npm run build
```

These commands make no OPS API calls and need no token. Installation uses the
lockfile-pinned development compiler and needs registry access unless cached;
running the built helpers needs no runtime npm dependencies. A generated-type
mismatch is a source/spec mismatch to investigate; do not mix release files or
silently regenerate types to bypass it. Run all example commands below from this
same `sdk` directory.

The package is private: it is supplied with the OPS source, not installed as a
separately published npm SDK. Its documented skill/helper path is maintained
with that OPS release. The optional MCP server is a separate Go module in `mcp/`
with its own setup in `docs/mcp.md`; it is not installed or authenticated by the
SDK setup.

After `make api-spec`, run `npm run generate` in `sdk/`. `npm run check:generated`
fails on drift. The generator retains required/optional properties, references,
arrays, enums, unions, intersections and typed dictionaries; unconstrained
OpenAPI objects remain `unknown` dictionaries. It does not infer stricter types
than the server specification. Exact authored configuration text has a dedicated
submission helper so duplicate keys and malformed source reach the strict
server parser intact.

## Named service workflow

First provision the service principal through the configured Azure tenant and
grant its OPS organization roles/methods. Exchange an Azure client-credentials
access token with `loginServicePrincipal`, or initialize a client with its OPS
access/refresh session. Tokens stay in memory; the SDK has no operator-token
fallback, browser cookie session or token logging. Use HTTPS outside local tests.
Refresh is explicit and concurrent refresh calls share one rotation. A failed
mutation is never automatically retried. Session changes and newer login
attempts invalidate pending authentication responses, so a slow earlier response
cannot switch the client back to an older principal.

```sh
export OPS_URL=http://localhost:8080
export OPS_ORG_ID=<organization-uuid>
export OPS_AZURE_ACCESS_TOKEN=<provider-access-token>
node examples/operate.mjs readiness
node examples/prepare.mjs --kind groups > context.json
```

Copy the complete `source` object from context into a new JSON file and edit it.
Context includes current source, catalogs, viewer eligibility and migration
diagnostics. Omission is not a deletion request; managed resources require
explicit deletions. For context-only export, select `--kind` or set
`OPS_CONFIGURATION_KIND` to `groups`,
`contract-registry`, `execution-rules`, `compliance`, `approvers` or `platform`.
Platform documents require separately configured named human platform authority;
that authority does not confer tenant access.

```sh
node examples/prepare.mjs groups.json > review.json
```

With a source file, one invocation reads context, submits a draft and reviews it.
The example infers its recognized `kind` and declared `scope` from that file;
there is no default stream. `--kind`, `--org`, `OPS_CONFIGURATION_KIND` and
`OPS_ORG_ID`, when supplied, must agree with the declaration and with each other.
Malformed, unknown, duplicate or case-ambiguous routing metadata is refused
before an HTTP request. The source is submitted as the original text, preserving
whitespace and all other fields; server parsing and authorization remain
authoritative. This routing check is not a second document validator.

Platform source declares `kind: "platform"` and `scope: {"kind":"platform"}`.
It needs no organization ID; unset `OPS_ORG_ID` and omit `--org`. A platform
context export uses `node examples/prepare.mjs --kind platform` under the same
conditions. No command searches other tenants or streams to guess a selection.

`OPS_COACTIVATE` supplies comma-separated sibling revision IDs. Declare their
digests in source dependencies before submitting. Draft compilation retains the
immutable artifact, review uses the full projected catalog, and activation
rechecks the current base, authors, independent approver and exact bundle.
Legacy restriction migration additionally requires `legacyRestrictionDigest`;
ordinary proxy relationships need reviewed `proxyPairs` or explicit pair rules.

Set `OPS_PREVIEW_FILE` to a JSON request with `method` and `params` to preview the
new execution candidate when `capabilities.executionPolicy.nodePreviewSupported`
is true. An unavailable requested preview is refused before submitting a draft;
omit the preview option to keep drafting and reviewing offline evidence.
Supported methods are `eth_call`, `eth_estimateGas`
and `debug_traceCall`. Supply a linked `from`; it may be omitted only when the
principal has exactly one active linked address. Current active permissions
remain mandatory and a candidate cannot authorize the application call itself.

Ordinary previews cannot execute candidate live state/account reads. A policy
with `recordParty` returns HTTP 403 with code
`candidate_state_reads_require_diagnostics`. An audited full human organization
administrator can explicitly use `preview(..., {dryRun:true,...})` to diagnose a
current member under mandatory organization isolation. A service cannot promote
itself by setting this field. An explicitly granted `debug_traceCall` method
exposes application execution internals; private policy frames remain hidden.

## Consumer capabilities

Configuration context reports `capabilities.executionPolicy`; the older
execution-policy context reports `capabilities`; admin status reports
`execution.policyCapabilities`. These describe configured implementation support,
independently of caller authority, compiler availability and transient node
readiness. `configuredConsumer: "none"` means no live consumer for execution
policy revisions, even when OPS Guard v1 is configured. Guard v1 retains its
existing RBAC/preflight fingerprint checks; it does not enforce these revisions.

| Capability | Legacy / consumer `none` | Experimental `guarded-reth` |
|---|---|---|
| Candidate and artifact review | Supported | Supported |
| Old described-frame reference simulation | Supported | Unavailable; old route returns 409 |
| Execution policy activation | Unavailable | Supported |
| Node preview, transaction status, ownership recovery | Unavailable | Supported |

Review and reference simulation are evidence workflows, not proof of live
enforcement. The examples print execution capabilities with prepared evidence
and before approval. Execution activation, including an execution sibling in an
otherwise ordinary bundle, requires affirmative support; missing capabilities
keep it closed. Ordinary non-execution draft/review/activation does not depend
on this additive object. Server authorization and activation fences are still
authoritative when a caller uses `OpsClient` directly.

## Approval is a separate operation

The preparation example stops at the review boundary. Run activation with a
different eligible human's `OPS_ACCESS_TOKEN`, or supply a signed manifest from
an independently configured CI approval system:

When switching credential sources, unset `OPS_AZURE_ACCESS_TOKEN` before setting
`OPS_ACCESS_TOKEN`. The examples reject ambiguous simultaneous credentials.

```sh
node examples/activate.mjs --prepared review.json
node examples/activate.mjs --prepared review.json signed-ci-approval.json
# An ID alone needs an explicit stream and scope; there is no default:
node examples/activate.mjs --kind groups --org <organization-uuid> <revision-id>
```

The prepared file carries selected kind/scope, primary and sibling revision IDs,
and reviewed digests. The approval invocation fetches context and freshly reviews
that exact selection, then checks scope, kinds, IDs and digests against the file.
It does not trust saved capabilities or saved approval eligibility. Explicit
selection and `OPS_COACTIVATE`, if supplied, must agree with prepared metadata.
Platform ID-only approval requires `--kind platform` and no organization ID.

The SDK captures the exact candidate IDs and document digests.
CI `candidateDigests` is keyed by configuration kind, not revision ID. The SDK
checks the captured digests before sending; the server independently verifies
scope, trusted issuer/key, repository/ref/commit, service subject, independent
human reviewers, expiry and single-use nonce. The SDK does not mint approval
claims or hold the external approval signing key. CI cannot replace approver
trust policy or platform configuration. Changed/stale bases require a new draft
and review, never silent source rewriting.

An activation error after dispatch, including a lost response or timeout, may
leave the selected revisions active. Do not retry automatically. Read those
exact revisions and their activation evidence first; an active selection is
not the same as node application or successful execution. A stale or changed
bundle requires a new explicit review and approval decision.

## Restore previous policy settings

Read current context before preparing a policy rollback. Use the earlier desired
settings in a new document with the current base, the reviewed dependencies and
any required explicit deletions; submit, review and independently activate that
new exact revision. Current authority and execution-consumer capabilities still
apply. An old revision ID cannot simply be reactivated, and an old source must
not silently overwrite current dependency choices or operational memberships,
bans, sessions or deployment observations. Resolve an ambiguous previous commit
through authenticated revision/activation readback before making another change.

## Bootstrap and operational actions

Initial tenant setup can use the existing tier-1 organization/admin-group/access
operations while the organization's groups stream is unmanaged. After adoption,
group definitions and permissions use named-principal document changes; a managed
writer's 409 or an authorization failure does not permit fallback to legacy
setters. OPS organization lifecycle is separate from the platform stream's
allowed Azure tenant registrations/shared infrastructure. Managed platform
settings use its reviewed, human-authorized workflow.

Onboarding, memberships, bans and address links remain operational API actions.
They do not require a policy revision. Their existing caller/scope checks still
apply. A tier-1 bootstrap token is not a named SDK session and cannot substitute
for the author or independent approver. See `.claude/skills/ops/SKILL.md` for the
bootstrap sequence and credential roles.

## Operations, RPC and status

Generated `client.request(operation, input)` provides typed access to the full
OpenAPI routes, including operational memberships, bans, linking and disclosure.
The convenience examples include onboarding via the existing by-DID operation:

```sh
node examples/operate.mjs onboard membership.json
node examples/operate.mjs rpc call.json
node examples/operate.mjs submit signed-transaction.txt
node examples/operate.mjs status <transaction-hash>
```

`membership.json` follows the generated `MembershipByDIDRequest` schema.
`call.json` contains `method`, `params`, and optional `visibleTo`. Deployment and
ordinary transactions must be signed locally and sent with
`eth_sendRawTransaction`; node mode does not support unlocked-account
`eth_sendTransaction`. Shared signers retain the current named principal's
identity and cannot read each other's transaction status.

`preview`, `transactionStatus`, `waitForFinality`, and the example `submit` command
that waits for finality use the guarded node's protocol. Their support flags are
separate from `execution.ready`; there is no legacy receipt fallback. Use the
ordinary `rpc` helper for legacy transactions, and handle its normal RPC result.

Acceptance is not inclusion or finality. `waitForFinality` ends only on a final
status with completed OPS reconciliation: `included` or `reverted` with
`execution.finalized`, or `dropped`: with `nonce_consumed` a finalized
transaction used its nonce and it can never execute. Lease expiry alone keeps
the transaction nonterminal, with its immutable principal binding retained
independently of final-status retention. Reverts and drops are returned for the caller to
handle. `pending`, `provisional` and `renewal_stopped` are nonterminal:
`renewal_stopped` means OPS will not renew the transaction's identity, but it
may still settle, so the helper keeps polling and passes every status to the
optional `onStatus` callback. `isFinal` and `describeStatus` expose the same
rules, and `FINAL_STATUSES` lists the final values. The helper has a bounded
timeout (two minutes by default) and accepts an `AbortSignal`; a transaction
can stay pending for up to OPS's maximum age (ten minutes by default) plus the
finality delay, so pass a longer `timeoutMs` to wait for every outcome.
HTTP/authentication errors are returned to the caller.
Permanent ownership, deployment grants and visibility records are reconciled
only from finalized node evidence. A status response never exposes raw
transactions, execution identity envelopes or visibility recipients.

## Verification

From the prepared SDK source directory, run `npm test` for generated drift,
build, type and runtime checks. Its HTTP fixtures do not contact a deployment.

Tests cover exact source, named credentials, service
exchange, refresh serialization, no mutation retries, captured review bundles,
external CI digest binding, explicit diagnostics, RPC errors, finality polling
and encoded route parameters. Subprocess example tests additionally cover stream
inference, platform scope, ambiguous routing metadata, exact source preservation,
fresh prepared-review binding and capability refusal for direct/sibling execution
activation and node preview. They inject HTTP responses without a live service.
Compile-time negative cases reject unknown paths,
missing path parameters and unsupported stream names. Live OPS stack behavior is
covered by the separate integration harness; these SDK tests do not claim a
live identity-provider login.

The SDK also passed five checks against isolated stack
`ops-reth-6fe399425e`: generated-route named human mockauth login and real refresh,
live readiness/current execution context, an explicit audited human candidate
diagnostic on Reth, revoked-rule RPC denial, and finalized own status with a
shared-signer peer denied status access. The reproducible smoke command is:

```sh
node test/stack-smoke.mjs <OPS_ORIGIN> <stack/acceptance.json> <stack/sdk-acceptance.json>
```

This command uses that harness's development mockauth identities. It never
synthesizes production credentials and does not claim an Azure provider test.
The result file contains only stack/organization identifiers and check names.
