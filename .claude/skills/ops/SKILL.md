---
name: ops
description: Operate an Open Privacy Suite deployment — prepare and independently approve configuration revisions, inspect execution capabilities, create organizations and groups, grant RPC access, onboard users by DID, choose credentials, connect MetaMask, and drive the named-principal SDK or bundled MCP server. Use for tenant setup, configuration review, access diagnosis, credentials, wallets or agent workflows.
---

# Operating Open Privacy Suite

This skill is a **map, not a manual**. The reference documentation is already in
the repo and on the docs site; what follows is the order operations must happen
in, which credential each step needs, and the traps that produce a working-looking
deployment nobody can actually use.

Everything here is behaviour of the code in this repository. When an answer is not
covered below, read the source rather than guessing — the admin handlers live in
`internal/server/` and the access engine in `internal/rbac/`.

## Source and helper setup

Use a complete OPS source checkout or source archive from the same explicit
release tag/commit as the deployment. Keep this skill, `sdk/` and the referenced
docs together; copying only this file does not install its helpers. Paths below
are relative to that source root. Do not fill missing files from a different
release or mutable main.

The helpers need Node 22+ and npm. Build them once from that source:

```sh
export OPS_SOURCE_ROOT=/absolute/path/to/ops-source
cd "$OPS_SOURCE_ROOT/sdk"
npm ci
npm run check:generated
npm run build
```

`npm ci` installs the lockfile-pinned development compiler and needs registry
access unless it is already cached. The built client has no runtime npm
dependencies. These setup commands need no OPS token and make no OPS API calls.
A generated-type mismatch is an error to investigate, not permission to
regenerate against another release. Run the following helper commands from this
same `sdk` directory. No separate npm publication or MCP server is required.

## Where the detail lives

| Topic | Read |
|---|---|
| Day-1 runbook, personas, first tenant | `ONBOARDING.md` |
| Full onboarding walkthrough with `curl` | `site/src/app/docs/operator-onboarding/page.mdx` |
| Permission model, claims, group rules | `site/src/app/docs/rbac/page.mdx` |
| Login flows, tokens, denial semantics | `site/src/app/docs/authentication/page.mdx` |
| Environment variables and secrets | `site/src/app/docs/configuration/page.mdx` |
| Why a call was denied | `site/src/app/docs/troubleshooting/page.mdx` |
| Every MCP tool, with arguments | `docs/mcp.md` |
| Named-principal SDK, exact configuration source and separate approval | `docs/implementation/headless-sdk.md` |

## Reviewed configuration workflow

Use versioned configuration for declarative `groups`, `contract-registry`,
`execution-rules`, `compliance`, `approvers` and `platform` streams. Keep operational
membership, onboarding, ban and address-link actions on their existing endpoints.
An active reviewed stream owns its projection: direct legacy writers return 409;
do not work around that guard or edit projection tables.

The SDK examples preserve context → draft submission → review in one invocation:

```sh
cd "$OPS_SOURCE_ROOT/sdk"
node examples/prepare.mjs --kind groups --org <organization-uuid> > context.json
# Edit a copy of context.source, preserving reviewed dependency requirements.
node examples/prepare.mjs groups.json > review.json
```

Supply a named session using `OPS_ACCESS_TOKEN`, or a configured Azure service
credential using `OPS_AZURE_ACCESS_TOKEN`; never both. Preparation with a source
file infers its explicitly declared recognized kind and scope and submits the
original bytes. There is no execution-rules default or cross-tenant search.
Explicit flags/environment must match source. Ambiguous or duplicate routing
metadata is refused, and the server still validates the complete document.
Context-only export needs explicit selection. Platform source/context uses
platform scope without `OPS_ORG_ID` / `--org` and requires named platform authority.

Review the exact source, artifact, preserved drift, dependency digests and sibling
revision IDs. Activation is a separate invocation by a different eligible human
or an independently configured trusted CI approver:

```sh
node examples/activate.mjs --prepared review.json
node examples/activate.mjs --prepared review.json signed-ci-approval.json
```

The example re-reads context and re-reviews the selected scope, exact IDs and
digests before activation. ID-only activation instead needs explicit kind/scope.
Do not rewrite source/dependencies, approve on the author's behalf, fabricate CI
claims, relax author separation, or retry a mutation automatically. After a lost
activation response, read the exact revisions and activation evidence before
deciding what to do next; the commit may have succeeded.

To restore earlier policy settings, read fresh current context and make a new
draft with the intended prior settings, the current base and the dependencies
reviewed for this change. Independently review and activate the new exact
revision under the current authority and capability checks. An old source file
is input to that new change; do not reactivate an old revision ID, reset SQL
pointers or restore old memberships, bans or deployment facts. Resolve an
ambiguous activation outcome before proposing another activation or rollback.

Check `context.capabilities.executionPolicy` (old execution-policy context:
`capabilities`; admin status: `execution.policyCapabilities`). A configured
consumer of `none` supports candidate/artifact review and old reference simulation,
but cannot activate execution policies or offer node preview/status/recovery.
OPS Guard v1 remains separate producer enforcement of RBAC/preflight fingerprints;
it does not consume execution-rule revisions. Experimental `guarded-reth` supports
activation and node actions; the old described-frame reference route is unavailable
there. Support is separate from current readiness and compiler availability.
Missing capability information must not enable sensitive execution actions or
disable ordinary non-execution configuration workflows. Evidence compilation and
simulation do not prove live enforcement, and an active desired revision does not
prove node application or final execution.

## 1. Initial tenant bootstrap — before reviewed groups

These direct group/access calls are for initial setup while the organization's
`groups` stream is unmanaged. Once a groups revision is active, even an admin-tier
token cannot use them to change its projection: use the reviewed workflow above
with named principals. An authorization error or an unknown managed state does
not establish that direct writes are allowed.

For a new organization, bootstrap in this order:

1. **Create the organization.** It starts with **no groups at all**.
2. **Create a group.** For the tenant's own administrators set `is_org_admin`.
3. **Set that group's access.** This is a separate call and it is *not* optional.
4. **Add members.**

OPS organization creation/deletion and operational membership actions remain
their existing separate operations. The platform stream's allowed Azure tenant
registrations and shared infrastructure are different settings: once managed,
their legacy setters require reviewed platform changes. Do not confuse those
Azure tenant registrations with OPS organizations.

### The trap: an admin group that can call nothing

Creating a group does **not** create its access settings. Until you set them, an
`is_org_admin` group grants every claim on every contract in the org and **zero
callable methods** — so its members authenticate successfully, appear correctly
configured in the dashboard, and every RPC call they make is denied.

This is deliberate fail-closed behaviour: the method allowlist is the source of
truth for method gating even for administrators, so the system refuses to guess a
set of methods rather than over-granting.

Two rules the API enforces when you set access on an `is_org_admin` group:

- `allowed_methods` must be **non-empty** — an empty list is rejected.
- `claims` must be **empty** — org admins receive all claims automatically, so a
  stored value there would be misleading. Sending claims is rejected.

A group cannot be both `is_org_admin` and `is_org_readonly_admin`; that is
rejected by the API and by a database constraint.

### Onboarding a user who has never logged in

Adding a member normally requires a user that already exists. To onboard a DID the
system has never seen, use the by-DID endpoint, which provisions the user and
places them in the group in one call:

```
POST /api/v1/admin/orgs/{org_id}/memberships/by-did
{ "did": "did:...", "group_id": "..." }
```

Note this has no MCP equivalent — the `add_membership` tool needs an existing
`user_id`, so for a brand-new DID use the REST endpoint above, or have the person
log in once first and then find them with `resolve_user`.

## 2. Which token to use

Both tier-1 credentials are sent in the `X-Admin-Token` header; which value you
send decides what you may do.

**Full admin token** (`ADMIN_API_TOKEN`) — an operational admin credential across
tenants, subject to the endpoint's identity, managed-writer and deployment gates.
It does not replace a named revision author or independent approver. Hold it only
inside your own trust boundary. It is not a blanket override — the
dry-run endpoint rejects **both** tier-1 tokens, because evaluating a request as
a user means reading tenant data as that user, which neither may do. That needs
a tier-2 org-admin JWT.

**Operator token** (`OPERATOR_API_TOKEN`) — a restricted onboarder. It can run the
initial bootstrap in section 1 while the groups stream is unmanaged: create and
delete organizations, create admin-tier groups, set their access, and add their
first members. It **cannot** read or modify tenant
data — regular groups, members, contracts, grants, audit logs and per-org
compliance all return `403`.

**If a third party performs onboarding, give them the operator token.** It does
the permitted unmanaged bootstrap while remaining unable to read the tenants it
creates. It is not a named document author/approver or a way around managed-stream
guards. Use an appropriately authorized named human for approvers/platform
changes, which services cannot replace. Handing over the full admin token grants
far more than the job requires.

Tenant administrators do not use either. They log in and act with a session JWT,
which is scoped to the organizations they administer.

## 3. Connecting a wallet

Requests carry `Authorization: Bearer <JWT>`. Anything that can set an HTTP header
— `curl`, ethers.js, web3.js, backend SDKs — works unchanged.

**Browser wallets cannot set headers.** MetaMask therefore needs a JWT-injecting
reverse proxy such as [`gateway-fm/jwt-injector`](https://github.com/gateway-fm/jwt-injector)
between it and the proxy: point the wallet's RPC endpoint at the injector, which
stamps the user's token onto every request. JWTs are short-lived, and keeping that
token file fresh is your deployment's responsibility, not the injector's —
`ONBOARDING.md` covers the mechanics.

### The trap: MetaMask still fails for ordinary users

Once the injector is wired correctly, MetaMask can still fail for authenticated
**non-administrator** users, with state reads returning an opaque
`method not found`.

This is intended behaviour, not a misconfiguration. MetaMask issues state reads at
**concrete block numbers** while simulating transactions, and the proxy denies
historical state queries to non-admin users: per-address visibility is evaluated
against *current* ownership, so answering a query at a past block could disclose
state from a time when the contract belonged to a different organization.

- Affected methods: `eth_call`, `eth_getStorageAt`, `eth_getBalance`,
  `eth_getCode`, `eth_getTransactionCount`, `eth_getProof`.
- A query counts as historical when its block parameter is a concrete block number
  or hash. The named tags — `latest`, `pending`, `safe`, `finalized`, `earliest` —
  are not historical and are allowed.
- Organization administrators are exempt.

Denials on the RPC data path are deliberately opaque, so the client is told only
`method not found`; the real reason is in the access log. Check there first when a
call fails for a reason the caller cannot see.

## 4. Optional MCP tools

The repo ships an MCP server exposing the admin and explorer APIs as tools, so an
agent can use it for supported bootstrap, operations and diagnosis. It is a
separate Go module in `mcp/`; its Go toolchain/dependencies are described in
`docs/mcp.md` and are not installed by SDK setup. For that optional source-based
setup, copy `.mcp.json.example` to `.mcp.json` at the source root and fill in
`PRIVACY_ADMIN_TOKEN` and `PRIVACY_URL`; the proxy must be running. Keep populated
credentials, local config and prepared customer reviews out of shared source.

Tools are grouped by domain: organizations, groups, users and memberships,
contracts and grants, disclosure, explorer reads, compliance, sessions and audit,
and system health. The unmanaged bootstrap in section 1 maps to `create_org`,
`create_group`, `set_group_access` and `add_membership`. Those setter tools are
not an alternative to named document review/approval for managed configuration;
use the SDK workflow above for that.

For diagnosis, three tools answer most questions without reading logs by hand:
`check_access` for whether a specific call would be allowed, `effective_permissions`
for what a user actually has in an organization, and `access_logs` for what was
denied and why. `docs/mcp.md` lists every tool and its arguments.

Destructive tools require an explicit confirmation step before they act.
