# Disclosure rules and cases

Approved configuration defines reusable, narrow disclosure rules. An authorized
investigator opens an operational case within one rule. Ordinary cases require
neither a customer approval nor a Git change. Extra authority requires an
explicit source change through the institution's Git review process.

This keeps routine investigations usable without deploying a new policy for
every case. Its cost is that a broad standing rule can affect many cases.
Explicit targets, data organization, resources, addresses, dates, detail level,
validity and maximum duration constrain that risk. Purpose/legal-basis text
records context; it does not prove legal authority or grant permission. This
is an engineering choice, not a universal claim about banks or jurisdictions.

The component supplies rule validation, case administration, revocation and
administrative audit. It mounts no protected activity, transaction, event,
address or report endpoint. Source requirements identify their data inputs
without claiming that those adapters are bound or ready.

## Approved source

`catalog-disclosure/v1` is an explicit validation-only bundle profile using
`policycore/native-v1alpha2` and its bounded static native matrix. It requires
both the global identity source and a hashed
`disclosureCatalog: {"path":"disclosure.json","sha256":"sha256:..."}`.
Other catalog profiles reject this extension. The shared
[authoring tool](policy-authoring.md) derives hashes and capabilities; the
draft supplies only `disclosureCatalog: {"path":"disclosure.json"}`.
Both global files count toward the manifest's aggregate/file-count limits.

The closed source document is:

```json
{"apiVersion":"ops.disclosure-policy/v1alpha1","kind":"DisclosurePolicy","rules":[]}
```

An explicit empty rule list denies source-authorized case creation. Each rule
requires the following fields:

| Field | Meaning |
| --- | --- |
| `id`, `dataOrganizationId` | Stable ID and same-bundle data organization |
| `viewers.groups` | Nonempty exact `{organizationId,groupId}` references |
| `viewers.actors` | Additional ActorID restriction; explicit `[]` adds none |
| `targets` | `mode: actors` with nonempty `actors`, or `all-in-data-org` with `actors: []` |
| `resources` | Nonempty output categories |
| `addresses` | `mode: list` with nonempty `values`, or `all-target-addresses` with `values: []` |
| `dataTime` | Inclusive integer-second `{start,end}` record-date interval |
| `maxLevel` | `redacted`, `pseudonymous`, or `full` |
| `validity` | Integer-second `{notBefore,expiresAt}` access window |
| `maxCaseSeconds` | Positive duration, at most 30 days |

Resources are `activity_logs`, `transactions`, `events`, `addresses`,
`activity_summary`, `sanctions_report` and `compliance_report`. These are output
entitlements: needing an internal activity source for a report does not grant
raw-log output. The case component stores scopes but exposes none of those
data categories itself. One complete rule must cover every scope dimension;
rules cannot combine one target with another rule's higher detail level.

Defaults bound source bytes to 1 MiB, rules to 1,024, viewer group references
per rule to 128, viewer/target ActorIDs to 256 and addresses to 1,024. Runtime
identities are canonical `ops:p1:` ActorIDs; DIDs, user UUIDs and tenantless
provider subjects are not interchangeable. Addresses normalize by their bytes;
duplicate normalized values reject. No user/membership directory is queried.

## Case API

`disclosurehttp.Handler` mounts these exact operations on its V2 HTTP mux:

| Method | Path | Purpose |
| --- | --- | --- |
| POST | `/api/v1/disclosure/cases` | Create or retry a bounded case |
| GET | `/api/v1/disclosure/cases` | Recipient or own-org administration metadata |
| GET | `/api/v1/disclosure/cases/{id}` | Authorized case metadata |
| POST | `/api/v1/disclosure/cases/{id}/revoke` | Permanently narrow a case |
| GET | `/api/v1/disclosure/cases/{id}/audit` | Bounded case-administration audit |

There is no approve/reject, reopen, delete, user-search or grant-token route.
HEAD does not execute GET handlers. Requests use the selected bundle's local
OPS assertion verifier. Responses are `no-store`. Unknown/unauthorized IDs
both return 404; malformed input returns 400, changed cursor/idempotency
context 409, invalid/expired access 401 and unavailable storage 503.

Create requires `ruleId`, `recipientActorId`, `caseReference`, `purpose`,
`legalBasis`, `scope`, `expiresAt` and UUID `idempotencyKey`. Scope is exactly
`{targetActors,resources,addresses,dataTime,level}`, with concrete targets.
JSON bodies are bounded to 128 KiB and raw query strings to 16 KiB before URL
decoding. Unknown/wrong-case/duplicate fields and null reject.
The response reports effective expiry bounded by the request and current rule.

Recipients need current whole-rule eligibility and their **entire original
scope** still fitting that rule to read metadata. True data-org administrators
retain own-org administrative history, including after source-rule removal;
that role does not itself grant protected-data access. A recipient can revoke
their own case after losing their role, receiving only `{caseId,status,version}`
so that operation cannot expose old targets or notes. Closed/revoked cases
never reopen. Stored scopes remain immutable.

Same creator/key and normalized request identify one case; different requests
return 409. Retries check present metadata rights and commit `metadata_read`
without duplicating `case_opened`. Source widening cannot extend original
expiry. Protected consumers must apply the current ceiling:
`min(recorded expiry, createdAt + current maxCaseSeconds, current rule expiry)`.
Administrative history has its separate metadata predicate.

Lists use `role=recipient` by default, or `role=data-org-admin` with an explicit
`organizationId`. Limits are 1–100, default 50; at most 500 candidates are
checked per page. An empty filtered page can return `scanComplete: false` with
`nextCursor`. There is no approximate total count. Audit has separate
`limit`/`cursor` and reveals no scope, free text, query/response body or IP.

Dedicated AES-256-GCM cursor keys allow one active and one explicit overlap key.
Encrypted cursors bind actor, endpoint/case, role, organization, query,
bundle/source identities and store epoch. They expire within five minutes and
the access assertion. They never replace current permission checks.

## Operational SQL

Schema `ops_v2` contains two data tables, `disclosure_cases` and
`disclosure_events`, plus one-row `disclosure_schema_version`. There are no
user/group/org foreign keys, policy projections or legacy policy reads. The
same physical database may host separate schemas/roles. Operational actor
references do not create a user profile directory.

Application grants are SELECT/INSERT on cases/events, UPDATE on only the five
status/version/revocation columns, and SELECT on schema version. A trigger
rejects immutable changes, reopening and version regression. Startup checks
effective grants and rejects owner/migrator privileges, audit mutation,
immutable-column updates and legacy public-data-table access. Migration and
retention have separate credentials. Pools cap at eight connections;
operations have five-second contexts, three-second statement limits and
one-second transactional lock waits.
Failure rollback/connection cleanup has its own one-second deadline.

Creation and its opening event commit together. Revoke and read-audit commits
serialize on the same case row. A response is prepared before audit commit,
then operation-specific validity and JWT lifetime are rechecked immediately
before its first bytes. Failed audit/commit/final checks return no metadata.
An event can remain if delivery failed: it records prepared exposure, not
client receipt. There is no exactly-once delivery promise.

Case writers, the service, database owner and backup/restore process remain
trusted for operational/audit integrity. File rules bound permissions but do
not make database tampering harmless. A malicious DBA is not neutralized.

Apply the embedded schema offline with pre-existing roles:

```sh
go run ./cmd/ops-v2-disclosure-migrate \
  --dsn-env OPS_DISCLOSURE_MIGRATION_DSN \
  --app-role ops_disclosure_app --retention-role ops_disclosure_retention
```

The named environment variable contains migrator credentials; its value is not
printed or accepted as a CLI argument. An advisory lock serializes migration.
Version, column shape and SQL-source checksum must match. Application startup
does not run DDL or repair unknown schema versions.

`RetentionFromEnv` reads `RETENTION_DISCLOSURE_EVENTS`,
`RETENTION_DISCLOSURE_CASES`, `RETENTION_CLEANUP_INTERVAL` and integer
`RETENTION_DISCLOSURE_CLEANUP_BATCH`. Defaults are seven 365-day years for cases
and events, one hour between cleanup attempts and batches of 1,000. These are
engineering defaults, not a legal judgment. Durations must be positive, case
retention at least 30 days and batch at most 1,000. `CleanupOnce` uses separate
retention credentials, bounded deletion and no cascade into audit. Its job
owner can retry time-bounded contention failures.

Stored namespaces hash the length-prefixed selected environment, decimal chain
ID and explicit `CaseStoreEpoch`, with a versioned domain. Changing source/image
alone keeps compatible cases; changing environment/chain/epoch isolates them.
This is not proof of blockchain identity: protected-chain consumers must also
bind their trusted deployment/genesis identity; private networks can reuse a
chain ID. This administration component does not qualify those data sources.

After restoring stale storage, deployment must choose a new `CaseStoreEpoch`
for all serving replicas. Old cases/cursors then fail closed, including old
creator/key collisions. The application cannot automatically detect a stale
backup restored with the old epoch. Drain, compatible image/bundle/schema
selection and restore invalidation belong to deployment operations.

## Verification

```sh
go test -race ./internal/identity ./internal/disclosurepolicy ./internal/disclosurecase ./internal/disclosurehttp ./internal/policybundle ./internal/operational/disclosuresql
go test ./internal/archtest
```

The SQL protocol test owns a disposable loopback-only PostgreSQL 16 container.
It exercises signed JWTs through actual HTTP and two independent SQL pools,
including retries, revocation, commit failure, expiry before output, role limits,
pagination and restore state. It does not qualify protected-data adapters or
live Azure/Privado issuance.
