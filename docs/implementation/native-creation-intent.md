# Creation intent journal

`catalog-runtime-creation-intent/v1` selects the closed runtime source
`ops.runtime-policy/v1alpha6`. It retains the native version 4 evaluator,
unsigned deployment simulation, and existing lifecycle signed and Guard v1
evidence formats. `rpcengine.NewCreationIntents` and
`admission.NewCreationIntents` explicitly select this contract; older
constructors and source accessors reject it.

The runtime document adds required `creationAttribution: {"factories": []}`.
An empty list is valid. Each optional declaration contains exactly `address`,
`organizationId`, `codeHash` and `scope: "same-namespace-creation-subtree"`.
At most 64 unique factories are accepted. Each must have a current explicit
registry owner matching its organization and a nonzero runtime hash. Shared
infrastructure and precompiles cannot be factories. An address scope alone is
not registration.

## What admission records

One complete successful native pass produces a private approval bound to the
exact request View, execution, organization and wallet snapshot. The financial
service requires that approval; detached JSON cannot substitute for it.
All frames and SELF checks must pass before the approval is exposed. The compact
plan stores at most 128 known fresh creation attempts in at most 64 KiB:
address/creator, CREATE kind, intended organization, initcode hash, value,
caller, depth and creation ancestry. It archives no raw code, signed
transactions, tokens, claims or user directory data.

A wallet reference requires a currently proved signer association and the
transaction's fixed Origin actor and organization. It references the actual
stored primary or extra witness. Earlier witness source and timestamps remain
unchanged when the current approved plan comes from a newer bundle.

A factory reference requires that the same pass observes the declared factory
as direct creator with installed ordinary runtime matching its pin. It contains
no actor or wallet. One reference covers the complete eligible factory-root set.
Inherited scope stops at any foreign-organization frame, including an ordinary
CALL, and resumes for unaffected siblings. A separately qualified factory can
start its own scope. A proxy runtime pin does not freeze implementation/storage.

These are admission-time intents. They establish neither actual inclusion nor
historical ownership or individual-deployer permission. A simulation does not
prove eventual execution, and a locally older block anchor does not prove that
a transaction was unmined when requested. No serving consumer reads this
journal as authority.

## Atomic effects and limits

Four additional tables share the operational PostgreSQL transaction:
`creation_capacity`, `creation_plans`, `creation_authority_refs` and
`creation_work`. Inserts and work/counter updates commit with financial record
use, strict audit, Origin, witnesses and shares. The existing hash lock precedes
a final network capacity-row lock that also serializes limits across different
hashes. Failure rolls back all allow effects; financial denial records no intent.

No creation or no qualified wallet/factory reference adds no journal rows.
Exact retries add no creation writes, capacity or work generation. New reference
batches increment generation once. Clock changes do not change reference
identity. Wallet and factory branches each reserve eight slots per transaction;
exhausting one cannot consume the other.

Per-network ceilings are 100,000 work rows, 200,000 plans, 1 GiB of encoded plan
payload, and 800,000 references of each kind. `OpenCreationWriter` accepts lower
positive limits, never higher limits. Row/index/WAL/backup overhead is additional
to the payload limit. A full journal makes new qualifying submissions unavailable.
Authority rows are retained indefinitely; compliance retention does not delete
them.

Only a known durable COMMIT followed by existing final freshness checks permits
Guard delivery or broadcast. Ambiguous COMMIT or postcommit expiry can leave a
truthful intent without publication. There is no background renewal, reapproval
or rebroadcast. Guard v1's signed format and TTL stay unchanged. Unsigned
simulations write nothing.

## Offline migration and restore

Stop all old application instances, readers and workers before upgrading an
existing schema. Mark existing networks unready with `begin-recovery` and a new
generation, then run `migrate-creation-intents` with explicit owner credentials
and three pre-existing roles. It installs migration 002 and reports the actual
validated version and combined source checksum. Application startup performs
no DDL. The new constructor requires schema 2.

New code can open exact schema 1 for older profiles and exact schema 2 for old
or new profiles. An old binary rejects schema 2 on startup. Updating the version
row cannot stop an already-open old process. After migration, image rollback
must retain schema-2-compatible code; an old bundle can be used with that code.

The application can insert plans, references and work, update only work
generation/time and capacity counters, and read the new tables. It cannot
rewrite/delete plans or references. The reader cannot write; retention has no
access to the four new tables. Database owners, migrators and backup operators
remain trusted because operational provenance can affect privacy.

Restore all applicable operational tables and constraints before `finalize`.
Finalization checks exact counters, plan encoding/digests/graphs and network
chain, reference variants/digests, Origin/witness bindings, contiguous branches,
work generations and finite timestamps. It streams plans in keyset pages of
256, retains bounded summaries, then checks each page's references after closing
the plan result stream. It never buffers the whole history or queries inside an
open result stream.

CLI `finalize --recovery-timeout` defaults to 10 minutes and accepts a positive
value up to 30 minutes. Earlier caller deadlines and finite individual SQL/lock
deadlines still apply. The existing `FinalizeRecovery` Go API retains its
60-second budget. Failure leaves readiness false. These budgets do not guarantee
completion for arbitrary hardware/history. Success requires an explicit
operator completeness attestation: present-row checks cannot detect coherently
omitted history. Restored rows cannot mint a process-local publication receipt.
