# First-party SSO configuration and transaction storage

`ssopolicy` compiles immutable first-party client configuration. `ssotransaction`
provides structural record validation and canonical storage captures. The
operational `ssosql` adapter stores bounded handoff transactions in PostgreSQL 16.
None of these packages authenticates a user, decrypts a token, issues an access
token, checks a client secret, or serves an HTTP endpoint. Finding a row or
accepting structurally valid ciphertext grants no authority.

Client documents use `ops.sso.clients/v1`, kind `SSOClients`. All fields are
required; unknown, duplicate, null or incorrectly cased fields are rejected.
Client IDs, references and redirect arrays must already be sorted and unique.
Clients explicitly select `client_secret_basic` and
`first-party-full-core-bearer`. The document contains an environment **reference**
for the client secret; compilation reads no secret or environment value.
Redirects are exact canonical HTTPS URIs with a clean ASCII path and no query,
fragment, user information, wildcard or encoded path. Callback and namespace
hosts accept canonical IP addresses or DNS names of at most 253 bytes; alternate
IPv4 spellings and numeric-ending DNS names are rejected because browsers may
interpret them as a different address. The complete source is
limited to 1 MiB,128 clients,16 profiles and 16 redirects per client.

Two explicit eligibility configurations are accepted:

- `any-listed-group`: an OR over 1–32 approved organization/group references.
- `any-human-in-allowed-profiles`: no group references; an explicit identity-only
  handoff rule for configured Azure human or Privado identity/role profiles.

These are configuration choices. A service composing an authenticated handoff
must check the actual human/profile and **all** organizations in the same
verified current permission View against `trustedOrganizationIds`, then apply
eligibility. An explicitly empty trusted-organization array means only a
zero-organization View is eligible. It never means unrestricted access. The
normal Core bearer also permits actor-global operations such as the actor's own
wallet operations: the trust mode does not attenuate that authority or bind a
token against future Core policy changes. Applications must be trusted with the
whole bearer; this component adds no delegated client scopes.

## Storage and one-use transitions

The owner creates two existing, distinct LOGIN NOINHERIT roles, then calls the
offline `Migrate` and `Initialize` APIs with an explicit namespace, broker
namespace/recovery epoch, SSO epoch and limits. Runtime `OpenApp` and
`OpenRetention` perform no DDL, role creation or initialization. Identity
migrations and their three roles are separate and receive no SSO privileges.

`ops_sso_v1.state` holds readiness, immutable namespace/broker binding, schema
checksum, selected limits and counters. `transactions` holds the closed flow
lifecycle. Multiple instances serialize counter mutations on the same state row
before locking flow rows. Ordinary operations do not scan retained rows to
recompute quotas.

A pending record expires within 5 minutes. Preparing a ready record adds an
opaque grant envelope, code hash, original family/token bindings and the digest
and byte count of the selected code response. The code expires within 60 seconds
and before the original flow, token and family deadlines. Consuming the exact
ready capture changes the phase once, records the selected token response
**digest and byte count**, and clears both ciphertexts in the same transaction.
A second consume fails; no raw response body or token is retained in terminal
metadata. The record does not assert that either response reached a browser.

A Capture is a domain-separated hash of the exact structural record, including
its original epochs and ciphertext. It is an optimistic storage comparison,
not a verified session or permission capability. Encryption, approved key
selection, actual signed-token validation, browser recipient/family checks,
client authentication, PKCE and final output checks belong to the authenticated
service using the adapter. Public key identifiers in rows are not key material.

All runtime operations have a 5-second context bound,500 ms lock timeout and
2-second statement timeout; the pool has at most 8 connections. Transactions use
synchronous COMMIT. Only a known successful COMMIT followed by fresh local
context/expiry checks yields a receipt. A connection failure at COMMIT can leave
a committed change with no receipt. Callers may inspect the durable phase; they
must not repeat provider/business effects or redeem a consumed code to hide the
uncertainty. A post-COMMIT expiry failure also returns no receipt while retaining
the committed state.

Rows and SQL projections are bounded before transfer, copying or hashing. The
projection's `all_fields_bounded` marker is authoritative: an overlong nullable
field masked to NULL must fail rather than become a legitimate absent field.
Current selected state is checked at transaction boundaries; its row lock ends
at COMMIT. This is no promise of an atomic future logout, policy-rollout or
socket-delivery fence.

## Capacity and retention

Defaults are:

| Budget | Limit |
| --- | ---: |
| Active pending/ready rows |200,000 |
| Ready rows |40,000 |
| Actual active ciphertext bytes |1 GiB |
| All stored rows |40,000,000 |
| Metadata credit |128 GiB |
| Prepared receipt retention |24 hours |

Each stored row reserves 2,048 logical metadata bytes. The canonical framing's
conservative metadata upper bound is 1,527 bytes. The context envelope is at most
4 KiB, the grant envelope 24 KiB, and the full framed record at most 30,199 bytes.
These credits describe logical values; Go/driver allocations, PostgreSQL heap,
indexes, TOAST, WAL, vacuum, backups and physical ciphertext remnants add cost.
Clearing a logical value does not promise immediate disk erasure.

All stored rows count, including expired and old-epoch records until actual
cleanup. Pending credit reserves no future ready-row or grant-byte capacity.
Every limit must still fit when the ready transition commits. The Go state
validator explicitly checks `AllRows <= MaxAllRows`; the individual comparison
is not inferred from the SQL constraints.

For illustration,100,000 active people handing off once every 5 minutes produce
333.33 handoffs/second and 28.8 million receipts/day.100,000 waiting pending
contexts plus 20,000 ready envelopes at maximum sizes consume 937.5 MiB. This is
arithmetic, not measured throughput, memory, latency or whole-auth capacity.
Multiple applications/devices and family churn require explicit separate
capacity planning. No 40-million-row or 333-TPS qualification is claimed.

`RetainUntil` is fixed at **original code expiry plus the selected retention**,
so every possible redemption has at least 24 hours of metadata retention by
default. Consumption, retries and configuration changes do not shorten or reset
that cutoff. A retention batch processes at most 1,000 rows, dividing budget
between expired pending deletion, ready expiry/cipher clearing, and terminal
audit deletion. Only actual committed rows release credits. The worker must
keep up with the arrival rate; the batch bound is no throughput guarantee. A
backward cleanup clock is rejected without forcing UTC forward. Full capacity
fails closed instead of discarding unexpired audit metadata.

## Roles and recovery

The app role can insert pending rows, read rows and update only lifecycle
columns/counters. It cannot delete or change namespace, readiness, limits or
roles. The retention role can clear expired ready ciphertexts and delete rows;
it cannot insert, consume or edit prepared identity/output metadata. Runtime
roles may use ordinary temporary tables but cannot CREATE in the database or
any persistent schema, including empty foreign schemas. Exact catalog/ACL
checks reject RLS, changed owners/functions/triggers/constraints/indexes,
unknown objects and wrong privileges. Fixed transaction search paths prevent a
temporary relation from shadowing catalog queries. The lifecycle guard separately
qualifies its owner lookup as `pg_catalog.pg_namespace`, so an allowed temporary
relation cannot impersonate the schema owner.

App and retention write credentials are explicitly part of the metadata/counter
integrity and availability trust boundary. Column privileges do not prevent a
stolen writer credential from issuing allowed counter updates directly, and a
retention DELETE privilege is not intrinsically age-restricted. The trusted
cleanup algorithm enforces age. An offline schema owner is also trusted. Such
SQL data still cannot authenticate a grant without the separate service's real
AEAD, signed-token and broker checks.

Owner recovery requires a drained deployment. `BeginRecovery` compares the exact
current Scope, commits storage unready and selects a different current SSO
epoch, optionally an explicitly supplied broker epoch. It does not rewrite old
record epochs. While unready, normal app writes and stale prepared finishes
fail. `Reconfigure` can change only limits/retention under drain when current
usage fits; old receipt cutoffs and role/namespace bindings stay fixed.

`FinalizeRecovery` deletes **all** pending rows and invalidates **all** ready
rows, regardless of their stored epochs, in bounded committed batches. It
clears both ready ciphertexts, preserves original prepared/audit metadata,
epochs and retention cutoffs, and releases exact old-byte/count credits. This
also covers a restored historical epoch reused as the selected current epoch;
there is no epoch-history registry. Phase expired can therefore mean recovery
invalidation as well as natural code expiry.

Before setting ready, a drained streaming validation checks all retained row
shapes and exact counts, requiring zero active rows and bytes. Its context is
bounded to 30 minutes, default 10 minutes when no parent deadline exists. Failed
validation remains unready; earlier committed cleanup is not undone and counter
mismatches are not silently repaired. Ordinary startup checks do not claim this
full retained-population validation. Draining and correct operator bindings
remain essential; reusing a historical Scope does not permanently fence a
historical process configured with those same values.
