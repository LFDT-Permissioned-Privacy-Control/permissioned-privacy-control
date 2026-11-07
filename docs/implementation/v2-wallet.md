# Operational wallet links

V2 wallet management retains user challenge/sign/link, own-wallet listing,
unlinking and optional ENS refresh. It stores operational proofs and revocations
in PostgreSQL. It reads no user, group or configuration tables and creates no
user directory API. A wallet link supplies neither membership nor permission to
execute a method.

A new link requires an EOA signature over a server-generated EIP-191 message.
That records a wallet association proved **at link time**; it does not prove
exclusive or continued key ownership, or authorship of every transaction from
that address. Submitting raw signed transaction bytes creates no ownership link.
The same wallet can be independently proved by multiple authenticated actors.

## Message and identity

`walletops.New` binds verification to one selected immutable policy bundle. Its
trusted `ServiceBinding` environment and decimal chain ID must match that same
bundle. Origin, genesis hash and deployment ID are explicit trusted assembly
inputs; they are not inferred from request headers or asserted to be present in
the existing bundle metadata. All replicas must select the same binding and
operational state.

The stable namespace is SHA-256 over uint32 big-endian length-prefixed UTF-8
fields, in order: `ops.wallet.namespace/v1`, exact HTTPS service origin,
environment, decimal chain ID, lower-case `0x` genesis hash and deployment ID.
The external form is `sha256:` plus 64 lower-case hex digits. Image or policy
revision changes do not enter this namespace. Changing a binding field selects
a different namespace; it does not migrate links or remove revocations.

The exact UTF-8 message uses LF separators, no final LF, and these lines:

```text
OPS wallet link v1
Service: <configured exact HTTPS origin>
Network: <stable namespace>
Actor: <verified canonical ops:p1: ActorID>
Address: <lower-case 0x address>
Nonce: <64 lower-case hex digits>
IssuedAt: <UTC RFC3339 whole seconds>
ExpiresAt: <UTC RFC3339 whole seconds>

I authorize this wallet to be linked to this OPS identity. This does not authorize a transaction.
```

The server supplies the message; verification accepts no caller-provided message.
Challenges bind address, ActorID, namespace, recovery generation, issuance and
five-minute expiry. Cryptographic nonces have 32 random bytes. V2 requires a
65-byte signature with recovery ID 0/1 or 27/28, valid nonzero scalars and low S.
EIP-1271 contract-wallet signatures are not part of this EOA flow.

EIP-191 hashing and recovery are factored into `walletproof`. Legacy auth
wrappers retain their decoder, errors and behavior, including the old recovery
boundary; V2's stricter entrypoint is separate. Hashing uses UTF-8 **byte** length
and has parity fixtures against the pinned go-ethereum `accounts.TextHash`.
The production proof package imports no accounts, core transaction or VM code.

## HTTP operations

All five operations require the selected bundle's verified local OPS assertion.
An authenticated identity with no mapped group can manage its own proofs; it
gains no execution rights by doing so. No request selects another ActorID.

| Method | Path | Body / result |
| --- | --- | --- |
| POST | `/api/v2/eth/link/challenge` | `{address}` → `{nonce,message,expiresAt}` |
| POST | `/api/v2/eth/link/verify` | `{nonce,address,signature}` → `{address,status:"linked"}` |
| GET | `/api/v2/eth/addresses` | Own active proofs: `[{address,verifiedAt,proofVersion:2}]` |
| DELETE | `/api/v2/eth/addresses/{address}` | `{address,status:"revoked"}` |
| POST | `/api/v2/eth/addresses/{address}/refresh-ens` | Own active proof → `{address,ensName}` |

Addresses must be exactly `0x` plus 40 hex digits. Lower, checksum and mixed case
parse to the same 20 bytes; output and messages use lower case. This parser does
not claim to validate EIP-55 checksums. ActorIDs remain case-sensitive. Nonces
are exactly 64 lower-case hex digits, signatures `0x` plus 130 hex digits.

JSON is limited to 8 KiB and depth 16; duplicate, wrong-case, unknown and null
fields reject. Query parameters are unsupported. The three bodyless operations
reject nonempty bodies; HEAD does not execute GET. Responses are `no-store` and
limited to 1 MiB. Errors contain no proof, DSN or other actor's data: 400 invalid
input, 401 invalid/expired assertion, 404 no own link, 409 conflicting or consumed
state, and 503 unavailable operational dependency.

ENS is optional display metadata, never permission evidence. Its adapter must
honor the supplied deadline and return a name no longer than 255 UTF-8 bytes,
forward-confirmed to the same wallet. Unknown own links return 404 before a
provider lookup; absent/failing/unconfirmed providers return 503. Own listing
does not trigger a provider lookup per wallet. Provider caching and the actual
wallet UI are separate assembly consumers of these interfaces.

## Transactions, limits and retries

Every mutation takes the same per-actor PostgreSQL transaction advisory lock.
Its two signed int32 arguments are the first eight SHA-256 bytes of the uint32
big-endian length-prefixed tuple `ops-wallet-actor-lock/v1`, raw namespace bytes
and exact ActorID bytes. A hash collision only serializes unrelated actors; all
queries still compare full namespace and ActorID. No directory/lock rows exist.

Issuance deletes at most eight expired own challenges, then enforces at most
eight outstanding rows, including expired or old-generation rows. Old-generation
challenges are unusable and may occupy capacity until their five-minute expiry.
There can be at most 4,096 link rows per actor, **including revocations**. A
revoked actor/wallet pair cannot self-link again. This retains V1's permanent
unlink behavior; there is no public revive or administrator-directory endpoint.

Verification consumes the bound challenge with `DELETE ... RETURNING`, verifies
the signature, and inserts the first proof in one transaction. Invalid proof or
commit failure rolls back consumption. A fresh valid challenge for an already
active pair consumes that challenge without rewriting the original proof/time.
A lost successful response can therefore leave a committed link: retrying the
consumed nonce returns 409, and authenticated own-list confirms current state.
Unlink is monotonic and idempotent. No exactly-once HTTP delivery is claimed.

Token liveness is checked before mutation, at callback completion and immediately
before output. A token can expire after commit and suppress the success body;
that does not undo the committed operation. Each operation has a five-second
context; SQL statements have three-second timeouts and transaction locks one
second. Failure cleanup has its own one-second deadline. A full server still
needs I/O deadlines, request/concurrency limits and bounded external adapters.

Optional SIEM events use a borrowed bounded channel and nonblocking send after
commit. Nil/full channels drop events. Events contain actor, wallet, action and
time, with no signature/message or collision identities. They describe a
committed operation, not client receipt. They are best effort as in V1, with no
new durable audit table or audit-write availability requirement. Assembly must
drain handlers before closing its event producer lifecycle.

## SQL and recovery

Dedicated schema `ops_wallet_v2` has two application tables: `wallet_links` and
`wallet_challenges`. `schema_version` and `store_state` are offline metadata.
Links contain an immutable first proof, or an explicitly nonauthorizing
`legacy_revoked` tombstone. A trigger forbids proof/identity mutation and revival;
revocation time can only move earlier when reconciling historical evidence.

Application credentials have SELECT/INSERT on links, UPDATE only on
`revoked,revoked_at`, SELECT/INSERT/DELETE on challenges and SELECT on metadata.
The reader role sees only ownership-query columns and state/version. Retention
can read challenge keys/expiry and delete challenges; it cannot delete links.
Offline credentials own DDL and readiness changes. Startup checks schema
version/checksum, column shape, trigger and effective grants, including inherited
and column-only rights; owner, broad legacy and excess mutation credentials
reject. An empty DSN rejects instead of falling back to ambient PostgreSQL
settings. Pools cap at eight connections.

The SQL writer, service, DBA and backup/restore process remain trusted. Forged
proof rows or lost revocations can affect privacy; signatures on insertion and
file policy do not make operational SQL tampering harmless. Active reads validate
bounded projected facts and trust the approved writer, without redoing thousands
of signature recoveries per request.

The stable namespace retains all links and tombstones during recovery. A separate
UUID generation invalidates challenges. Runtime also requires an expected
revocation-coverage digest selected **outside the restored database**. Every
query/transaction checks ready state and exact generation/coverage; absence or
mismatch fails, including for an actor with zero links.

Use `cmd/ops-v2-wallet-migrate` with an explicit `--dsn-env NAME`, never a DSN CLI
argument. The tool neither prints the value nor runs at application startup:

1. `migrate --app-role ROLE --reader-role ROLE --retention-role ROLE` applies the
   embedded schema with pre-existing distinct roles.
2. For a genuinely new installation, `bootstrap-empty` with the full binding and
   generation creates a previously absent namespace using the distinguished
   `SHA256("ops.wallet.empty-source/v1")` coverage. It refuses an existing namespace.
3. For migration/recovery, drain **all** replicas. `begin-recovery` with full
   binding/new generation creates or marks the namespace unready, preserving links.
4. `import-revocations --file PATH --sha256 sha256:...` with binding/generation
   imports bounded batches while unready. Each batch is one transaction, at most
   16 MiB / 100,000 aliases and revocations. Unknown aliases, wrong namespace,
   noncanonical fields or conflicts abort it. Repeated imports are idempotent;
   existing proofs are only revoked, never rewritten or promoted.
5. Reconcile **all** source/backup revocations. `finalize --generation UUID
   --coverage-digest sha256:... --acknowledge-complete` with the full binding
   validates stored link shapes and publishes the operator's completeness
   attestation. Select those same expected values in every serving replica.

The closed import object is `{apiVersion:"ops.wallet-revocations/v1",
kind:"WalletRevocationBatch",namespace,sourceExportDigest,aliases,revocations}`.
Each alias explicitly attests legacy subject → canonical ActorID with evidence
digest, identity authority, source tenant and human/service kind.
Alias families are Azure's exact v2 tenant issuer with that same canonical tenant
UUID and human/service kind, or exact `privado` with empty tenant and human kind.
This checks structural scope; it does not recompute the actor or verify the truth
of an operator's identity attestation.
Each revocation
has that exact legacy subject, canonical lower-case address and UTC whole-second
`revokedAt`. Multiple verified aliases for one actor/wallet keep the earliest
revocation. The tool cannot prove that the source export included every absent
row; completeness is an explicit trusted operator responsibility. Restoring an
old database **and** reusing its old trusted runtime configuration cannot be
detected automatically.

Legacy system links and unverifiable message-hash/signature rows do not become
new ownership. Users make one fresh V2 proof. Old revoked pairs need verified
offline identity aliases and complete tombstone import before an existing
installation serves. Missing alias/coverage is a migration blocker, not permission
to discard a revocation or guess an actor from a tenantless subject.

`RetentionFromEnv` accepts `RETENTION_WALLET_CHALLENGES_CLEANUP_INTERVAL` and
`RETENTION_WALLET_CHALLENGES_CLEANUP_BATCH`, default one minute / 1,000 rows.
`CleanupOnce` has a five-second total context. No age-based deletion removes
wallet ownership or permanent revocations; retirement of an entire namespace is
an explicit operator operation. At 100K actors with five links each, 500K rows
would have about 2 GiB of message/signature payload at the 4,096-byte message
ceiling, before indexes/MVCC/metadata. This is capacity arithmetic, not an SLO.

## Privacy adapter

`walletadapter.Resolver` implements the native request wallet interface through a
fresh bounded ownership query, with no cross-request Redis/memory rights cache.
A revoke committed before that query begins is absent. An already captured
snapshot may finish after unlink; no instantaneous fleet cancellation is claimed.
Snapshot version hashes the length-prefixed `ops-wallet-snapshot/v1` domain,
raw namespace, canonical generation UUID text, coverage digest, exact ActorID
and sorted unique active 20-byte addresses. Captured ownership changes therefore
change the version without a global counter. Evidence time is captured when the
store read completes. The digest identifies those facts; it is neither a proof
against trusted database tampering nor a guarantee against a later unlink.

Internal `ResolveRecipients` checks the raw maximum of 32 entries before any
query. ActorIDs remain exact. An address resolves only if exactly one active
user-proved actor owns the association; unknown/ambiguous addresses return a
conflict, and callers can supply the explicit ActorID. The immutable result stores
ActorIDs at admission, so a future wallet owner does not acquire old shares.
There is no public reverse-lookup/list/search route. Calling code must still
authorize the send, read profile and visibility rules; this adapter grants none.

Current wallet association alone does not establish historical data organization
or actor authorship. Those consumers require their own verified admission/record
provenance and current policy. These routes do not implement transaction
broadcast, automatic sender linking or protected disclosure data reads.

## Verification

```sh
go test -race ./internal/walletproof ./internal/walletops ./internal/walletadapter ./internal/wallethttp ./internal/operational/walletsql ./cmd/ops-v2-wallet-migrate
go test ./internal/archtest
```

The PostgreSQL protocol test owns and removes a loopback-only PostgreSQL 16
container. It exercises actual HTTP, verified JWTs, real EOA signatures and two
independent pools, including one-use races, caps, commit failure, expiry before
output, revocation, shared-wallet audiences, roles, restore/import and retention.
