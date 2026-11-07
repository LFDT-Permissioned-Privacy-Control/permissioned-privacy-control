# V2 Azure identity broker and renewal state

`internal/identitybroker` exchanges verified Azure evidence for the existing
`ops-access+jwt` assertion. Core still verifies those assertions locally through
`internal/identity`; it never queries the provider or a session/user directory.
`internal/identityhttp` adapts those operations to the browser and machine routes
described in [the HTTP contract](v2-identity-http.md). Production mounting and the
combined broker/RPC source profile require deliberate runtime composition.

## Approved source

The explicit `catalog-broker/v1` authoring profile accepts the existing identity
catalog plus an `authCatalog` manifest reference. `ops-v2 prepare` and the pinned
loader use the same compiler, exact raw hashes, document/byte limits and inferred
capabilities/secret references. Existing profiles reject the extension. This
standalone profile does not compose a running RPC server with authentication.

An `ops.auth-broker/v1alpha1` / `AuthBroker` document selects an existing OPS
issuer/public signing key, HTTPS web origin and same-origin completion URI, and
explicit Azure profile bindings. Human profiles provide an approved HTTPS
callback and an `OPS_BROKER_AZURE_*` secret reference. Service profiles provide
only their profile ID. This source version rejects Privado bindings.

Renewal HMAC and refresh-encryption keys each have one active key and at most one
retained key. The document contains only IDs and `OPS_BROKER_REFRESH_*` or
`OPS_BROKER_ENCRYPTION_*` references. Trusted assembly supplies actual material;
libraries do not read environment variables. HMAC keys are 32–128 bytes, AES keys
32 bytes, and material must differ across uses and from the Ed25519 signing
key/seed. The private signing key must match the approved public key. Key removal
can force affected sessions to log in again; keep a retained key for the intended
session window if that disruption is undesirable.

## Provider evidence and freshness

Human login uses the actual pinned `go-oidc` and `oauth2` libraries: authorization
code, S256 PKCE and a random nonce. The authorization request includes the full
approved API scope plus `openid profile email offline_access`. The scope URI's
terminal word is matched exactly against the verified access token's `scp`.
Initial login requires a signed ID token for the selected single client audience
and nonce, and a separate signed access token for the selected OPS API. Their
Azure `oid` and `tid` must match. Roles/groups come from the access token.

Every human renewal constructs a NEW refresh-only TokenSource and invokes its
grant once. A cached provider access token cannot satisfy renewal. The pinned
SDK omits `scope` on refresh, which retains the original grant under
[RFC 6749 §6](https://www.rfc-editor.org/rfc/rfc6749#section-6). Returned evidence
still must match the exact tenant, API audience, client, delegated scope and
persisted identity. Explicit `AuthStyleInParams` prevents an automatic retry
using a different client authentication style.

A refresh ID token is optional. If present, it must verify for the same client,
original OIDC subject and Azure identity. Its nonce, if present, must match the
original nonce hash. `auth_time` must match the original value when known, or be
no later than the original login otherwise. These values establish continuity,
not fresh membership. Missing selected roles/groups mean an empty fact list;
Azure group-overage indicators reject group-ID evidence and do not erase
independent app-role evidence. There is no Graph fallback or role cache.

Service exchange accepts only the selected own-API application token, expected
tenant, allowed client and `idtyp=app`, with no delegated scope. It creates no
renewal family. An old source token cannot be re-signed to obtain another five
minutes of authority.

Human assertion expiry is bounded by grant start +300 seconds, local issue time
+300 seconds and provider expiry. Service assertions additionally retain the
source token's original issue-time bound. The broker signs the shared exact
Core DTO and verifies it through the same Core verifier before returning it.
Existing verifier clock tolerance may produce up to 330 seconds of verifier-
relative exposure. New grants do not prove instantaneous Azure directory
replication; real tenant/group-overage/account behavior needs provider
qualification. Already-issued assertions and Guard v1 approvals retain their
documented lifetimes after logout.

Discovery/token/JWKS URLs are fixed Microsoft HTTPS endpoints derived from the
approved tenant. Production transport uses normal TLS, guarded DNS/dials, no
environment proxy and no redirects. Compact tokens are capped at 32 KiB, token
responses at 256 KiB, discovery at 64 KiB and JWKS at 256 KiB/32 keys before SDK
decoding. Only RS256 provider signatures are accepted. Individual operations
have a ten-second provider deadline and finite connections. The pinned OIDC
library can fetch keys through a background singleflight: its explicit HTTP
timeout bounds that fetch; caller cancellation does not necessarily terminate
the SDK's background fetch immediately. Signing-key caching is intentional.

## Operational SQL, without user rows

`internal/operational/identitysql` is the named PostgreSQL adapter. Its
`ops_identity_v2` schema has two application tables:

- `pending_requests`: one-use state hash, encrypted nonce/PKCE, approved profile
  digest, recipient hash and a maximum five-minute expiry.
- `renewal_families`: one bounded row per login, canonical ActorID and Azure
  identity, encrypted provider refresh token, current handle hash/generation,
  original ID-token continuity hashes, recipient hash, revocation and an
  absolute seven-day lifetime. No memberships or provider access tokens.

The singleton metadata records exact schema checksum, stable deployment
namespace, expected recovery epoch and readiness. There are no foreign keys to
users, groups, policy or legacy tables and no user list/search operation.

The recipient is a SHA-256 binding to a random initiating client secret supplied
by the trusted HTTP adapter. Public state/request IDs are not credentials.
Pending ciphertext and family ciphertext use separate versioned AES-GCM AAD
binding row identity, namespace/epoch, profile, recipient and key; family AAD
also binds generation/current handle and original OIDC continuity. Copying
encrypted material between rows cannot transfer authentication.

Completion atomically deletes the eligible pending row, exchanges ONE provider
code and inserts ONE family in the same transaction. Credentials become
available only after a known COMMIT. External provider code consumption cannot
be rolled back: provider/SQL failure may require a fresh login. No completion
response is reconstructed from stored rows.

Renewal locks precisely one family across the provider grant and rotation.
HS256 `ops-refresh+jwt` proof is verified before SQL access; the row must match
its immutable identity/expiry/epoch and recipient before decryption. An authentic
old generation, future generation or current-hash mismatch commits a permanent
revocation and then denies. Invalid MACs or recipients cannot revoke a selected
family. A concurrent duplicate renewal can therefore revoke the successor;
the HTTP/client adapter must serialize renewal and reauthenticate after an
uncertain result. Infrastructure failures roll back; ambiguity never yields
credentials or an automatic grant retry.

Fresh expiry checks run after real row-lock waits, after final SQL writes and
readiness checks immediately before COMMIT for credential issuance/rotation,
and again before credential delivery. Revocation commits do not depend on a
credential-publication gate. Login/renewal results are process-local opaque
values; callers must use `Credentials()` immediately before output. A credential
issued just before family expiry can remain valid for its bounded assertion
lifetime; family expiry blocks new renewal and late delivery.

Capacity is 10,000 unexpired pending requests and 100,000 active families per
dedicated store. Short capacity advisory locks cover indexed, limited counts
and insertion; the provider call is never made while holding a global capacity
lock. A separate pool has at most eight connections, twenty-second operations,
one-second SQL lock waits and two-second SQL statement limits. Rollback and offline connection close
use separate one-second cleanup contexts. Pool close waits for checked-out
operations, which have the explicit operation bounds above. These are engineering limits, not
measured throughput guarantees.

## Roles, recovery and retention

An offline schema owner runs `ops-v2-identity-migrate`. The application has
metadata SELECT; pending SELECT/INSERT/DELETE; family SELECT/INSERT and UPDATE
only for rotation/revocation columns. A trigger preserves identity, recipient,
absolute lifetime, monotonic generation and permanent revocation. Startup checks
exact columns/indexes/checksum, readiness/namespace/epoch and effective roles;
owner/superuser/foreign application-table privileges reject. Runtime never runs
DDL. PostgreSQL administrators, migration credentials and stored state are
trusted; encrypted tokens do not make a malicious database owner harmless.

The retention role has SELECT/DELETE on both application tables, with no INSERT,
UPDATE or metadata mutation. The trusted cleanup command deletes expired
pending rows and families only after absolute expiry +24 hours, at most 1,000
rows/five seconds per call. SQL grants do not impose those row predicates: a
compromised retention credential can delete active state and force logins.

Run `migrate`, then `bootstrap-empty` only for a fresh empty installation. For a
restore, drain ALL broker workers, select a NEW expected recovery epoch outside
the restored database, run `begin-recovery --acknowledge-drained`, then
`finalize --acknowledge-drained`, and start workers with that epoch. Finalization
clears old pending/family material before readiness. It is transactionally
repeatable if interrupted while unready; a failed finalization preserves the
unready state. Normal restart retains the epoch. Bundle rollback does not reset
it. An operator reusing an old restored epoch can defeat this safeguard; the
deployment process is trusted. The offline sixty-second operation bound is not
a qualification of a production-size restore.

Commands require an explicit `--dsn-env NAME` and explicit namespace/epoch
binding. Raw DSNs and provider/token details are omitted from errors/output.
`cleanup` takes the retention DSN; migration/recovery take the offline owner DSN.

## Remaining composition

The HTTP adapter and browser helper establish their own exact Origin, cookie,
recipient and serialized-renewal contracts. Privado proof verification,
enterprise OAuth resource delegation, Explorer/UI wiring, production mounting
and real Azure tenant/account qualification require separate composition.
A complete runtime must compose the broker and RPC profiles deliberately and
qualify its binary imports, credentials, recovery and deployment.
