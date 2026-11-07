# Privado sessions in the V2 broker

`identitybroker.NewMulti` and `identityhttp.NewMulti` compose the real Privado
provider with recipient-bound login, explicit identity confirmation and fresh
proof renewal. They require the separately selected `catalog-broker-multi/v1`
validation profile and an `ops.auth-broker/v1alpha2` source. The old `New`
constructors, source version and `BrowserAuthClient` remain Azure-only. Neither
constructor mounts itself in the legacy server or selects an RPC runtime.

## Approved inputs

SourceV2 keeps the existing issuer, signing-key ID, browser Origin, completion
URI, Azure bindings and renewal/encryption key references. It additionally
requires explicit `privadoProfiles`, `privadoNetworks` and `pinnedDocuments`
arrays. At least one Privado profile is selected; an empty Azure array is valid.
There are at most 64 selected profiles in total, eight required networks and
sixteen pinned documents. For example, the additional fields are:

```json
{
  "privadoProfiles": [{"profileId":"bank-role"}],
  "privadoNetworks": [{
    "network":"polygon:mumbai", "chainId":"80001",
    "stateContract":"0x1111111111111111111111111111111111111111",
    "rpcUrl":"https://state.example/rpc", "allowPrivate":false,
    "credential":{"fromEnv":"OPS_BROKER_PRIVADO_STATE","header":"Authorization"}
  }],
  "pinnedDocuments": [{
    "url":"https://schemas.example/bank-role.jsonld",
    "path":"role-context.json",
    "sha256":"sha256:<64 lowercase hex digits of the exact file>"
  }]
}
```

These illustrative network/address values are not deployment recommendations.
Each selected identity profile must already exist, be allowed by the OPS
issuer, and have the exact configured network/state contract. Credential-issuer
networks must also be supplied. The identity catalog defines the verifier DID,
allowed credential issuers, context/type and required equality predicates;
neither a request nor a wallet can override them. See the
[provider contract](v2-privado-provider.md) for the supported circuits and limits.

The shared prepare/load compiler reads the named regular files, including these
nested references. It rejects symlinks, path escapes, duplicate/colliding paths,
hash mismatches, undeclared files and exceeded file/byte budgets. Pinned files
are capped at 1 MiB each and 2 MiB total and are copied into the prepared
artifact. The pure catalog never reads files, secrets or networks itself.
`SourceV1()` and `MultiSource()` expose explicit variants; legacy `Source()`
returns no projected V1 source for a V2 catalog. `CommonSettings()` contains
only detached shared public settings and key references.

Trusted assembly supplies exact resolved signing/MAC/encryption/RPC bindings.
NewMulti constructs one owned concrete provider from that same approved
snapshot, selected networks and captured pinned bytes. Its transport parameter
is trusted infrastructure, not a query/endpoint/document override. No public
constructor accepts arbitrary facts or a restored verifier-success flag.

## Login and renewal

The browser begins a login for a selected profile. It may explicitly select a
canonical expected holder DID. Otherwise the first valid public response only
creates a candidate: it cannot create a session or set cookies. The initiating
browser previews the full verified holder DID, network and configured profile,
then explicitly confirms that exact actor, holder and proof digest. Untrusted
DID display names are not identity confirmation. Rejecting means starting a new
flow; the helper never automatically confirms the first callback.

| Route | Request/result |
| --- | --- |
| POST `/api/v2/auth/privado/start` | `{profileId,expectedHolderDid?}` → `{requestId,requestUri,expiresAt,sourceProfile,expectedActorId}`; the last field is explicitly null when unknown |
| GET `/api/v2/auth/privado/requests/{id}` | Public immutable authorization JSON for a live canonical UUID |
| POST `/api/v2/auth/privado/proofs/{id}` | Original compact JWZ as raw `text/plain`, optionally UTF-8; known stored offer → HTTP 200 with an empty body |
| POST `/api/v2/auth/privado/preview` | `{requestId}` → closed `waiting` or `candidate`; no grant or cookie |
| POST `/api/v2/auth/privado/complete` | `{requestId,expectedActorId,expectedHolderDid,proofDigest,expectedSessionId?}` → existing human access DTO with `provider:"privado"` and cookies after known commit |

Waiting contains `status,requestId,sourceProfile,expiresAt`. Candidate adds
`holderDid,network,actorId,proofDigest,verifiedAt`. Its verifiedAt is the honest
callback observation; preview does not perform a new chain-state check. Public
requests ignore even malformed Cookie/Authorization headers, use the separate
proof DB role, and never read or mutate a family. Proof bodies are capped at
1 MiB; JSON wrappers and alternative media types reject.

Only the two public resource shapes emit `Access-Control-Allow-Origin: *`.
Cross-origin browser wallets must use `credentials:"omit"`. There is never
allow-credentials, reflected Origin or Set-Cookie on those routes. Route-local
OPTIONS permits only that route's GET or POST and absent/empty/content-type
requested headers. Private routes retain exact Host/Origin/cookie checks and
have no wildcard CORS. Global middleware must preserve that distinction.

An authenticated renewal handle selects the provider/profile. Existing
`POST renew` request shapes stay closed: bootstrap, or renew with the expected
actor/family pair. A live Privado family returns exactly:

```text
status=proof_required, provider=privado, principalKind=human, mode=renew,
requestId, requestUri, expiresAt, actorId, browserSessionId, sourceProfile
```

This outcome has no access token and sets zero cookies. It captures the SAME
family, actor, recipient, current generation and handle. Completion rotates
that family once; it never creates a new family or extends its original
seven-day cutoff. A wrong expected pair rejects before family/provider work.
An authenticated stale handle on the private renewal path retains permanent
replay revocation. A late public callback or completion merely denies; it must
not revoke the current family.

Both callback and completion use real AuthV2/SigV2 verification. Completion
decrypts and verifies the ORIGINAL compact response again through the SAME
owned current provider, outside SQL locks. Saved candidate metadata is never
proof authority. Original ClaimsAsOf and NotAfter are preserved; current second
SourceVerifiedAt may advance. Access expires by the earliest of now+300,
original source age, proof cutoff, flow expiry and family expiry. A replaced
GIST/nonrevocation state or unavailable current state denies issuance. Existing
Core clock tolerance and Guard v1 approval lifetimes/modes are unchanged.

## Operational persistence and failure boundaries

Schema2 keeps one provider-tagged family table with disjoint Azure and Privado
validation. Azure UUID/OIDC fields, ciphertext and v1 AAD/MAC bytes are retained.
Privado has a canonical holder DID, no fictitious tenant/upstream refresh token,
and bounded encrypted continuity metadata. Changes to the selected profile,
source-auth digest or any of the four provider plan digests require explicit
fresh login for renewal. A runtime permission-only edit leaving those auth
inputs unchanged need not invalidate renewal. Existing access tokens retain
their normal bounded lifetime.

Separate immutable `privado_challenges` and `privado_offers` tables keep compact
protected request context and the encrypted original proof. All IDs, recipient,
capture fields, original times, profile and public plans are authenticated in
canonical payloads/AAD. Small ciphertexts are capped at 2 KiB; proof ciphertext
is at most 1 MiB plus 28 bytes of AES-GCM overhead. No roles or serialized grant
are restored from storage.

All Privado mutations and cascading retention take one namespace admission lock
first, followed by the existing family-capacity lock for creation, then a real
family row lock for renewal. Challenge/offer reads are plain immutable reads;
they require no UPDATE grant. Prepared effects and exact detached snapshots are
checked, the common family engine creates/rotates, and conditional parent
deletion consumes the challenge with proof cascade in the same transaction.
No RPC, Groth16 proving/verification, AEAD or signing occurs under these locks.
Current finite source/time/result checks run immediately before commit and
credential delivery. Unknown commit returns no reconstructable credentials.

Per selected deployment namespace the limits are 10,000 stored challenges,
64 stored offers AND 64 MiB of actual proof ciphertext. Counts include expired
and previous-epoch rows until deletion. Sixty-four maximum-size ciphers exceed
the byte cap by 1,792 bytes, so only 63 such ciphers fit. These are service
admission limits, not global disk limits across arbitrary operator-created
namespaces. The supported schema has one selected metadata namespace/epoch and
can serve several OPS workers. Metadata/index/WAL overhead is additional.

The private app role can read/insert/delete challenges and only read offers.
The public-proof role can read metadata/challenges and read/insert offers,
with zero family/Azure-pending access. Retention deletes parent challenges or
families; proof rows cascade without a direct child DELETE grant. No runtime
role can UPDATE child rows, change metadata, own schema objects, use other
application tables, or perform DDL. These credentials and the offline owner
remain operational trust; encryption does not make arbitrary SQL writes safe.

Startup checks the exact compiled PostgreSQL16 catalog, constraints/FKs,
indexes, triggers/function definitions/owners and effective table/column ACLs.
Every transaction checks schema version/checksum, namespace, epoch and readiness
both at entry and before commit. Full catalog checks occur at startup; the
drained offline owner is trusted for later DDL. Each operation is bounded to
20 seconds, SQL lock/statement waits to 1/2 seconds. The HTTP adapter also sets
real socket read/write deadlines; wrappers must expose `Unwrap`. Privado HTTP
and all other NewMulti auth work (including Azure, renew/bootstrap and logout)
share eight immediate slots owned by that Service across all its handlers.
Fixed public OPTIONS performs no provider/store work and is excluded; legacy
New retains its existing 32 slots. Actual provider verification has four. Host
servers still need finite header, idle and perimeter limits.

## Migration, restart and browser state

Run `ops-v2-identity-migrate migrate-v2` with explicit owner DSN reference,
namespace/epoch, app/proof/retention role names and `--acknowledge-drained`.
All three roles must already exist. The owner commits readiness=false before
the additive upgrade, installs schema2/ACLs atomically while unready, validates
the known shape and retained state, then separately enables readiness. The
whole operation has a 60-second bound. A crash leaves an exact known unready
state for explicit rerun. No worker performs migration. Legacy `migrate-v1`
only prepares001; it cannot label an existing schema2 installation as v1.

New image with schema1 and old image with schema2 are unready. New image with
an old Azure source on migrated schema2 is supported, including existing
ciphertext/MAC/AAD. Roll back the bundle on a compatible image; do not assume
the old image can use the upgraded schema. Backup restore requires draining,
a NEW externally selected recovery epoch, and clearing pending/challenge/offer/
family state before readiness. Normal restart retains the epoch and may restore
a sealed original flow, but completion still re-verifies it.

`NewMultiClient` shares the existing origin lock and transport while using an
explicit version2 marker, at most 2 KiB. It stores only provider/profile,
actor/family and a bounded PUBLIC request UUID/mode/expiry/capture. It stores no
token, proof, roles, secret nonce or holder DID. Live flow UUIDs survive reload
and are reused across tabs without creating another renewal request. Only a
truly absent marker with no remembered identity may bootstrap. Existing
hard-denied state never silently bootstraps. Wallet waiting occurs outside Web
Locks; preview and confirmation use short locked operations. Confirmation
consumes the exact local continuation BEFORE its final POST. Unknown response,
failed storage or context mismatch leaves denied state with no automatic retry.

## Local qualification

With the installed pinned dependencies, public circuit artifacts, Node24,
Chrome and cached PostgreSQL16 image:

```sh
OPS_PRIVADO_WALLET_INTEGRATION=1 go test -race -tags=prover_disabled \
  ./internal/operational/identitysql -run '^TestActualPrivadoWallet' -count=1
OPS_BROWSER_INTEGRATION=1 OPS_PRIVADO_WALLET_INTEGRATION=1 \
  go test -race -tags=prover_disabled ./internal/operational/identitysql \
  -run '^TestActualPrivadoTwoTabBrowser$' -count=1 -timeout=240s
```

The owned fixture uses actual JS SDK1.43, new explicitly public test identities,
real W3C role credentials/Merkle trees, actual AuthHandler/provers and pinned
verification keys. It tests first and subsequent freshly generated role proofs
from one long-lived populated cache, explicit proof-cache bypass and disabled
state caching. A deliberately reused inner proof keeps its old timestamp and
fails the production source-age gate. A real changed GIST rejects saved proof
at completion, while a new proof against the changed tree succeeds. The browser
qualification reaches real TLS, PostgreSQL, Core JWT verification, Web Locks,
two tabs/reload, explicit holder selection and committed-response loss.

This qualifies the local SDK/protocol fixture. It does not qualify a hosted
WebWallet deployment, a physical mobile wallet, arbitrary issuer provisioning,
or unattended five-minute user interaction. Fresh role proofs do not themselves
look up a bank's employee directory: withdrawal still requires the issuer's
revocation/reissue process and current chain state. Production mounting and
complete release composition must select and qualify those deployment inputs.
