# Enterprise SSO runtime

`internal/operational/ssohttp` composes the real multi-provider identity broker,
one complete selected Core snapshot, the approved first-party client catalog,
and the operational SSO transaction store. Core keeps no user or membership
rows. SSO returns the original verified human OPS access token; it creates no
new access token, refresh token, ID token or application-specific scope.

The existing Privado SDK lexically imports an unused native C proving utility.
An untagged broker/runtime build inherits its CGO requirement. Linux builds can
use `CGO_ENABLED=0` with the existing `-tags=prover_disabled`: this disables only
proving calls, which return errors, and retains the real Go Groth16 verifier.
SSO never generates a proof or substitutes a verification-success stub. See
[the provider build contract](v2-privado-provider.md). Core has no broker/SSO
dependency and builds separately without this tag.

An application trusted for this handoff receives a full Core bearer token,
including the actor's own-wallet authority. Its approved
`trustedOrganizationIds` must include **every** organization mapped for the
verified token, and its explicit allowed profile and eligibility rule must pass.
An empty list trusts only tokens mapping to zero organizations. It does not mean
all organizations. Group eligibility is an OR over the listed verified groups;
profile eligibility can explicitly admit a human with no mapped group.

## Startup

Owned assembly selects the immutable approved Core and broker snapshots and
compiles `ops.sso.clients/v1`. It opens the separate operational `ssosql.OpenApp`
store after offline owner migration/initialization. App and retention credentials
are distinct. `AppMetadata` checks the concrete pointer's local app role and
lifetime only; operations independently check actual catalog, ACL, readiness and
recovery scope. No runtime handler migrates or repairs a database.

The additional approved runtime JSON is strict and pinned by its raw SHA-256:

```json
{
  "apiVersion": "ops.sso.runtime/v1",
  "kind": "SSORuntime",
  "coreManifestDigest": "sha256:<selected Core manifest>",
  "brokerManifestDigest": "sha256:<selected broker manifest>",
  "clientCatalogDigest": "sha256:<compiled client catalog>",
  "contextKey": {"id": "sso-context", "fromEnv": "OPS_SSO_CONTEXT"},
  "grantKey": {"id": "sso-grant", "fromEnv": "OPS_SSO_GRANT"}
}
```

The placeholders above must be replaced by exact lowercase, nonzero digests.
Owned startup supplies key and client-secret bindings; the handler does not read
environment variables or accept runtime settings changes. The expected digest
proves selected bytes, not approval. Core, broker and clients must use the same
identity-catalog digest. The broker's actual source, origin, namespace and
recovery epoch must match the approved broker and the E0 store.

The two AES-256 keys have distinct IDs, references and material. Every selected
client secret is 32–256 visible ASCII bytes. All selected client secrets and SSO
keys must be disjoint in material and references, and disjoint from retained
broker MAC/AES keys and signing seed/private material. The broker retains private
AES equality fingerprints, with a fixed 32-byte key length, and exposes no key or
fingerprint getter. Missing, extra and repeated bindings fail startup.

## HTTP protocol

The owned server registers exactly these routes and supplies normal HTTPS
termination plus read/header/idle limits. The handler installs a real 20-second
read/write socket deadline, shortened by an earlier parent deadline. It shares
the actual broker's eight-slot, nonqueueing HTTP admission limit through output.
Total server headers must allow 64 KiB for supported bearer-plus-cookie inputs.
Forwarded headers never select an origin, host, provider or callback.

| Route | Behavior |
|---|---|
| `GET /api/v2/sso/authorize` | Requires exact configured client/callback, `response_type=code`, state and canonical S256 challenge. Inserts encrypted Pending state, waits for known COMMIT, then redirects only to the approved OPS `/auth/sso?flow=<UUID>`. |
| `POST /api/v2/sso/flow` with `action=inspect` | Requires exact central Origin/Host and recipient cookie. Returns only configured client label/ID, phase and original expiry. |
| `POST /api/v2/sso/flow` with `action=complete` | Also requires one original bearer, current actual MAC renewal cookie and expected actor/session pair. Checks the same Core View and read-only current broker family, prepares encrypted Ready state and callback, waits for known COMMIT, then rechecks before returning the callback URL. |
| `POST /api/v2/sso/token` | Backchannel form only, with no Origin or Cookie header. Authenticates the confidential client, checks the exact callback and S256 verifier, verifies the stored original JWT and current family, consumes once with known COMMIT, rechecks, then returns the original token. |

Unknown/duplicate fields, unsupported grants, `client_secret_post`, malformed
encodings and client/callback mixups fail closed. Private flow JSON is at most
2 KiB; authorize query and token form are each at most 8 KiB. Bearer tokens are
at most 16 KiB; renewal cookies at most 3,500 bytes; total cookies at most 16 KiB.
There is no credentialed CORS or browser consent/disclosure-approval step.
Provider login and supported-wallet proof confirmation remain authentication.

OAuth `client_secret_basic` has one exact decoding rule: one bounded Basic
header, strict canonical standard base64, first-colon split, then one
`url.QueryUnescape` per component. Decoded credentials must satisfy their bounded
grammars. Basic client ID must equal form `client_id` before any code lookup and
both Ready/context IDs before consumption. Secret comparison uses exact length
and constant-time SHA-256 equality. Clients call
`SetBasicAuth(url.QueryEscape(id), url.QueryEscape(secret))`. A literal secret
`%2B` is sent as `%252B`; it cannot authenticate another secret `+` through a
second decode. No raw-secret fallback exists.

## Current sessions and token age

The broker authenticates the actual MAC renewal handle before selecting a
family. The expected actor/session pair constrains that selection. Read-only
inspection uses existing `WithFamily`/`WithProviderFamily` and `DenyUnchanged`;
it never rotates or revokes an old handle. Because `DenyUnchanged` skips the
store's mutation gate, the broker requires known read COMMIT and an explicit
postgate. Bindings are opaque and owned by the exact Service instance.

SSO separately builds a live View from the original JWT and matches human actor,
profile and profile digest with the current family. The JWT has no family claim:
this proves a current family and matching live actor/profile, not that this JWT
was originally minted by that exact family generation. The returned JWT bytes,
ClaimsAsOf, source freshness and signed expiry are unchanged. `expires_in` is the
floor of the remaining original lifetime when the exact response is prepared.
A renewal cookie cannot reconstruct a new access token. A new central document
uses actual existing Azure renewal or requires a new actual Privado proof.

## Encryption, interruptions and recovery

Context and grant use separate AES-256-GCM purposes with a random 12-byte nonce
and 16-byte tag. Context AAD binds selected runtime source and every immutable
Pending field. Grant AAD additionally binds context ciphertext and every Ready
scalar, including code, actor/profile/family, current handle hash, original
access hash/expiry and exact prepared callback-response digest/size.

Encrypted JSON uses `SetEscapeHTML(false)`; quote/backslash escaping and the
encoder newline remain counted. Maximum legal combined context inputs use
3,278 ciphertext bytes within the 4,096-byte cap. Maximum grant ciphertext is
19,956 bytes within 24,576. Public response JSON keeps ordinary HTML escaping;
maximum original-token response is 16,443 bytes within 24 KiB.

The E0 store uses state-first locking, exact scoped CAS, fixed expiry/retention
and one-use consumption. A known E0 COMMIT is required before any code/token
output, followed by a fresh actual family read and local View/expiry gate.
No identity lock spans an E0 transaction, provider operation, wallet interaction
or socket write. A failed/uncertain COMMIT or a postcommit gate failure returns
no protected response. A durable Ready or Consumed effect can remain while its
response is withheld. There is no automatic action retry, re-signing, response
reconstruction or age reset; the browser starts a new flow.

Identity currentness is sampled at these boundaries. There is no atomic
cross-database logout/socket fence, and a delivered Core token retains its
original expiry window after logout. Ordinary restart with the same approved
sources, keys and epochs retains original flow expiry. Changed source/key
selection invalidates old capsules; operators drain/recover the SSO scope and
start new flows. The store's offline recovery controls retain their existing
semantics.

Ready/Consumed rows attest prepared grant/token operations and bounded response
digests, not socket delivery. Fixed redacted rejection logs include no code,
state, verifier, secret, JWT, cookie, raw query/body or upstream diagnostic.
There is no complete durable ledger of all malformed authentication attempts.

The component supplies neither an application BFF session store nor mounted
central frontend pages. Those callers must bind browser state/PKCE, retain the
original token expiry, support top-level continuation and use the existing
Azure/Privado authentication flows. A token cookie, raw Basic arguments, or an
unverified identity fallback is not a compatible adapter.
