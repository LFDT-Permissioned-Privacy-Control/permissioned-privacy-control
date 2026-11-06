# Local assertion verification and identity catalog

`internal/identity` is a pure library for approved public trust, source profiles,
verified facts and mappings to OPS groups. It verifies short OPS access
assertions locally. It does not implement login, a provider verifier, broker,
session/refresh storage, user directory or a production authorization consumer.
Existing server authentication remains unchanged.

The closed `ops.identity-catalog/v1alpha1` document contains `apiVersion`,
`kind: IdentityCatalog`, `issuers`, `profiles` and `mappings`. Empty explicit
arrays express deny-all. Issuers contain only exact issuer/audience/public
Ed25519 keys and the source profiles they may assert. Profiles are flat closed
variants: `azure-human/v1`, `azure-service/v1`, `privado-identity/v1` and
`privado-role-query/v1`. Variant fields cannot be mixed. The Azure profile pins
one public-cloud tenant/v2 issuer, own API UUID, client binding and role/group
fact source. The proposed role-query profile pins one context, issuer set,
credentialAtomicQuerySigV2 circuit and uint32 equality predicates. Parsing these
profiles does not qualify real Azure issuance or Privado proof behavior.

Mappings match profile, principal kind and exact typed fact value, then grant
the declared group IDs within the declared organization. Group references are
validated against the same immutable bundle. The compilation callback is
discarded; request-time mapping never consults a mutable group source. Roles
are case-sensitive, external group IDs are canonical UUIDs, and Privado facts
must name declared predicates. Unknown Azure values grant nothing. Identity-only
Privado assertions have no role facts or grant-producing mappings.

`catalog-identity/v1` is an explicit second bundle validation profile. It
requires one global manifest `identityCatalog: {path, sha256}` reference,
positive explicit `IdentityLimits` and the inferred `identity.claims/v1`
capability. The original foundation profile rejects that reference. The file
shares the selected manifest hash, flat regular-file rules, document count and
aggregate byte budget; it is not independently mutable authority. Both profiles
remain validation-only libraries, without a Ready flag or production switch.

Raw identity file SHA-256, canonical catalog digest and each source-profile
digest remain separate. Canonical typed JSON sorts catalog sets and uses fixed
struct field order. A profile digest includes its ID/kind and its applicable
public fields, without issuer signing keys or group mappings. Key or mapping
changes affect the catalog digest; profile changes invalidate assertions using
the previous profile digest. Getters return detached source and metadata copies.

Access assertions are exactly three canonical unpadded base64url segments, an
exact `{typ: ops-access+jwt, alg: EdDSA, kid}` header and closed integer-second
claims. The verifier accepts only approved local Ed25519 keys and checks issuer,
scalar audience, allowed source profile/digest, identity/tenant/kind, facts and
signature. It never fetches keys or accepts direct provider tokens, old HMAC
tokens, renewal handles, supplied OPS group lists or algorithm fallbacks.

The subject is `ops:p1:` plus base64url SHA-256 of uint32 big-endian
length-prefixed tuple components. Azure uses `(azure-v2, issuer, tid, oid, kind)`;
Privado uses `(privado, holderDID, human)`. Profile IDs and display names do not
form the actor ID. DID validation here checks a bounded exact ASCII
`did:(iden3|polygonid):blockchain:network:base58` shape and profile network only;
it does not establish checksum, holder proof or on-chain validity. Existing
wallet/history aliases are not migrated by this library.

Time checks require `claims_as_of <= source_verified_at <= iat`, `nbf <= iat`
and `exp <= min(iat+300, claims_as_of+300, known source expiry)`, with `exp > iat`.
Expiration has zero leeway. Future source/issuance timestamps may be at most
30 seconds ahead of the verifier: this explicitly permits up to 330 seconds
of local remaining lifetime for a clock-ahead issuer. Changing OPS `iat` cannot
reset old source age. Azure source expiry is required; identity-only Privado
does not invent credential expiry. The core trusts these signed source facts;
provider freshness and renewal must be established by separately qualified
broker adapters.

Token/header/payload bytes, depth, fact/value sizes and catalog/key/profile/
mapping/reference counts have explicit engineering limits checked before
typed construction or expansion. Valid signatures do not bypass caps. A
RequestPrincipal is immutable and request-scoped; consumers verify each new
request and use its expiry, rather than keeping a grant cache across catalogs.

Run the bounded checks with:

```sh
go test -race ./internal/identity ./internal/policybundle ./internal/strictjson ./internal/configuration
go test ./internal/archtest -run 'Test(IdentityDependencyBoundary|PolicyBundleDependencyBoundary|NativePolicyDependencyBoundary|DependencyDirection)$'
```
