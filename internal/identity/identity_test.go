package identity_test

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"privacy-proxy/internal/identity"
)

const tenant = "11111111-1111-1111-1111-111111111111"
const org = "22222222-2222-2222-2222-222222222222"
const group = "33333333-3333-3333-3333-333333333333"
const group2 = "44444444-4444-4444-4444-444444444444"
const oid = "55555555-5555-5555-5555-555555555555"
const azureIssuer = "https://login.microsoftonline.com/" + tenant + "/v2.0"
const holder = "did:iden3:polygon:amoy:123456789ABCDEFGH"
const azureActor = "ops:p1:h8r51EkUOmId9V9QsfRAB4s2CDMR3omEQA4OG8icGig"
const privadoActor = "ops:p1:YJi2G0ot_md1qvCZnNv3QI3Ow8n1RQ8zk0dYhw9dh3M"
const now = int64(1800000000)

type groupIndex struct {
	calls int
	deny  bool
}

func (g *groupIndex) HasGroup(o, id string) bool {
	g.calls++
	return !g.deny && o == org && (id == group || id == group2)
}
func raw(t *testing.T, v any) []byte {
	t.Helper()
	b, e := json.Marshal(v)
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func privateKey() ed25519.PrivateKey { return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, 32)) }
func fixture() identity.SourceCatalog {
	profiles := []identity.Profile{
		{ID: "azure", Kind: identity.AzureHuman, TenantID: tenant, Issuer: azureIssuer, APIAudience: "77777777-7777-7777-7777-777777777777", ClientID: "88888888-8888-8888-8888-888888888888", DelegatedScope: "api://77777777-7777-7777-7777-777777777777/access", FactSource: "appRoles"},
		{ID: "service", Kind: identity.AzureService, TenantID: tenant, Issuer: azureIssuer, APIAudience: "77777777-7777-7777-7777-777777777777", AllowedClientIDs: []string{"88888888-8888-8888-8888-888888888888"}, FactSource: "groupIds"},
		{ID: "did", Kind: identity.PrivadoIdentity, VerifierID: "did:iden3:polygon:amoy:987654321ABCDEFGH", Network: "polygon:amoy", IdentityStateContract: "0x1111111111111111111111111111111111111111"},
		{ID: "role", Kind: identity.PrivadoRole, VerifierID: "did:iden3:polygon:amoy:987654321ABCDEFGH", Network: "polygon:amoy", IdentityStateContract: "0x1111111111111111111111111111111111111111", AllowedCredentialIssuers: []string{holder}, ContextDigest: "sha256:" + strings.Repeat("a", 64), Context: "https://example.test/context", Type: "BankRole", CircuitID: "credentialAtomicQuerySigV2", Predicates: []identity.Predicate{{ID: "banker", Field: "role", Operator: "eq", Value: "7"}}},
	}
	return identity.SourceCatalog{APIVersion: identity.APIVersion, Kind: identity.CatalogKind, Issuers: []identity.Issuer{{ID: "ops", Issuer: "https://ops.test", Audience: "ops-core", Keys: []identity.PublicKey{{Kid: "k1", Alg: "EdDSA", Kty: "OKP", Crv: "Ed25519", X: base64.RawURLEncoding.EncodeToString(privateKey().Public().(ed25519.PublicKey))}}, AllowedProfiles: []string{"azure", "service", "did", "role"}}}, Profiles: profiles, Mappings: []identity.Mapping{
		{ID: "read", ProfileID: "azure", OrganizationID: org, PrincipalKind: identity.Human, Fact: identity.Fact{Kind: "azure.role", Value: "Reader"}, GroupIDs: []string{group}},
		{ID: "service", ProfileID: "service", OrganizationID: org, PrincipalKind: identity.Service, Fact: identity.Fact{Kind: "azure.group", Value: group}, GroupIDs: []string{group2}},
		{ID: "role", ProfileID: "role", OrganizationID: org, PrincipalKind: identity.Human, Fact: identity.Fact{Kind: "privado.predicate", Value: "banker"}, GroupIDs: []string{group}},
	}}
}
func compile(t *testing.T, s identity.SourceCatalog, l identity.Limits) *identity.Catalog {
	t.Helper()
	c, e := identity.Compile(s, &groupIndex{}, l)
	if e != nil {
		t.Fatal(e)
	}
	return c
}
func claims(t *testing.T, c *identity.Catalog, id string) map[string]any {
	d, _ := c.ProfileDigest(id)
	m := map[string]any{"iss": "https://ops.test", "aud": "ops-core", "sub": azureActor, "jti": "request-1", "iat": now, "nbf": now, "exp": now + 300, "principal_kind": "human", "source_profile": id, "source_profile_digest": d, "identity_authority": azureIssuer, "source_subject": oid, "source_tenant": tenant, "source_verified_at": now, "claims_as_of": now, "source_not_after": now + 3600, "facts": []identity.Fact{{Kind: "azure.role", Value: "Reader"}}}
	if id == "did" || id == "role" {
		m["sub"], m["identity_authority"], m["source_subject"] = privadoActor, "privado", holder
		delete(m, "source_tenant")
		delete(m, "source_not_after")
		m["facts"] = []identity.Fact{}
		if id == "role" {
			m["facts"] = []identity.Fact{{Kind: "privado.predicate", Value: "banker"}}
		}
	}
	return m
}
func signRaw(t *testing.T, h, p []byte, key ed25519.PrivateKey) string {
	t.Helper()
	encoded := base64.RawURLEncoding.EncodeToString(h) + "." + base64.RawURLEncoding.EncodeToString(p)
	signature, e := jwt.SigningMethodEdDSA.Sign(encoded, key)
	if e != nil {
		t.Fatal(e)
	}
	return encoded + "." + base64.RawURLEncoding.EncodeToString(signature)
}
func token(t *testing.T, c map[string]any) string {
	return signRaw(t, raw(t, map[string]any{"typ": "ops-access+jwt", "alg": "EdDSA", "kid": "k1"}), raw(t, c), privateKey())
}
func verifier(t *testing.T, c *identity.Catalog) *identity.Verifier {
	t.Helper()
	v, e := identity.NewVerifier(c, func() time.Time { return time.Unix(now, 0) })
	if e != nil {
		t.Fatal(e)
	}
	return v
}
func denied(t *testing.T, v *identity.Verifier, s string) {
	t.Helper()
	p, e := v.VerifyAccess(s)
	if e == nil || p != nil {
		t.Fatal("unexpected assertion grant", p, e)
	}
	if _, ok := e.(*identity.Error); !ok {
		t.Fatalf("untyped error %T", e)
	}
}

func TestCatalogMappingActorGoldensAndImmutableOwnership(t *testing.T) {
	s := fixture()
	index := &groupIndex{}
	c, e := identity.Compile(s, index, identity.DefaultLimits())
	if e != nil {
		t.Fatal(e)
	}
	initialCalls := index.calls
	index.deny = true
	v := verifier(t, c)
	p, e := v.VerifyAccess(token(t, claims(t, c, "azure")))
	if e != nil {
		t.Fatal(e)
	}
	if p.ActorID() != azureActor || p.Kind() != identity.Human || !slices.Equal(p.Groups(org), []string{group}) || len(p.Groups("unknown")) != 0 {
		t.Fatal("actor or group mapping differs")
	}
	if d, _ := c.ProfileDigest("azure"); d != "sha256:aa9862994a6871b6631758d3ee124e8ac69454decda0fbc7200c0b9f933b9b1b" {
		t.Fatal("profile canonical encoding changed", d)
	}
	for _, id := range []string{"did", "role"} {
		principal, e := v.VerifyAccess(token(t, claims(t, c, id)))
		if e != nil || principal.ActorID() != privadoActor {
			t.Fatal("Privado golden changed", e)
		}
		if id == "did" && len(principal.Groups(org)) != 0 {
			t.Fatal("identity-only received role grant")
		}
	}
	// Mutating callers/getters cannot replace the verified key or a mapping.
	s.Issuers[0].Keys[0].X = "changed"
	s.Mappings[0].GroupIDs[0] = group2
	s.Profiles[0].FactSource = "groupIds"
	detached := c.Source()
	detached.Issuers[0].Keys[0].X = "changed"
	detached.Mappings[0].GroupIDs[0] = group2
	detached.Profiles[0].ID = "changed"
	p.Facts()[0].Value = "Admin"
	p.Groups(org)[0] = group2
	if !slices.Equal(p.Groups(org), []string{group}) || index.calls != initialCalls {
		t.Fatal("runtime touched mutable source/group callback")
	}
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for range 25 {
				p.Groups(org)
				p.Facts()
				c.Source()
				if _, e := v.VerifyAccess(token(t, claims(t, c, "azure"))); e != nil {
					t.Error(e)
				}
			}
		})
	}
	wg.Wait()
	// Current mappings, not a token's precomputed group IDs, define each revision.
	changed := fixture()
	changed.Mappings[0].GroupIDs = []string{group2}
	next := compile(t, changed, identity.DefaultLimits())
	sameToken := token(t, claims(t, c, "azure"))
	nextPrincipal, e := verifier(t, next).VerifyAccess(sameToken)
	if e != nil || !slices.Equal(nextPrincipal.Groups(org), []string{group2}) {
		t.Fatal("mapping revision did not govern existing verified facts", e)
	}
	renamed := fixture()
	renamed.Profiles[0].ID = "renamed"
	renamed.Issuers[0].AllowedProfiles[0] = "renamed"
	renamed.Mappings[0].ProfileID = "renamed"
	renamedCatalog := compile(t, renamed, identity.DefaultLimits())
	renamedClaims := claims(t, renamedCatalog, "azure")
	renamedClaims["source_profile"] = "renamed"
	renamedClaims["source_profile_digest"], _ = renamedCatalog.ProfileDigest("renamed")
	renamedPrincipal, e := verifier(t, renamedCatalog).VerifyAccess(token(t, renamedClaims))
	if e != nil || renamedPrincipal.ActorID() != azureActor {
		t.Fatal("profile rename changed actor", e)
	}
	permuted := fixture()
	slices.Reverse(permuted.Profiles)
	slices.Reverse(permuted.Mappings)
	slices.Reverse(permuted.Issuers[0].AllowedProfiles)
	if compile(t, permuted, identity.DefaultLimits()).Digest() != c.Digest() {
		t.Fatal("source order changed canonical catalog digest")
	}
	if !reflect.DeepEqual(c.Source(), compile(t, fixture(), identity.DefaultLimits()).Source()) {
		t.Fatal("source mutation reached catalog")
	}
}

func TestTenantAndPrincipalNamespacesRemainDistinct(t *testing.T) {
	s := fixture()
	second := s.Profiles[0]
	second.ID = "second"
	second.TenantID = "66666666-6666-6666-6666-666666666666"
	second.Issuer = "https://login.microsoftonline.com/" + second.TenantID + "/v2.0"
	s.Profiles = append(s.Profiles, second)
	s.Issuers[0].AllowedProfiles = append(s.Issuers[0].AllowedProfiles, "second")
	m := s.Mappings[0]
	m.ID, m.ProfileID, m.GroupIDs = "second", "second", []string{group2}
	s.Mappings = append(s.Mappings, m)
	c := compile(t, s, identity.DefaultLimits())
	v := verifier(t, c)
	other := claims(t, c, "azure")
	other["source_profile"] = "second"
	other["source_profile_digest"], _ = c.ProfileDigest("second")
	other["source_tenant"], other["identity_authority"], other["sub"] = second.TenantID, second.Issuer, "ops:p1:OmUa3RJAC7NhHjfK2MOUkUXKX8aoZUyE7ydfvMY39d4"
	p, e := v.VerifyAccess(token(t, other))
	if e != nil || p.ActorID() == azureActor || !slices.Equal(p.Groups(org), []string{group2}) {
		t.Fatal("same oid collapsed across tenants", e)
	}
	other["source_tenant"] = tenant
	denied(t, v, token(t, other))
	service := claims(t, c, "service")
	service["principal_kind"], service["sub"], service["facts"] = "service", "ops:p1:HQsEa6-MJcWNRjgO428iV8-o-jtdvqnaijNqLT38oug", []identity.Fact{{Kind: "azure.group", Value: group}}
	p, e = v.VerifyAccess(token(t, service))
	if e != nil || p.Kind() != identity.Service || !slices.Equal(p.Groups(org), []string{group2}) {
		t.Fatal("service profile binding failed", e)
	}
	service["principal_kind"] = "human"
	denied(t, v, token(t, service))
}
