package ssopolicy

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"privacy-proxy/internal/identity"
	"strings"
	"testing"
)

const org = "11111111-1111-4111-8111-111111111111"
const group = "22222222-2222-4222-8222-222222222222"

type refs struct {
	calls int
	deny  bool
}

func (r *refs) Organization(o string) bool { r.calls++; return !r.deny && o == org }
func (r *refs) Group(o, g string) bool     { r.calls++; return !r.deny && o == org && g == group }
func (r *refs) HasGroup(o, g string) bool  { return r.Group(o, g) }
func identities(t *testing.T) *identity.Catalog {
	t.Helper()
	p := []identity.Profile{{ID: "azure", Kind: identity.AzureHuman, TenantID: org, Issuer: "https://login.microsoftonline.com/" + org + "/v2.0", APIAudience: group, ClientID: org, DelegatedScope: "api://" + group + "/access", FactSource: "appRoles"}, {ID: "did", Kind: identity.PrivadoIdentity, VerifierID: "did:iden3:polygon:amoy:987654321ABCDEFGH", Network: "polygon:amoy", IdentityStateContract: "0x1111111111111111111111111111111111111111"}, {ID: "service", Kind: identity.AzureService, TenantID: org, Issuer: "https://login.microsoftonline.com/" + org + "/v2.0", APIAudience: group, AllowedClientIDs: []string{org}, FactSource: "groupIds"}}
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x51}, 32)).Public().(ed25519.PublicKey)
	s := identity.SourceCatalog{APIVersion: identity.APIVersion, Kind: identity.CatalogKind, Issuers: []identity.Issuer{{ID: "ops", Issuer: "https://ops.test", Audience: "ops-core", AllowedProfiles: []string{"azure", "did", "service"}, Keys: []identity.PublicKey{{Kid: "fixture", Alg: "EdDSA", Kty: "OKP", Crv: "Ed25519", X: base64.RawURLEncoding.EncodeToString(key)}}}}, Profiles: p, Mappings: []identity.Mapping{}}
	c, e := identity.Compile(s, &refs{}, identity.DefaultLimits())
	if e != nil {
		t.Fatal(e)
	}
	return c
}
func source() Source {
	return Source{APIVersion, Kind, []ClientSource{{ID: "explorer", DisplayName: "Bank Explorer", Authentication: "client_secret_basic", Secret: SecretRef{"EXPLORER_SECRET"}, TrustMode: "first-party-full-core-bearer", TrustedOrganizationIDs: []string{org}, EligibleGroups: []GroupRef{{org, group}}, Eligibility: GroupEligibility, AllowedProfiles: []string{"azure", "did"}, RedirectURIs: []string{"https://explorer.test/api/auth/callback"}}}}
}
func raw(v any) []byte {
	b, e := json.Marshal(v)
	if e != nil {
		panic(e)
	}
	return b
}
func TestExactCatalogAndOwnership(t *testing.T) {
	id := identities(t)
	r := &refs{}
	s := source()
	c, e := Compile(raw(s), id, r)
	if e != nil {
		t.Fatal(e)
	}
	before := r.calls
	r.deny = true
	x, _ := c.Client("explorer")
	v := x.Source()
	v.AllowedProfiles[0] = "service"
	v.TrustedOrganizationIDs[0] = "changed"
	all := c.Clients()
	all[0].source.ID = "changed"
	x, _ = c.Client("explorer")
	if x.Source().AllowedProfiles[0] != "azure" || r.calls != before || c.IdentityDigest() != id.Digest() {
		t.Fatal("not detached")
	}
	s.Clients[0].Eligibility = ProfileEligibility
	s.Clients[0].EligibleGroups = []GroupRef{}
	s.Clients[0].TrustedOrganizationIDs = []string{}
	if _, e = Compile(raw(s), id, &refs{}); e != nil {
		t.Fatal("explicit zero-org-only shape", e)
	}
	s.Clients[0].TrustedOrganizationIDs = nil
	if _, e = Compile(raw(s), id, &refs{}); e == nil {
		t.Fatal("null treated as empty")
	}
	var nilref *refs
	if _, e = Compile(raw(source()), id, nilref); e == nil {
		t.Fatal("typed nil")
	}
}
func TestClosedCatalogNegatives(t *testing.T) {
	id := identities(t)
	for name, edit := range map[string]func(*ClientSource){"trust default": func(c *ClientSource) { c.TrustMode = "" }, "ALL invented": func(c *ClientSource) { c.Eligibility = "all-listed-groups" }, "profile mixed groups": func(c *ClientSource) { c.Eligibility = ProfileEligibility }, "group empty": func(c *ClientSource) { c.EligibleGroups = []GroupRef{} }, "crossorg": func(c *ClientSource) { c.TrustedOrganizationIDs = []string{} }, "service": func(c *ClientSource) { c.AllowedProfiles = []string{"service"} }, "unknown": func(c *ClientSource) { c.AllowedProfiles = []string{"unknown"} }, "duplicate": func(c *ClientSource) { c.AllowedProfiles = []string{"azure", "azure"} }, "secret literal": func(c *ClientSource) { c.Secret.FromEnv = "not a ref" }, "long display": func(c *ClientSource) { c.DisplayName = strings.Repeat("x", 129) }, "control": func(c *ClientSource) { c.DisplayName = "a\nb" }} {
		t.Run(name, func(t *testing.T) {
			s := source()
			edit(&s.Clients[0])
			if _, e := Compile(raw(s), id, &refs{}); e == nil {
				t.Fatal("accepted")
			}
		})
	}
	good := string(raw(source()))
	for _, bad := range []string{strings.Replace(good, `"id":"explorer"`, `"id":"explorer","id":"other"`, 1), strings.Replace(good, `"trustMode":`, `"TrustMode":`, 1), strings.Replace(good, `"kind":"SSOClients",`, "", 1), good + "{}", strings.Repeat(" ", 1<<20) + good} {
		if _, e := Compile([]byte(bad), id, &refs{}); e == nil {
			t.Fatal("closed JSON")
		}
	}
}
func TestExactRedirects(t *testing.T) {
	for _, s := range []string{"http://a.test/cb", "https://A.test/cb", "https://a.test/cb?next=x", "https://a.test/cb#x", "https://u@a.test/cb", "https://a.test:443/cb", "https://a.test/a/../cb", "https://a.test/a//cb", "https://a.test/%63b", "https://a.test/cb\\x", "https://a.test/cb?", "https://*.test/cb", "https://a.test"} {
		if redirect(s) {
			t.Fatal(s)
		}
	}
	for _, s := range []string{"https://a.test/cb", "https://[::1]:8443/cb", "https://127.0.0.1:8443/cb", "https://a.test/"} {
		if !redirect(s) {
			t.Fatal(s)
		}
	}
}

func TestCompiledRedirectPreservesBrowserHostname(t *testing.T) {
	ids := identities(t)
	tooLong := strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 62)
	for _, host := range []string{"127.1", "2130706433", "0x7f000001", "0177.0.0.1", "127.0.0.01", "0x7f.1", "example.123", tooLong} {
		t.Run(host, func(t *testing.T) {
			s := source()
			s.Clients[0].RedirectURIs = []string{"https://" + host + "/cb"}
			if _, err := Compile(raw(s), ids, &refs{}); err == nil {
				t.Fatal("callback accepts a noncanonical browser host")
			}
		})
	}
	maxDNS := strings.TrimSuffix(tooLong, "d")
	for _, host := range []string{"127.0.0.1", "[::1]", "example.test", maxDNS} {
		s := source()
		s.Clients[0].RedirectURIs = []string{"https://" + host + "/cb"}
		if _, err := Compile(raw(s), ids, &refs{}); err != nil {
			t.Fatal("canonical callback host rejected", host, err)
		}
	}
}
