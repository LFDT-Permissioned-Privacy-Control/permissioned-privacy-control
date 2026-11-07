// Package disclosuretest supplies deterministic source/JWT fixtures only. No
// production command imports this package or its explicitly known test key.
package disclosuretest

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	p "privacy-proxy/internal/disclosurepolicy"
	"privacy-proxy/internal/identity"
	"privacy-proxy/internal/policybundle"
	"privacy-proxy/internal/policycore"
	"privacy-proxy/internal/policyprofiles"
)

const (
	Org           = "11111111-1111-1111-1111-111111111111"
	OtherOrg      = "22222222-2222-2222-2222-222222222222"
	AuditorGroup  = "33333333-3333-3333-3333-333333333333"
	AdminGroup    = "44444444-4444-4444-4444-444444444444"
	ReadonlyGroup = "55555555-5555-5555-5555-555555555555"
	LocalGroup    = "66666666-6666-6666-6666-666666666666"
	ForeignGroup  = "77777777-7777-7777-7777-777777777777"
	Tenant        = "88888888-8888-8888-8888-888888888888"
	Subject       = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
	AdminSubject  = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
	Now           = int64(1800000000)
)

func key() ed25519.PrivateKey { return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{4}, 32)) }
func Actor(subject string) string {
	h := sha256.New()
	for _, s := range []string{"azure-v2", "https://login.microsoftonline.com/" + Tenant + "/v2.0", Tenant, subject, "human"} {
		var n [4]byte
		binary.BigEndian.PutUint32(n[:], uint32(len(s)))
		h.Write(n[:])
		h.Write([]byte(s))
	}
	return "ops:p1:" + base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}
func DefaultRule() p.RuleSource {
	return p.RuleSource{ID: "auditor", DataOrganizationID: Org, Viewers: p.Viewers{Groups: []p.GroupRef{{OrganizationID: Org, GroupID: AuditorGroup}}, Actors: []string{}}, Targets: p.Targets{Mode: "all-in-data-org", Actors: []string{}}, Resources: []p.Resource{p.ActivitySummary, p.Transactions}, Addresses: p.Addresses{Mode: "all-target-addresses", Values: []string{}}, DataTime: p.Interval{Start: Now - 86400, End: Now + 3600}, MaxLevel: p.Pseudonymous, Validity: p.Validity{NotBefore: Now - 10, ExpiresAt: Now + 3600}, MaxCaseSeconds: 1200}
}
func Scope() p.Scope {
	return p.Scope{TargetActors: []string{Actor(Subject)}, Resources: []p.Resource{p.Transactions}, Addresses: p.Addresses{Mode: "all-target-addresses", Values: []string{}}, DataTime: p.Interval{Start: Now - 3600, End: Now}, Level: p.Redacted}
}
func encode(t testing.TB, v any) []byte {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func Snapshot(t testing.TB, rules []p.RuleSource) *policybundle.CatalogSnapshot {
	return SelectedSnapshot(t, rules, "test", "1")
}

func SelectedSnapshot(t testing.TB, rules []p.RuleSource, environment, chain string) *policybundle.CatalogSnapshot {
	t.Helper()
	if rules == nil {
		rules = []p.RuleSource{DefaultRule()}
	}
	profiles := []identity.Profile{{ID: "azure", Kind: identity.AzureHuman, TenantID: Tenant, Issuer: "https://login.microsoftonline.com/" + Tenant + "/v2.0", APIAudience: Subject, ClientID: AuditorGroup, DelegatedScope: "api://bank/access", FactSource: "appRoles"}}
	identitySource := identity.SourceCatalog{APIVersion: identity.APIVersion, Kind: identity.CatalogKind, Issuers: []identity.Issuer{{ID: "ops", Issuer: "https://ops.test", Audience: "core", Keys: []identity.PublicKey{{Kid: "test", Alg: "EdDSA", Kty: "OKP", Crv: "Ed25519", X: base64.RawURLEncoding.EncodeToString(key().Public().(ed25519.PublicKey))}}, AllowedProfiles: []string{"azure"}}}, Profiles: profiles, Mappings: []identity.Mapping{}}
	groups := map[string][]policybundle.Group{Org: {}, OtherOrg: {}}
	for _, item := range []struct {
		id, name, org   string
		admin, readonly bool
		claims          []string
	}{{AuditorGroup, "Auditor", Org, false, false, []string{}}, {AdminGroup, "Admin", Org, true, false, []string{}}, {ReadonlyGroup, "Readonly", Org, false, true, []string{}}, {LocalGroup, "Local", Org, false, false, []string{"admin"}}, {ForeignGroup, "Foreign", OtherOrg, true, false, []string{}}} {
		methods := []string{}
		if item.admin {
			methods = []string{"eth_getCode"}
		}
		groups[item.org] = append(groups[item.org], policybundle.Group{ID: item.id, Slug: item.name, Name: item.name, IsOrgAdmin: item.admin, IsOrgReadonlyAdmin: item.readonly, Claims: item.claims, AllowedMethods: methods})
		identitySource.Mappings = append(identitySource.Mappings, identity.Mapping{ID: item.name, ProfileID: "azure", OrganizationID: item.org, PrincipalKind: identity.Human, Fact: identity.Fact{Kind: "azure.role", Value: item.name}, GroupIDs: []string{item.id}})
	}
	draft := policybundle.Draft{APIVersion: policybundle.DraftAPIVersion, Kind: policybundle.DraftKind, Environment: environment, ChainID: chain, EvaluatorVersion: policybundle.NativeV2EvaluatorVersion, Profile: policybundle.DisclosureProfileID, SourceRevision: "fixture", Organizations: []policybundle.Organization{{ID: Org, Slug: "a", Name: "A"}, {ID: OtherOrg, Slug: "b", Name: "B"}}, Documents: []policybundle.DraftDocument{}, IdentityCatalog: &policybundle.DraftIdentity{Path: "identity.json"}, DisclosureCatalog: &policybundle.DraftIdentity{Path: "disclosure.json"}}
	sourceDir := t.TempDir()
	write := func(name string, v any) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(sourceDir, name), encode(t, v), 0600); err != nil {
			t.Fatal(err)
		}
	}
	for i, org := range []string{Org, OtherOrg} {
		prefix := []string{"a", "b"}[i]
		for _, item := range []struct {
			kind   policybundle.Kind
			suffix string
			spec   any
		}{{policybundle.Groups, "groups", policybundle.GroupsSpec{Groups: groups[org]}}, {policybundle.ContractRegistry, "registry", policybundle.RegistrySpec{Contracts: []policybundle.Contract{}}}, {policybundle.ExecutionRules, "execution", policybundle.ExecutionSpec{Policy: &policycore.Policy{APIVersion: policycore.NativeV2APIVersion, Kind: policycore.Kind, Org: org, NestedCalls: policycore.NestedCallsRequireOwnRule, Bindings: []policycore.Binding{}}}}} {
			name := prefix + "-" + item.suffix + ".json"
			draft.Documents = append(draft.Documents, policybundle.DraftDocument{Kind: item.kind, OrganizationID: org, Path: name})
			write(name, map[string]any{"apiVersion": policybundle.DocumentAPIVersion, "kind": item.kind, "organizationId": org, "spec": item.spec})
		}
	}
	write("identity.json", identitySource)
	write("disclosure.json", p.Source{APIVersion: p.APIVersion, Kind: p.Kind, Rules: rules})
	write("draft.json", draft)
	options, _, err := policyprofiles.Options(policybundle.DisclosureProfileID)
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := policybundle.PrepareDirectory(context.Background(), policybundle.DraftSelection{Directory: sourceDir}, options)
	if err != nil {
		t.Fatal(err)
	}
	output := t.TempDir()
	for _, file := range artifact.Files() {
		if err := os.WriteFile(filepath.Join(output, file.Path), file.Bytes, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(output, "manifest.json"), artifact.ManifestBytes(), 0600); err != nil {
		t.Fatal(err)
	}
	snapshot, err := policybundle.LoadDirectory(context.Background(), policybundle.Selection{Directory: output, ExpectedManifestDigest: artifact.ManifestDigest(), ExpectedEnvironment: environment, ExpectedChainID: chain}, options)
	if err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func Token(t testing.TB, snapshot *policybundle.CatalogSnapshot, subject string, roles ...string) string {
	t.Helper()
	catalog, _ := snapshot.Identity()
	profile, _ := catalog.ProfileDigest("azure")
	facts := []identity.Fact{}
	for _, role := range roles {
		facts = append(facts, identity.Fact{Kind: "azure.role", Value: role})
	}
	claims := jwt.MapClaims{"iss": "https://ops.test", "aud": "core", "sub": Actor(subject), "jti": "test-request", "iat": Now, "nbf": Now, "exp": Now + 300, "principal_kind": "human", "source_profile": "azure", "source_profile_digest": profile, "identity_authority": "https://login.microsoftonline.com/" + Tenant + "/v2.0", "source_subject": subject, "source_tenant": Tenant, "source_verified_at": Now, "claims_as_of": Now, "source_not_after": Now + 3600, "facts": facts}
	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	token.Header["typ"], token.Header["kid"] = "ops-access+jwt", "test"
	raw, err := token.SignedString(key())
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
