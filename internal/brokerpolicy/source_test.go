package brokerpolicy_test

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"privacy-proxy/internal/brokerpolicy"
	f "privacy-proxy/internal/brokertest"
	"privacy-proxy/internal/identity"
)

type allGroups struct{}

func (allGroups) HasGroup(string, string) bool { return true }

func catalog(t *testing.T, modify func(*identity.SourceCatalog)) *identity.Catalog {
	t.Helper()
	source := f.IdentitySource()
	if modify != nil {
		modify(&source)
	}
	c, err := identity.Compile(source, allGroups{}, identity.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	return c
}
func TestBrokerSourcePinsExistingProfilesAndDetachedRequirements(t *testing.T) {
	identities := catalog(t, nil)
	source := f.BrokerSource()
	c, err := brokerpolicy.Compile(source, identities)
	if err != nil {
		t.Fatal(err)
	}
	profile, ok := c.Profile(f.HumanProfile)
	if !ok || profile.ScopeWord != "access" || profile.Definition.DelegatedScope != "api://"+f.Audience+"/access" {
		t.Fatal("scope identity drift")
	}
	caps, refs := c.Requirements()
	if len(caps) != 4 || len(refs) != 3 {
		t.Fatal(caps, refs)
	}
	source.AzureProfiles[0].ClientSecret.FromEnv = "OTHER"
	copy := c.Source()
	copy.AzureProfiles[0].ClientSecret.FromEnv = "OTHER"
	profile.Binding.ClientSecret.FromEnv = "OTHER"
	caps[0] = "other"
	refs[0] = "OTHER"
	if p, _ := c.Profile(f.HumanProfile); p.Binding.ClientSecret.FromEnv != "OPS_BROKER_AZURE_TEST" {
		t.Fatal("source escaped immutable catalog")
	}
	a, z := c.Requirements()
	if reflect.DeepEqual(a, caps) || reflect.DeepEqual(z, refs) {
		t.Fatal("requirements escaped")
	}
	reordered := f.BrokerSource()
	reordered.AzureProfiles[0], reordered.AzureProfiles[1] = reordered.AzureProfiles[1], reordered.AzureProfiles[0]
	second, err := brokerpolicy.Compile(reordered, identities)
	if err != nil || second.Digest() != c.Digest() {
		t.Fatal("nondeterministic public source", err)
	}
}
func TestBrokerRejectsAmbiguousAuthorityAndSecrets(t *testing.T) {
	identities := catalog(t, nil)
	for name, change := range map[string]func(*brokerpolicy.Source){
		"version": func(s *brokerpolicy.Source) { s.APIVersion = "next" }, "issuer": func(s *brokerpolicy.Source) { s.IssuerID = "other" }, "key": func(s *brokerpolicy.Source) { s.AccessKeyID = "other" },
		"foreign completion": func(s *brokerpolicy.Source) { s.CompletionURI = "https://other.test/complete" }, "http": func(s *brokerpolicy.Source) { s.WebOrigin = "http://ops.test" }, "fragment": func(s *brokerpolicy.Source) { s.CompletionURI += "#token" },
		"missing human secret": func(s *brokerpolicy.Source) { s.AzureProfiles[0].ClientSecret = nil }, "literal secret": func(s *brokerpolicy.Source) { s.AzureProfiles[0].ClientSecret.FromEnv = "test-secret" }, "service redirect": func(s *brokerpolicy.Source) { s.AzureProfiles[1].RedirectURI = "https://ops.test/callback" },
		"duplicate profile": func(s *brokerpolicy.Source) { s.AzureProfiles = append(s.AzureProfiles, s.AzureProfiles[0]) }, "unknown profile": func(s *brokerpolicy.Source) { s.AzureProfiles[0].ProfileID = "other" },
		"inactive renewal": func(s *brokerpolicy.Source) { s.RenewalKeys[0].Active = false }, "duplicate key": func(s *brokerpolicy.Source) { s.RenewalKeys = append(s.RenewalKeys, s.RenewalKeys[0]) }, "too many keys": func(s *brokerpolicy.Source) {
			s.EncryptionKeys = append(s.EncryptionKeys, s.EncryptionKeys[0], s.EncryptionKeys[0])
		},
	} {
		t.Run(name, func(t *testing.T) {
			source := f.BrokerSource()
			change(&source)
			if _, err := brokerpolicy.Compile(source, identities); err == nil {
				t.Fatal("invalid broker source accepted")
			}
		})
	}
	raw, _ := json.Marshal(f.BrokerSource())
	for _, bad := range []string{strings.TrimSuffix(string(raw), "}") + `,"clientSecret":"plaintext"}`, strings.Replace(string(raw), `"kind":`, `"Kind":`, 1), strings.Replace(string(raw), `"kind":"AuthBroker"`, `"kind":"AuthBroker","kind":"AuthBroker"`, 1), strings.Replace(string(raw), `"renewalKeys":[`, `"renewalKeys":null,"unused":[`, 1), strings.Repeat(" ", brokerpolicy.MaxSourceBytes+1), string(raw) + "{}"} {
		if _, err := brokerpolicy.Decode([]byte(bad)); err == nil {
			t.Fatal("nonclosed source accepted")
		}
	}
}
func TestFullDelegatedScopeHasUnambiguousJWTWord(t *testing.T) {
	for _, scope := range []string{"api://" + f.Audience + "/access", "https://api.bank.example/scopes/Transactions.Read"} {
		identities := catalog(t, func(s *identity.SourceCatalog) { s.Profiles[0].DelegatedScope = scope })
		if _, err := brokerpolicy.Compile(f.BrokerSource(), identities); err != nil {
			t.Fatal(scope, err)
		}
	}
	for _, scope := range []string{"access", "api://api/.default", "api://api/access/", "api://api/access?x=y", "api://api/acc%65ss", "api://api/access other"} {
		source := f.IdentitySource()
		source.Profiles[0].DelegatedScope = scope
		identities, err := identity.Compile(source, allGroups{}, identity.DefaultLimits())
		if err != nil {
			continue
		}
		if _, err := brokerpolicy.Compile(f.BrokerSource(), identities); err == nil {
			t.Fatal("ambiguous scope accepted", scope)
		}
	}
}
