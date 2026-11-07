// Package brokertest supplies deterministic public source and known test keys.
// No production command imports it.
package brokertest

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"privacy-proxy/internal/brokerpolicy"
	f "privacy-proxy/internal/disclosuretest"
	"privacy-proxy/internal/identity"
	"privacy-proxy/internal/policybundle"
	"privacy-proxy/internal/policycore"
	"privacy-proxy/internal/policyprofiles"
)

const HumanProfile = "azure"
const ServiceProfile = "service"
const Audience = "99999999-9999-9999-9999-999999999999"
const HumanClient = "aaaaaaaa-1111-1111-1111-111111111111"
const ServiceClient = "bbbbbbbb-1111-1111-1111-111111111111"

func SigningKey() ed25519.PrivateKey { return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, 32)) }
func BrokerSource() brokerpolicy.Source {
	return brokerpolicy.Source{APIVersion: brokerpolicy.APIVersion, Kind: brokerpolicy.Kind, IssuerID: "ops", AccessKeyID: "test", WebOrigin: "https://ops.test", CompletionURI: "https://ops.test/auth/complete", AzureProfiles: []brokerpolicy.AzureBinding{{ProfileID: HumanProfile, RedirectURI: "https://ops.test/api/v2/auth/azure/callback", ClientSecret: &brokerpolicy.SecretRef{FromEnv: "OPS_BROKER_AZURE_TEST"}}, {ProfileID: ServiceProfile}}, RenewalKeys: []brokerpolicy.KeyRef{{ID: "mac-test", FromEnv: "OPS_BROKER_REFRESH_TEST", Active: true}}, EncryptionKeys: []brokerpolicy.KeyRef{{ID: "aes-test", FromEnv: "OPS_BROKER_ENCRYPTION_TEST", Active: true}}}
}
func IdentitySource() identity.SourceCatalog {
	return identity.SourceCatalog{APIVersion: identity.APIVersion, Kind: identity.CatalogKind, Issuers: []identity.Issuer{{ID: "ops", Issuer: "https://ops.test", Audience: "core", Keys: []identity.PublicKey{{Kid: "test", Alg: "EdDSA", Kty: "OKP", Crv: "Ed25519", X: base64.RawURLEncoding.EncodeToString(SigningKey().Public().(ed25519.PublicKey))}}, AllowedProfiles: []string{HumanProfile, ServiceProfile}}}, Profiles: []identity.Profile{{ID: HumanProfile, Kind: identity.AzureHuman, TenantID: f.Tenant, Issuer: "https://login.microsoftonline.com/" + f.Tenant + "/v2.0", APIAudience: Audience, ClientID: HumanClient, DelegatedScope: "api://" + Audience + "/access", FactSource: "appRoles"}, {ID: ServiceProfile, Kind: identity.AzureService, TenantID: f.Tenant, Issuer: "https://login.microsoftonline.com/" + f.Tenant + "/v2.0", APIAudience: Audience, AllowedClientIDs: []string{ServiceClient}, FactSource: "appRoles"}}, Mappings: []identity.Mapping{{ID: "reader", ProfileID: HumanProfile, OrganizationID: f.Org, PrincipalKind: identity.Human, Fact: identity.Fact{Kind: "azure.role", Value: "Reader"}, GroupIDs: []string{f.AuditorGroup}}, {ID: "admin", ProfileID: HumanProfile, OrganizationID: f.Org, PrincipalKind: identity.Human, Fact: identity.Fact{Kind: "azure.role", Value: "Admin"}, GroupIDs: []string{f.AdminGroup}}, {ID: "service", ProfileID: ServiceProfile, OrganizationID: f.Org, PrincipalKind: identity.Service, Fact: identity.Fact{Kind: "azure.role", Value: "Service"}, GroupIDs: []string{f.AuditorGroup}}}}
}

func Snapshot(t testing.TB, change func(*identity.SourceCatalog, *brokerpolicy.Source)) *policybundle.CatalogSnapshot {
	t.Helper()
	identities, broker := IdentitySource(), BrokerSource()
	if change != nil {
		change(&identities, &broker)
	}
	return snapshot(t, identities, broker, policybundle.BrokerProfileID, nil)
}
func snapshot(t testing.TB, identities identity.SourceCatalog, broker any, profile string, extra map[string][]byte) *policybundle.CatalogSnapshot {
	t.Helper()
	draft := policybundle.Draft{APIVersion: policybundle.DraftAPIVersion, Kind: policybundle.DraftKind, Environment: "test", ChainID: "1", EvaluatorVersion: policybundle.NativeV2EvaluatorVersion, Profile: profile, SourceRevision: "broker-fixture", Organizations: []policybundle.Organization{{ID: f.Org, Slug: "bank", Name: "Bank"}}, Documents: []policybundle.DraftDocument{}, IdentityCatalog: &policybundle.DraftIdentity{Path: "identity.json"}, AuthCatalog: &policybundle.DraftIdentity{Path: "auth.json"}}
	dir := t.TempDir()
	write := func(name string, value any) {
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	groups := []policybundle.Group{{ID: f.AuditorGroup, Slug: "reader", Name: "Reader", Claims: []string{}, AllowedMethods: []string{"eth_call"}}, {ID: f.AdminGroup, Slug: "admin", Name: "Admin", IsOrgAdmin: true, Claims: []string{}, AllowedMethods: []string{"eth_getCode"}}}
	for _, row := range []struct {
		kind policybundle.Kind
		file string
		spec any
	}{{policybundle.Groups, "groups.json", policybundle.GroupsSpec{Groups: groups}}, {policybundle.ContractRegistry, "registry.json", policybundle.RegistrySpec{Contracts: []policybundle.Contract{}}}, {policybundle.ExecutionRules, "execution.json", policybundle.ExecutionSpec{Policy: &policycore.Policy{APIVersion: policycore.NativeV2APIVersion, Kind: policycore.Kind, Org: f.Org, NestedCalls: policycore.NestedCallsRequireOwnRule, Bindings: []policycore.Binding{}}}}} {
		draft.Documents = append(draft.Documents, policybundle.DraftDocument{Kind: row.kind, OrganizationID: f.Org, Path: row.file})
		write(row.file, map[string]any{"apiVersion": policybundle.DocumentAPIVersion, "kind": row.kind, "organizationId": f.Org, "spec": row.spec})
	}
	write("identity.json", identities)
	write("auth.json", broker)
	write("draft.json", draft)
	for name, raw := range extra {
		if err := os.WriteFile(filepath.Join(dir, name), raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	options, _, err := policyprofiles.Options(profile)
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := policybundle.PrepareDirectory(t.Context(), policybundle.DraftSelection{Directory: dir}, options)
	if err != nil {
		t.Fatal(err)
	}
	out := t.TempDir()
	for _, file := range artifact.Files() {
		if err := os.WriteFile(filepath.Join(out, file.Path), file.Bytes, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(out, "manifest.json"), artifact.ManifestBytes(), 0600); err != nil {
		t.Fatal(err)
	}
	snapshot, err := policybundle.LoadDirectory(t.Context(), policybundle.Selection{Directory: out, ExpectedManifestDigest: artifact.ManifestDigest(), ExpectedEnvironment: "test", ExpectedChainID: "1"}, options)
	if err != nil {
		t.Fatal(err)
	}
	return snapshot
}
