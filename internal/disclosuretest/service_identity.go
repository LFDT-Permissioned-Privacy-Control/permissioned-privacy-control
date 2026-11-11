package disclosuretest

import (
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"privacy-proxy/internal/identity"
	"privacy-proxy/internal/policybundle"
)

// EnableServiceIdentity adds a real approved Azure service profile and mapping.
// A signed token still traverses the normal selected catalog verification.
func EnableServiceIdentity(t testing.TB, f *StateFixture) {
	t.Helper()
	base := Snapshot(t, nil)
	catalog, _ := base.Identity()
	source := catalog.Source()
	source.Profiles = append(source.Profiles, identity.Profile{ID: "service", Kind: identity.AzureService, TenantID: Tenant, Issuer: "https://login.microsoftonline.com/" + Tenant + "/v2.0", APIAudience: Subject, AllowedClientIDs: []string{Subject}, FactSource: "appRoles"})
	source.Issuers[0].AllowedProfiles = append(source.Issuers[0].AllowedProfiles, "service")
	source.Mappings = append(source.Mappings, identity.Mapping{ID: "service-auditor", ProfileID: "service", OrganizationID: Org, PrincipalKind: identity.Service, Fact: identity.Fact{Kind: "azure.role", Value: "Workload"}, GroupIDs: []string{AuditorGroup}})
	f.IdentityCatalog = &source
}
func ServiceToken(t testing.TB, snapshot *policybundle.CatalogSnapshot, subject string) string {
	t.Helper()
	catalog, _ := snapshot.Identity()
	tenant := Tenant
	actor, err := catalog.SourceActorID(identity.SourceIdentity{ProfileID: "service", Kind: identity.Service, Authority: "https://login.microsoftonline.com/" + Tenant + "/v2.0", Subject: subject, Tenant: &tenant})
	if err != nil {
		t.Fatal(err)
	}
	profile, _ := catalog.ProfileDigest("service")
	claims := jwt.MapClaims{"iss": "https://ops.test", "aud": "core", "sub": actor, "jti": "test-service-request", "iat": Now, "nbf": Now, "exp": Now + 300, "principal_kind": "service", "source_profile": "service", "source_profile_digest": profile, "identity_authority": "https://login.microsoftonline.com/" + Tenant + "/v2.0", "source_subject": subject, "source_tenant": Tenant, "source_verified_at": Now, "claims_as_of": Now, "source_not_after": Now + 3600, "facts": []identity.Fact{{Kind: "azure.role", Value: "Workload"}}}
	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	token.Header["typ"], token.Header["kid"] = "ops-access+jwt", "test"
	raw, err := token.SignedString(key())
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
