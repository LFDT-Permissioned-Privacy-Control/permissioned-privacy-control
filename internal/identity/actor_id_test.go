package identity_test

import (
	"strings"
	"testing"

	"privacy-proxy/internal/identity"
)

func TestCanonicalActorSyntaxDoesNotAcceptLegacyOrAmbiguousEncoding(t *testing.T) {
	if !identity.ValidActorID(azureActor) || !identity.ValidActorID(privadoActor) {
		t.Fatal("issued canonical actor rejected")
	}
	for _, bad := range []string{"", strings.ToUpper(azureActor), azureActor + "=", azureActor[:len(azureActor)-1] + "h", "did:polygonid:polygon:amoy:abc", "11111111-1111-1111-1111-111111111111", strings.TrimPrefix(azureActor, "ops:p1:")} {
		if identity.ValidActorID(bad) {
			t.Fatalf("noncanonical actor accepted: %q", bad)
		}
	}
}

func TestCatalogSourceIdentitySharesCoreGoldenIdentifiers(t *testing.T) {
	c := compile(t, fixture(), identity.DefaultLimits())
	tenantCopy := tenant
	azure := identity.SourceIdentity{ProfileID: "azure", Kind: identity.Human, Authority: azureIssuer, Subject: oid, Tenant: &tenantCopy}
	if got, err := c.SourceActorID(azure); err != nil || got != azureActor {
		t.Fatal("Azure canonical identity changed", got, err)
	}
	for _, profile := range []string{"did", "role"} {
		if got, err := c.SourceActorID(identity.SourceIdentity{ProfileID: profile, Kind: identity.Human, Authority: "privado", Subject: holder}); err != nil || got != privadoActor {
			t.Fatal("Privado canonical identity changed", got, err)
		}
	}
	for _, mutate := range []func(*identity.SourceIdentity){func(s *identity.SourceIdentity) { s.ProfileID = "missing" }, func(s *identity.SourceIdentity) { s.Kind = identity.Service }, func(s *identity.SourceIdentity) { s.Authority = "privado" }, func(s *identity.SourceIdentity) { s.Tenant = nil }} {
		bad := azure
		mutate(&bad)
		if _, err := c.SourceActorID(bad); err == nil {
			t.Fatal("invalid source tuple accepted")
		}
	}
	other := azure
	other.Subject = tenant
	if got, err := c.SourceActorID(other); err != nil || got == azureActor {
		t.Fatal("distinct source subject collapsed", err)
	}
	// Exporting the identifier helper must not remove access evidence bounds.
	claims := claims(t, c, "azure")
	delete(claims, "source_not_after")
	denied(t, verifier(t, c), token(t, claims))
}
