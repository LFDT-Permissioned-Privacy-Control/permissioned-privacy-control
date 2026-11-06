package policybundle

import "privacy-proxy/internal/identity"

type identityGroups struct{ groups map[string]map[string]Group }

func (g identityGroups) HasGroup(org, id string) bool { _, ok := g.groups[org][id]; return ok }

func (b *catalogBuilder) compileIdentity() error {
	if b.identitySource == nil {
		return nil
	}
	catalog, err := identity.Compile(*b.identitySource, identityGroups{b.snapshot.groups}, b.identityLimits)
	if err != nil {
		return fail(InvalidSchema, "", "", "identityCatalog", err.Error())
	}
	b.snapshot.identity = catalog
	b.snapshot.metadata.IdentityCatalog = &IdentityCatalogIdentity{IdentityCatalogRef: *b.identityRef, SemanticDigest: Digest(catalog.Digest())}
	b.capabilities[CapabilityIdentity] = true
	if catalog.HasMappings() {
		b.capabilities[CapabilityPrincipal] = true
	}
	return nil
}
