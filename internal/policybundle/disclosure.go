package policybundle

import "privacy-proxy/internal/disclosurepolicy"

type disclosureGroups struct{ snapshot *CatalogSnapshot }

func (g disclosureGroups) HasOrganization(org string) bool {
	_, ok := g.snapshot.groups[org]
	return ok
}
func (g disclosureGroups) HasGroup(org, id string) bool {
	_, ok := g.snapshot.groups[org][id]
	return ok
}
func (b *catalogBuilder) compileDisclosure() error {
	if b.disclosureSource == nil {
		return nil
	}
	catalog, err := disclosurepolicy.Compile(*b.disclosureSource, disclosureGroups{b.snapshot}, b.disclosureLimits)
	if err != nil {
		return fail(InvalidSchema, "", "", "disclosureCatalog", err.Error())
	}
	b.snapshot.disclosure = catalog
	b.snapshot.metadata.DisclosureCatalog = &DisclosureCatalogIdentity{DisclosureCatalogRef: *b.disclosureRef, SemanticDigest: Digest(catalog.Digest())}
	for _, name := range catalog.Requirements() {
		b.capabilities[name] = true
	}
	return nil
}

func globalDocumentRefs(m Manifest) []DocumentRef {
	refs := []DocumentRef{}
	if r := m.IdentityCatalog; r != nil {
		refs = append(refs, DocumentRef{Path: r.Path, SHA256: r.SHA256})
	}
	if r := m.RuntimeCatalog; r != nil {
		refs = append(refs, DocumentRef{Path: r.Path, SHA256: r.SHA256})
	}
	if r := m.DisclosureCatalog; r != nil {
		refs = append(refs, DocumentRef{Path: r.Path, SHA256: r.SHA256})
	}
	return refs
}
