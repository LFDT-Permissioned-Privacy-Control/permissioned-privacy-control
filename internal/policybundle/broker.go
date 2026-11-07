package policybundle

import "privacy-proxy/internal/brokerpolicy"

func (b *catalogBuilder) compileAuth() error {
	if b.authSource == nil && b.authMultiSource == nil {
		return nil
	}
	var catalog *brokerpolicy.Catalog
	var err error
	if b.authMultiSource != nil {
		catalog, err = brokerpolicy.CompileV2(*b.authMultiSource, b.snapshot.identity, b.authDocuments)
	} else {
		catalog, err = brokerpolicy.Compile(*b.authSource, b.snapshot.identity)
	}
	if err != nil {
		return fail(InvalidSchema, "", "", "authCatalog", err.Error())
	}
	b.snapshot.auth = catalog
	b.snapshot.metadata.AuthCatalog = &AuthCatalogIdentity{AuthCatalogRef: *b.authRef, SemanticDigest: Digest(catalog.Digest())}
	capabilities, refs := catalog.Requirements()
	for _, name := range capabilities {
		b.capabilities[name] = true
	}
	for _, ref := range refs {
		b.secrets[ref] = true
	}
	return nil
}
