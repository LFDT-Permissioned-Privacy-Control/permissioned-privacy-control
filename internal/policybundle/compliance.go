package policybundle

import "privacy-proxy/internal/compliancepolicy"

type complianceOrganizations struct{ snapshot *CatalogSnapshot }

func (o complianceOrganizations) OrganizationIDs() []string {
	ids := make([]string, 0, len(o.snapshot.organizations))
	for _, org := range o.snapshot.organizations {
		ids = append(ids, org.ID)
	}
	return ids
}
func (b *catalogBuilder) compileCompliance() error {
	if b.complianceSource == nil {
		return nil
	}
	c, err := compliancepolicy.Compile(*b.complianceSource, complianceOrganizations{b.snapshot}, b.complianceLimits)
	if err != nil {
		return fail(InvalidSchema, "", "", "complianceCatalog", err.Error())
	}
	b.snapshot.compliance = c
	b.snapshot.metadata.ComplianceCatalog = &ComplianceCatalogIdentity{ComplianceCatalogRef: *b.complianceRef, SemanticDigest: Digest(c.Digest())}
	for _, name := range c.Requirements() {
		b.capabilities[name] = true
	}
	return nil
}
