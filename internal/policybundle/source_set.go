package policybundle

import (
	"context"
	"sort"

	"privacy-proxy/internal/compliancepolicy"
	"privacy-proxy/internal/disclosurepolicy"
	"privacy-proxy/internal/identity"
)

// compileSourceSet is the sole document/normalization/profile compiler shared
// by pinned runtime loads and preparation. Only LoadDirectory publishes its
// snapshot, after independently checking the selected digest and declarations.
func compileSourceSet(ctx context.Context, manifest Manifest, digest Digest, manifestBytes int64, options Options, methods methodIndex, read func(string, int64) ([]byte, error)) (*CatalogSnapshot, error) {
	sort.Slice(manifest.Documents, func(i, j int) bool { return manifest.Documents[i].Path < manifest.Documents[j].Path })
	builder := newCatalogBuilder(manifest, digest, options)
	builder.snapshot.methods = methods // prepareOptions owns every registry map/slice.
	total := manifestBytes
	for _, ref := range manifest.Documents {
		if err := canceled(ctx); err != nil {
			return nil, err
		}
		budget := min(options.Limits.MaxDocumentBytes, options.Limits.MaxBundleBytes-total)
		if budget <= 0 {
			return nil, fail(LimitExceeded, ref.Kind, ref.OrganizationID, ref.Path, "bundle byte budget exceeded")
		}
		raw, err := read(ref.Path, budget)
		if err != nil {
			return nil, err
		}
		total += int64(len(raw)) // readRegular bounded this by the remaining total.
		if RawDigest(raw) != ref.SHA256 {
			return nil, fail(IntegrityFailure, ref.Kind, ref.OrganizationID, ref.Path, "document digest does not match exact bytes")
		}
		wire, spec, err := decodeDocument(raw, ref, options.Limits)
		if err != nil {
			return nil, err
		}
		if err := builder.add(wire, spec, ref, methods, options.Limits); err != nil {
			return nil, err
		}
	}
	if ref := manifest.IdentityCatalog; ref != nil {
		budget := min(options.Limits.MaxDocumentBytes, int64(options.IdentityLimits.MaxIdentityDocumentBytes), options.Limits.MaxBundleBytes-total)
		if budget <= 0 {
			return nil, fail(LimitExceeded, "", "", "identityCatalog", "identity file exceeds remaining byte budget")
		}
		raw, err := read(ref.Path, budget)
		if err != nil {
			return nil, err
		}
		total += int64(len(raw))
		if RawDigest(raw) != ref.SHA256 {
			return nil, fail(IntegrityFailure, "", "", "identityCatalog", "identity file digest does not match exact bytes")
		}
		source, err := identity.Decode(raw, options.IdentityLimits)
		if err != nil {
			return nil, fail(InvalidSchema, "", "", "identityCatalog", err.Error())
		}
		builder.identitySource = &source
		builder.identityRef = ref
	}
	if ref := manifest.RuntimeCatalog; ref != nil {
		budget := min(options.Limits.MaxDocumentBytes, options.Limits.MaxBundleBytes-total)
		if budget <= 0 {
			return nil, fail(LimitExceeded, "", "", "runtimeCatalog", "runtime file exceeds remaining byte budget")
		}
		raw, err := read(ref.Path, budget)
		if err != nil {
			return nil, err
		}
		total += int64(len(raw))
		if RawDigest(raw) != ref.SHA256 {
			return nil, fail(IntegrityFailure, "", "", "runtimeCatalog", "runtime file digest does not match exact bytes")
		}
		var source RuntimeSource
		if err := decodeSource(raw, &source, options.Limits.MaxJSONDepth); err != nil {
			return nil, fail(InvalidSchema, "", "", "runtimeCatalog", err.Error())
		}
		builder.runtimeSource = &source
		builder.runtimeRef = ref
	}
	if ref := manifest.DisclosureCatalog; ref != nil {
		budget := min(options.Limits.MaxDocumentBytes, int64(options.DisclosureLimits.MaxDocumentBytes), options.Limits.MaxBundleBytes-total)
		if budget <= 0 {
			return nil, fail(LimitExceeded, "", "", "disclosureCatalog", "disclosure file exceeds remaining byte budget")
		}
		raw, err := read(ref.Path, budget)
		if err != nil {
			return nil, err
		}
		total += int64(len(raw))
		if RawDigest(raw) != ref.SHA256 {
			return nil, fail(IntegrityFailure, "", "", "disclosureCatalog", "disclosure digest does not match exact bytes")
		}
		source, err := disclosurepolicy.Decode(raw, options.DisclosureLimits)
		if err != nil {
			return nil, fail(InvalidSchema, "", "", "disclosureCatalog", err.Error())
		}
		builder.disclosureSource = &source
		builder.disclosureRef = ref
	}
	if ref := manifest.ComplianceCatalog; ref != nil {
		budget := min(options.Limits.MaxDocumentBytes, int64(options.ComplianceLimits.MaxDocumentBytes), options.Limits.MaxBundleBytes-total)
		if budget <= 0 {
			return nil, fail(LimitExceeded, "", "", "complianceCatalog", "compliance file exceeds remaining byte budget")
		}
		raw, err := read(ref.Path, budget)
		if err != nil {
			return nil, err
		}
		total += int64(len(raw))
		if RawDigest(raw) != ref.SHA256 {
			return nil, fail(IntegrityFailure, "", "", "complianceCatalog", "compliance digest does not match exact bytes")
		}
		source, err := compliancepolicy.Decode(raw, options.ComplianceLimits)
		if err != nil {
			return nil, fail(InvalidSchema, "", "", "complianceCatalog", err.Error())
		}
		builder.complianceSource = &source
		builder.complianceRef = ref
	}
	if err := canceled(ctx); err != nil {
		return nil, err
	}
	return builder.finish(ctx)
}
