package policybundle

import (
	"context"

	"privacy-proxy/internal/brokerpolicy"
)

// authPinnedRefs discovers only the closed source's explicit file references.
// The caller still reads them through the same regular-file resolver and total
// budgets as every other source file; URLs are loader keys, never fetch targets.
func authPinnedRefs(raw []byte, profile string, existing []DocumentRef) ([]DocumentRef, error) {
	if profile != BrokerMultiProfileID {
		return nil, nil
	}
	source, err := brokerpolicy.DecodeV2(raw)
	if err != nil {
		return nil, fail(InvalidSchema, "", "", "authCatalog", err.Error())
	}
	seen := map[string]bool{"draft.json": true, "manifest.json": true}
	for _, ref := range existing {
		seen[ref.Path] = true
	}
	refs := make([]DocumentRef, 0, len(source.PinnedDocuments))
	urls := map[string]bool{}
	for _, r := range source.PinnedDocuments {
		if len(r.Path) > 128 || !filePattern.MatchString(r.Path) || seen[r.Path] || urls[r.URL] || !validDigest(Digest(r.SHA256)) {
			return nil, fail(InvalidSchema, "", "", "pinnedDocuments", "invalid or duplicate pinned document reference")
		}
		seen[r.Path] = true
		urls[r.URL] = true
		refs = append(refs, DocumentRef{Path: r.Path, SHA256: Digest(r.SHA256)})
	}
	return refs, nil
}

func discoverAuthPinned(ctx context.Context, manifest Manifest, options Options, existing []DocumentRef, read func(string, int64) ([]byte, error)) ([]DocumentRef, error) {
	if manifest.AuthCatalog == nil || options.Profile.id != BrokerMultiProfileID {
		return nil, nil
	}
	if err := canceled(ctx); err != nil {
		return nil, err
	}
	raw, err := read(manifest.AuthCatalog.Path, min(int64(brokerpolicy.MaxSourceBytes), options.Limits.MaxDocumentBytes, options.Limits.MaxBundleBytes))
	if err != nil {
		return nil, err
	}
	return authPinnedRefs(raw, options.Profile.id, existing)
}
