package policybundle

import (
	"context"
	"io"
	"os"
	"sort"
)

// LoadDirectory reads a materialized read-only regular-file artifact. It has no
// fallback, file watcher or writer. Failure never returns a partial snapshot.
func LoadDirectory(ctx context.Context, selection Selection, options Options) (*CatalogSnapshot, error) {
	methods, err := prepareOptions(options)
	if err != nil {
		return nil, err
	}
	if selection.Directory == "" || !validDigest(selection.ExpectedManifestDigest) || !boundedName(selection.ExpectedEnvironment, 128) || !chainID(selection.ExpectedChainID) {
		return nil, fail(InvalidSelection, "", "", "selection", "expected manifest hash, environment and canonical chain ID are required")
	}
	if err := canceled(ctx); err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(selection.Directory)
	if err != nil {
		return nil, fail(ReadFailure, "", "", "directory", "cannot open selected artifact directory")
	}
	defer root.Close()
	manifestLimit := min(options.Limits.MaxManifestBytes, options.Limits.MaxBundleBytes)
	raw, err := readRegular(ctx, root, "manifest.json", manifestLimit)
	if err != nil {
		return nil, err
	}
	if RawDigest(raw) != selection.ExpectedManifestDigest {
		return nil, fail(IntegrityFailure, "", "", "manifest.json", "selected manifest digest does not match exact bytes")
	}
	var manifest Manifest
	if err := decodeSource(raw, &manifest, options.Limits.MaxJSONDepth); err != nil {
		return nil, fail(InvalidSchema, "", "", "manifest", err.Error())
	}
	if err := validateManifest(manifest, selection, options); err != nil {
		return nil, err
	}
	if err := checkEntries(ctx, root, manifest.Documents, options.Limits.MaxDocuments); err != nil {
		return nil, err
	}
	sort.Slice(manifest.Documents, func(i, j int) bool { return manifest.Documents[i].Path < manifest.Documents[j].Path })
	builder := newCatalogBuilder(manifest, selection.ExpectedManifestDigest, options)
	total := int64(len(raw))
	for _, ref := range manifest.Documents {
		if err := canceled(ctx); err != nil {
			return nil, err
		}
		budget := min(options.Limits.MaxDocumentBytes, options.Limits.MaxBundleBytes-total)
		if budget <= 0 {
			return nil, fail(LimitExceeded, ref.Kind, ref.OrganizationID, ref.Path, "bundle byte budget exceeded")
		}
		raw, err := readRegular(ctx, root, ref.Path, budget)
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
	if err := canceled(ctx); err != nil {
		return nil, err
	}
	return builder.finish(ctx, manifest.RequiredCapabilities)
}

func canceled(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return &Error{Code: Canceled, Field: "context", message: "load canceled", cause: err}
	}
	return nil
}

func readRegular(ctx context.Context, root *os.Root, name string, limit int64) ([]byte, error) {
	if err := canceled(ctx); err != nil {
		return nil, err
	}
	info, err := root.Lstat(name)
	if err != nil || !info.Mode().IsRegular() {
		return nil, fail(ReadFailure, "", "", name, "artifact entry must be a readable regular file")
	}
	if info.Size() > limit {
		return nil, fail(LimitExceeded, "", "", name, "file exceeds remaining byte budget")
	}
	file, err := root.Open(name)
	if err != nil {
		return nil, fail(ReadFailure, "", "", name, "cannot read artifact file")
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(info, opened) {
		return nil, fail(ReadFailure, "", "", name, "artifact file changed while opening")
	}
	raw, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, fail(ReadFailure, "", "", name, "cannot read artifact bytes")
	}
	if int64(len(raw)) > limit {
		return nil, fail(LimitExceeded, "", "", name, "file exceeds remaining byte budget")
	}
	if err := canceled(ctx); err != nil {
		return nil, err
	}
	return raw, nil
}

func checkEntries(ctx context.Context, root *os.Root, refs []DocumentRef, maxDocuments int) error {
	want := map[string]bool{"manifest.json": true}
	for _, ref := range refs {
		want[ref.Path] = true
	}
	directory, err := root.Open(".")
	if err != nil {
		return fail(ReadFailure, "", "", "directory", "cannot enumerate artifact directory")
	}
	defer directory.Close()
	seen, count := map[string]bool{}, 0
	for {
		if err := canceled(ctx); err != nil {
			return err
		}
		entries, err := directory.ReadDir(32)
		for _, entry := range entries {
			count++
			if count > maxDocuments+1 {
				return fail(LimitExceeded, "", "", "directory", "too many artifact directory entries")
			}
			if !want[entry.Name()] || seen[entry.Name()] {
				return fail(IntegrityFailure, "", "", "directory", "unexpected or duplicate artifact entry")
			}
			info, statErr := entry.Info()
			if statErr != nil || !info.Mode().IsRegular() {
				return fail(ReadFailure, "", "", entry.Name(), "artifact entry must be a regular file")
			}
			seen[entry.Name()] = true
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return fail(ReadFailure, "", "", "directory", "cannot enumerate artifact entries")
		}
	}
	if len(seen) != len(want) {
		return fail(IntegrityFailure, "", "", "directory", "artifact is missing listed files")
	}
	return nil
}
