package policybundle

import (
	"context"
	"io"
	"os"
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
	entries := append([]DocumentRef(nil), manifest.Documents...)
	if manifest.IdentityCatalog != nil {
		entries = append(entries, DocumentRef{Path: manifest.IdentityCatalog.Path})
	}
	if manifest.RuntimeCatalog != nil {
		entries = append(entries, DocumentRef{Path: manifest.RuntimeCatalog.Path})
	}
	if err := checkEntries(ctx, root, entries, options.Limits.MaxDocuments); err != nil {
		return nil, err
	}
	snapshot, err := compileSourceSet(ctx, manifest, selection.ExpectedManifestDigest, int64(len(raw)), options, methods, func(name string, budget int64) ([]byte, error) {
		return readRegular(ctx, root, name, budget)
	})
	if err != nil {
		return nil, err
	}
	inferred := make(map[string]bool, len(snapshot.requirements.Capabilities))
	for _, name := range snapshot.requirements.Capabilities {
		inferred[name] = true
	}
	if err := compareCapabilities(manifest.RequiredCapabilities, inferred); err != nil {
		return nil, err
	}
	return snapshot, nil
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
	return checkEntriesNamed(ctx, root, refs, maxDocuments, "manifest.json")
}

func checkEntriesNamed(ctx context.Context, root *os.Root, refs []DocumentRef, maxDocuments int, selectionFile string) error {
	want := map[string]bool{selectionFile: true}
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
