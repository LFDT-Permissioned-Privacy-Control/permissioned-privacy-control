package v2demo

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"privacy-proxy/internal/identity"
)

// Only these generated public source documents may leave the offline volume.
// Never export state.json, environment files, TLS material or runtime directories.
var publicSources = map[string][]string{
	"core":   {"draft.json", "groups.json", "registry.json", "execution.json", "identity.json", "runtime.json", "compliance.json", "disclosure.json"},
	"broker": {"draft.json", "groups.json", "registry.json", "execution.json", "identity.json", "auth.json", "role-context.json"},
}

type PublicSources struct {
	Version        int               `json:"version"`
	OrganizationID string            `json:"organizationId"`
	Files          map[string]string `json:"files"`
}

func readPublicFile(file string) ([]byte, error) {
	info, err := os.Lstat(file)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > 1<<20 {
		return nil, ErrInvalid
	}
	return os.ReadFile(file)
}

func ExportSources(root string) (PublicSources, error) {
	root, err := canonicalRoot(root)
	if err != nil {
		return PublicSources{}, err
	}
	s, err := readState(root)
	if err != nil || !s.Configured {
		return PublicSources{}, ErrInvalid
	}
	out := PublicSources{Version: 1, OrganizationID: Organization, Files: map[string]string{}}
	for directory, names := range publicSources {
		for _, name := range names {
			raw, err := readPublicFile(s.file("private/authoring/" + directory + "/" + name))
			if err != nil || !json.Valid(raw) {
				return PublicSources{}, ErrInvalid
			}
			out.Files[directory+"/"+name] = string(raw)
		}
	}
	return out, nil
}

type demoGroups struct{}

func (demoGroups) HasGroup(org, group string) bool {
	return org == Organization && (group == Admin || group == Deployer || group == Reader)
}

// This demo editor changes only claim mappings, using the existing native
// IdentityCatalog schema. Provider trust, keys and proof requirements stay fixed.
func checkedIdentity(base identity.SourceCatalog, raw []byte) (identity.SourceCatalog, error) {
	limits := identity.DefaultLimits()
	source, err := identity.Decode(raw, limits)
	if err != nil {
		return source, err
	}
	compiled, err := identity.Compile(source, demoGroups{}, limits)
	if err != nil {
		return source, err
	}
	expected, err := identity.Compile(base, demoGroups{}, limits)
	if err != nil {
		return source, err
	}
	a, b := compiled.Source(), expected.Source()
	a.Mappings, b.Mappings = []identity.Mapping{}, []identity.Mapping{}
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	if !bytes.Equal(x, y) {
		return source, fmt.Errorf("demo editor permits mappings only: %w", ErrInvalid)
	}
	return compiled.Source(), nil
}

func identityCandidate(ctx context.Context, root, walletOutput, file string) (State, []byte, error) {
	root, err := canonicalRoot(root)
	if err != nil {
		return State{}, nil, err
	}
	s, err := readState(root)
	if err != nil || !s.Configured {
		return s, nil, ErrInvalid
	}
	if walletOutput != "" {
		s.WalletOutput = walletOutput
	}
	metadata, _, err := walletMetadata(s)
	if err != nil {
		return s, nil, err
	}
	base, err := baseIdentitySource(s, metadata)
	if err != nil {
		return s, nil, err
	}
	raw, err := readPublicFile(file)
	if err != nil {
		return s, nil, err
	}
	if _, err = checkedIdentity(base, raw); err != nil {
		return s, nil, err
	}
	// Prepare and load both complete candidate bundles away from selected files.
	// No node, database, current selection or serving file is changed by a check.
	stage, err := os.MkdirTemp(root, ".identity-candidate-")
	if err != nil {
		return s, nil, err
	}
	defer os.RemoveAll(stage)
	candidate := s
	candidate.Root = stage
	if candidate.WalletOutput == "" {
		candidate.WalletOutput = s.file("wallet-state")
	}
	if _, err = writeBytes(filepath.Join(stage, "identity-override.json"), raw); err == nil {
		_, _, _, _, err = bundles(ctx, candidate)
	}
	return s, raw, err
}

func CheckIdentity(ctx context.Context, root, walletOutput, file string) error {
	_, _, err := identityCandidate(ctx, root, walletOutput, file)
	return err
}

func ApplyIdentity(ctx context.Context, root, walletOutput, file string) error {
	s, raw, err := identityCandidate(ctx, root, walletOutput, file)
	if err != nil {
		return err
	}
	metadata, _, err := walletMetadata(s)
	if err != nil {
		return err
	}
	old, err := identitySource(s, metadata)
	if err != nil {
		return err
	}
	if _, err = writeJSON(s.file("identity-previous.json"), old); err != nil {
		return err
	}
	if _, err = writeBytes(s.file("identity-override.json"), raw); err != nil {
		return err
	}
	// Serving processes are drained by the launcher before this offline action.
	// The selected source persists on failure; resume retries preparation while
	// the old serving processes stay stopped. Operational epochs are untouched.
	return Configure(ctx, s.Root, s.WalletOutput)
}
