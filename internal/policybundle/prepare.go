package policybundle

import (
	"context"
	"encoding/json"
	"os"
	"privacy-proxy/internal/brokerpolicy"
	"slices"
	"sort"
)

const DraftAPIVersion = "ops.policy-draft/v1alpha1"
const DraftKind = "PolicyDraft"

type DraftSelection struct{ Directory string }

// Draft supplies source identity and file references. File hashes and required
// capabilities are derived by the shared compiler, never authored as guesses.
type Draft struct {
	APIVersion        string          `json:"apiVersion"`
	Kind              string          `json:"kind"`
	Environment       string          `json:"environment"`
	ChainID           string          `json:"chainId"`
	EvaluatorVersion  string          `json:"evaluatorVersion"`
	Profile           string          `json:"profile"`
	SourceRevision    string          `json:"sourceRevision"`
	Organizations     []Organization  `json:"organizations"`
	Documents         []DraftDocument `json:"documents"`
	IdentityCatalog   *DraftIdentity  `json:"identityCatalog,omitempty" optional:"true"`
	RuntimeCatalog    *DraftRuntime   `json:"runtimeCatalog,omitempty" optional:"true"`
	DisclosureCatalog *DraftIdentity  `json:"disclosureCatalog,omitempty" optional:"true"`
	ComplianceCatalog *DraftIdentity  `json:"complianceCatalog,omitempty" optional:"true"`
	AuthCatalog       *DraftIdentity  `json:"authCatalog,omitempty" optional:"true"`
}

type DraftDocument struct {
	Kind           Kind   `json:"kind"`
	OrganizationID string `json:"organizationId"`
	Path           string `json:"path"`
}
type DraftIdentity struct {
	Path string `json:"path"`
}
type DraftRuntime struct {
	Path string `json:"path"`
}

type PreparedFile struct {
	Path  string
	Bytes []byte
}

// PreparedArtifact is an unapproved proposal. It has no snapshot, activation,
// principal or readiness accessor and cannot be passed to a runtime consumer.
type PreparedArtifact struct {
	manifest []byte
	files    []PreparedFile
	required Requirements
}

func (p *PreparedArtifact) ManifestBytes() []byte  { return slices.Clone(p.manifest) }
func (p *PreparedArtifact) ManifestDigest() Digest { return RawDigest(p.manifest) }
func (p *PreparedArtifact) Files() []PreparedFile {
	files := slices.Clone(p.files)
	for i := range files {
		files[i].Bytes = slices.Clone(files[i].Bytes)
	}
	return files
}
func (p *PreparedArtifact) Requirements() Requirements {
	return Requirements{Capabilities: slices.Clone(p.required.Capabilities), SecretRefs: slices.Clone(p.required.SecretRefs)}
}

// PrepareDirectory reads draft.json and only its listed regular files. It
// preserves their exact bytes, infers requirements through the same compiler as
// LoadDirectory, and returns a detached proposal without writing or approval.
func PrepareDirectory(ctx context.Context, selection DraftSelection, options Options) (*PreparedArtifact, error) {
	methods, err := prepareOptions(options)
	if err != nil {
		return nil, err
	}
	if selection.Directory == "" {
		return nil, fail(InvalidSelection, "", "", "directory", "draft directory is required")
	}
	if err := canceled(ctx); err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(selection.Directory)
	if err != nil {
		return nil, fail(ReadFailure, "", "", "directory", "cannot open draft source directory")
	}
	defer root.Close()
	raw, err := readRegular(ctx, root, "draft.json", min(options.Limits.MaxManifestBytes, options.Limits.MaxBundleBytes))
	if err != nil {
		return nil, err
	}
	var draft Draft
	if err := decodeSource(raw, &draft, options.Limits.MaxJSONDepth); err != nil {
		return nil, fail(InvalidSchema, "", "", "draft", err.Error())
	}
	if draft.APIVersion != DraftAPIVersion || draft.Kind != DraftKind || !boundedName(draft.Environment, 128) || !chainID(draft.ChainID) {
		return nil, fail(InvalidSchema, "", "", "draft", "unsupported draft version/kind or invalid environment/chain")
	}
	manifest := Manifest{APIVersion: BundleAPIVersion, Kind: BundleKind, Environment: draft.Environment, ChainID: draft.ChainID, EvaluatorVersion: draft.EvaluatorVersion, Profile: draft.Profile, SourceRevision: draft.SourceRevision, Organizations: slices.Clone(draft.Organizations), Documents: make([]DocumentRef, 0, len(draft.Documents)), RequiredCapabilities: []string{}}
	for _, ref := range draft.Documents {
		if ref.Path == "draft.json" {
			return nil, fail(InvalidSchema, ref.Kind, ref.OrganizationID, "path", "document collides with draft.json")
		}
		manifest.Documents = append(manifest.Documents, DocumentRef{Kind: ref.Kind, OrganizationID: ref.OrganizationID, Path: ref.Path, SHA256: RawDigest(nil)})
	}
	if draft.IdentityCatalog != nil {
		if draft.IdentityCatalog.Path == "draft.json" {
			return nil, fail(InvalidSchema, "", "", "identityCatalog", "identity source collides with draft.json")
		}
		manifest.IdentityCatalog = &IdentityCatalogRef{Path: draft.IdentityCatalog.Path, SHA256: RawDigest(nil)}
	}
	if draft.RuntimeCatalog != nil {
		if draft.RuntimeCatalog.Path == "draft.json" {
			return nil, fail(InvalidSchema, "", "", "runtimeCatalog", "runtime source collides with draft.json")
		}
		manifest.RuntimeCatalog = &RuntimeCatalogRef{Path: draft.RuntimeCatalog.Path, SHA256: RawDigest(nil)}
	}
	if draft.DisclosureCatalog != nil {
		if draft.DisclosureCatalog.Path == "draft.json" {
			return nil, fail(InvalidSchema, "", "", "disclosureCatalog", "disclosure source collides with draft.json")
		}
		manifest.DisclosureCatalog = &DisclosureCatalogRef{Path: draft.DisclosureCatalog.Path, SHA256: RawDigest(nil)}
	}
	selected := Selection{ExpectedManifestDigest: RawDigest(nil), ExpectedEnvironment: draft.Environment, ExpectedChainID: draft.ChainID}
	if draft.ComplianceCatalog != nil {
		if draft.ComplianceCatalog.Path == "draft.json" {
			return nil, fail(InvalidSchema, "", "", "complianceCatalog", "compliance source collides with draft.json")
		}
		manifest.ComplianceCatalog = &ComplianceCatalogRef{Path: draft.ComplianceCatalog.Path, SHA256: RawDigest(nil)}
	}
	if draft.AuthCatalog != nil {
		if draft.AuthCatalog.Path == "draft.json" {
			return nil, fail(InvalidSchema, "", "", "authCatalog", "auth source collides with draft.json")
		}
		manifest.AuthCatalog = &AuthCatalogRef{Path: draft.AuthCatalog.Path, SHA256: RawDigest(nil)}
	}
	if err := validateManifest(manifest, selected, options); err != nil {
		return nil, err
	}
	refs := slices.Clone(manifest.Documents)
	refs = append(refs, globalDocumentRefs(manifest)...)
	if err := checkEntriesNamed(ctx, root, refs, options.Limits.MaxDocuments, "draft.json"); err != nil {
		return nil, err
	}
	files := map[string][]byte{}
	total := int64(len(raw))
	for _, ref := range refs {
		budget := min(options.Limits.MaxDocumentBytes, options.Limits.MaxBundleBytes-total)
		if manifest.IdentityCatalog != nil && ref.Path == manifest.IdentityCatalog.Path {
			budget = min(budget, int64(options.IdentityLimits.MaxIdentityDocumentBytes))
		}
		if manifest.DisclosureCatalog != nil && ref.Path == manifest.DisclosureCatalog.Path {
			budget = min(budget, int64(options.DisclosureLimits.MaxDocumentBytes))
		}
		if manifest.ComplianceCatalog != nil && ref.Path == manifest.ComplianceCatalog.Path {
			budget = min(budget, int64(options.ComplianceLimits.MaxDocumentBytes))
		}
		if manifest.AuthCatalog != nil && ref.Path == manifest.AuthCatalog.Path {
			budget = min(budget, int64(brokerpolicy.MaxSourceBytes))
		}
		if budget <= 0 {
			return nil, fail(LimitExceeded, ref.Kind, ref.OrganizationID, ref.Path, "draft bundle byte budget exceeded")
		}
		bytes, err := readRegular(ctx, root, ref.Path, budget)
		if err != nil {
			return nil, err
		}
		total += int64(len(bytes))
		files[ref.Path] = bytes
	}
	for i := range manifest.Documents {
		manifest.Documents[i].SHA256 = RawDigest(files[manifest.Documents[i].Path])
	}
	if ref := manifest.IdentityCatalog; ref != nil {
		ref.SHA256 = RawDigest(files[ref.Path])
	}
	if ref := manifest.RuntimeCatalog; ref != nil {
		ref.SHA256 = RawDigest(files[ref.Path])
	}
	if ref := manifest.DisclosureCatalog; ref != nil {
		ref.SHA256 = RawDigest(files[ref.Path])
	}
	if ref := manifest.ComplianceCatalog; ref != nil {
		ref.SHA256 = RawDigest(files[ref.Path])
	}
	if ref := manifest.AuthCatalog; ref != nil {
		ref.SHA256 = RawDigest(files[ref.Path])
	}
	snapshot, err := compileSourceSet(ctx, manifest, RawDigest(nil), int64(len(raw)), options, methods, func(name string, budget int64) ([]byte, error) {
		bytes, ok := files[name]
		if !ok {
			return nil, fail(ReadFailure, "", "", name, "draft source file is missing")
		}
		if int64(len(bytes)) > budget {
			return nil, fail(LimitExceeded, "", "", name, "source file exceeds remaining byte budget")
		}
		return bytes, nil
	})
	if err != nil {
		return nil, err
	}
	manifest.RequiredCapabilities = slices.Clone(snapshot.requirements.Capabilities)
	sort.Slice(manifest.Documents, func(i, j int) bool { return manifest.Documents[i].Path < manifest.Documents[j].Path })
	sort.Slice(manifest.Organizations, func(i, j int) bool { return manifest.Organizations[i].ID < manifest.Organizations[j].ID })
	manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return nil, fail(InvalidSchema, "", "", "manifest", "cannot encode prepared manifest")
	}
	manifestBytes = append(manifestBytes, '\n')
	if int64(len(manifestBytes)) > options.Limits.MaxManifestBytes || int64(len(manifestBytes)) > options.Limits.MaxBundleBytes {
		return nil, fail(LimitExceeded, "", "", "manifest", "generated manifest exceeds byte budget")
	}
	artifact := &PreparedArtifact{manifest: manifestBytes, required: snapshot.Requirements()}
	total = int64(len(manifestBytes))
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		bytes := files[name]
		if int64(len(bytes)) > options.Limits.MaxBundleBytes-total {
			return nil, fail(LimitExceeded, "", "", name, "generated artifact exceeds total byte budget")
		}
		total += int64(len(bytes))
		artifact.files = append(artifact.files, PreparedFile{Path: name, Bytes: bytes})
	}
	if err := canceled(ctx); err != nil {
		return nil, err
	}
	return artifact, nil
}
