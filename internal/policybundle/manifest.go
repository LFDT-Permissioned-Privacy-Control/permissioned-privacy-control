// Package policybundle validates one deployment-selected, immutable local
// artifact. It supplies catalogs, not a running authorization service. The
// foundation profile cannot attest runtime providers or production readiness.
package policybundle

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

const (
	BundleAPIVersion   = "ops.policy-bundle/v1alpha1"
	DocumentAPIVersion = "ops.policy-document/v1alpha1"
	BundleKind         = "PolicyBundle"
)

type Digest string

// RawDigest identifies the exact bytes, before parsing or normalization.
func RawDigest(raw []byte) Digest {
	sum := sha256.Sum256(raw)
	return Digest("sha256:" + hex.EncodeToString(sum[:]))
}

func validDigest(d Digest) bool {
	s := string(d)
	if len(s) != 71 || !strings.HasPrefix(s, "sha256:") || s != strings.ToLower(s) {
		return false
	}
	_, err := hex.DecodeString(s[7:])
	return err == nil
}

// Selection comes from trusted deployment configuration, never an RPC caller
// or a digest file found alongside the artifact being checked.
type Selection struct {
	Directory              string
	ExpectedManifestDigest Digest
	ExpectedEnvironment    string
	ExpectedChainID        string
}

type Manifest struct {
	APIVersion           string                `json:"apiVersion"`
	Kind                 string                `json:"kind"`
	Environment          string                `json:"environment"`
	ChainID              string                `json:"chainId"`
	EvaluatorVersion     string                `json:"evaluatorVersion"`
	Profile              string                `json:"profile"`
	SourceRevision       string                `json:"sourceRevision"`
	Organizations        []Organization        `json:"organizations"`
	RequiredCapabilities []string              `json:"requiredCapabilities"`
	Documents            []DocumentRef         `json:"documents"`
	IdentityCatalog      *IdentityCatalogRef   `json:"identityCatalog,omitempty" optional:"true"`
	RuntimeCatalog       *RuntimeCatalogRef    `json:"runtimeCatalog,omitempty" optional:"true"`
	DisclosureCatalog    *DisclosureCatalogRef `json:"disclosureCatalog,omitempty" optional:"true"`
	ComplianceCatalog    *ComplianceCatalogRef `json:"complianceCatalog,omitempty" optional:"true"`
}

type DisclosureCatalogRef struct {
	Path   string `json:"path"`
	SHA256 Digest `json:"sha256"`
}
type ComplianceCatalogRef struct {
	Path   string `json:"path"`
	SHA256 Digest `json:"sha256"`
}
type ComplianceCatalogIdentity struct {
	ComplianceCatalogRef
	SemanticDigest Digest
}
type DisclosureCatalogIdentity struct {
	DisclosureCatalogRef
	SemanticDigest Digest
}

type IdentityCatalogRef struct {
	Path   string `json:"path"`
	SHA256 Digest `json:"sha256"`
}
type IdentityCatalogIdentity struct {
	IdentityCatalogRef
	SemanticDigest Digest
}

type Organization struct {
	ID   string `json:"id"`
	Slug string `json:"slug"`
	Name string `json:"name"`
}

type DocumentRef struct {
	Kind           Kind   `json:"kind"`
	OrganizationID string `json:"organizationId"`
	Path           string `json:"path"`
	SHA256         Digest `json:"sha256"`
}

type BundleMetadata struct {
	ManifestDigest       Digest
	Environment          string
	ChainID              string
	EvaluatorVersion     string
	Profile              string
	MethodCatalogVersion string
	SourceRevision       string
	Documents            []DocumentIdentity
	IdentityCatalog      *IdentityCatalogIdentity
	RuntimeCatalog       *RuntimeCatalogIdentity
	DisclosureCatalog    *DisclosureCatalogIdentity
	ComplianceCatalog    *ComplianceCatalogIdentity
}

// RawDigest pins the approved file. SemanticDigest identifies its normalized
// source; PolicyDigest separately identifies the native policy alone.
type DocumentIdentity struct {
	DocumentRef
	SemanticDigest Digest
	PolicyDigest   string
}
