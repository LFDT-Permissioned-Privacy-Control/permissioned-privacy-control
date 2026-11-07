package policybundle

import (
	"encoding/hex"
	"encoding/json"
	"slices"
	"sort"
	"strings"

	"github.com/ethereum/go-ethereum/common"
)

const RuntimeAPIVersion = "ops.runtime-policy/v1alpha1"
const RuntimeKind = "RuntimePolicy"
const RuntimeNodeEvidenceProfileID = "geth-prague-call/v1"

type RuntimeCatalogRef struct {
	Path   string `json:"path"`
	SHA256 Digest `json:"sha256"`
}
type RuntimeCatalogIdentity struct {
	RuntimeCatalogRef
	SemanticDigest Digest
}
type SharedInfrastructure struct {
	Address  string  `json:"address"`
	CodeHash *string `json:"codeHash,omitempty" optional:"true"`
}
type AddressScope struct {
	Address        string `json:"address"`
	OrganizationID string `json:"organizationId"`
}
type RuntimeSource struct {
	APIVersion           string                 `json:"apiVersion"`
	Kind                 string                 `json:"kind"`
	ReadProfile          string                 `json:"readProfile"`
	IntraOrgGrantTracing bool                   `json:"intraOrgGrantTracing"`
	SharedInfrastructure []SharedInfrastructure `json:"sharedInfrastructure"`
	AddressScopes        []AddressScope         `json:"addressScopes"`
	NodeEvidenceProfile  string                 `json:"nodeEvidenceProfile"`
}

// RuntimeCatalog is approved immutable source. Its static scopes never enter
// the registered-contract/native execution or operational ownership indexes.
type RuntimeCatalog struct {
	source RuntimeSource
	digest Digest
}

func (r *RuntimeCatalog) Source() RuntimeSource {
	s := r.source
	s.AddressScopes = slices.Clone(s.AddressScopes)
	s.SharedInfrastructure = slices.Clone(s.SharedInfrastructure)
	for i := range s.SharedInfrastructure {
		if s.SharedInfrastructure[i].CodeHash != nil {
			h := *s.SharedInfrastructure[i].CodeHash
			s.SharedInfrastructure[i].CodeHash = &h
		}
	}
	return s
}
func (r *RuntimeCatalog) Digest() Digest                    { return r.digest }
func (r *RuntimeCatalog) NodeEvidenceProfile() string       { return r.source.NodeEvidenceProfile }
func (s *CatalogSnapshot) Runtime() (*RuntimeCatalog, bool) { return s.runtime, s.runtime != nil }

func (b *catalogBuilder) compileRuntime(limits Limits) error {
	if b.runtimeSource == nil {
		return nil
	}
	s := *b.runtimeSource
	bad := func(field, message string) error { return fail(InvalidSchema, "", "", field, message) }
	if s.APIVersion != RuntimeAPIVersion || s.Kind != RuntimeKind || (s.ReadProfile != "standard" && s.ReadProfile != "strict") || s.NodeEvidenceProfile != RuntimeNodeEvidenceProfileID {
		return bad("runtimeCatalog", "unsupported runtime schema/profile")
	}
	if len(s.SharedInfrastructure) > min(4096, limits.MaxContractsPerOrg) || len(s.AddressScopes) > min(4096, limits.MaxContractsPerOrg) {
		return fail(LimitExceeded, "", "", "runtimeCatalog", "runtime address budget exceeded")
	}
	orgs := map[string]bool{}
	for _, org := range b.snapshot.organizations {
		orgs[org.ID] = true
	}
	seen := map[common.Address]bool{}
	for i := range s.SharedInfrastructure {
		item := &s.SharedInfrastructure[i]
		if !common.IsHexAddress(item.Address) || len(item.Address) != 42 || !strings.HasPrefix(item.Address, "0x") {
			return bad("sharedInfrastructure.address", "invalid shared address")
		}
		a := common.HexToAddress(item.Address)
		if a == (common.Address{}) || seen[a] {
			return bad("sharedInfrastructure.address", "zero or duplicate shared address")
		}
		seen[a] = true
		item.Address = addressKey(item.Address)
		if item.CodeHash != nil {
			hash := *item.CodeHash
			if len(hash) != 66 || !strings.HasPrefix(hash, "0x") || hash != strings.ToLower(hash) {
				return bad("sharedInfrastructure.codeHash", "noncanonical code hash")
			}
			if _, e := hex.DecodeString(hash[2:]); e != nil {
				return bad("sharedInfrastructure.codeHash", "invalid code hash")
			}
			copyHash := hash
			item.CodeHash = &copyHash
		}
	}
	b.runtimeScopes = map[string]string{}
	for i := range s.AddressScopes {
		item := &s.AddressScopes[i]
		if !common.IsHexAddress(item.Address) || len(item.Address) != 42 || !strings.HasPrefix(item.Address, "0x") || common.HexToAddress(item.Address) == (common.Address{}) || !orgs[item.OrganizationID] {
			return bad("addressScopes", "invalid scope address or organization")
		}
		item.Address = addressKey(item.Address)
		if _, duplicate := b.runtimeScopes[item.Address]; duplicate {
			return bad("addressScopes", "duplicate static scope address")
		}
		if owner, known := b.addresses[item.Address]; known && owner != item.OrganizationID {
			return fail(ReferenceFailure, "", item.OrganizationID, "addressScopes", "scope conflicts with registered owner")
		}
		b.runtimeScopes[item.Address] = item.OrganizationID
	}
	sort.Slice(s.SharedInfrastructure, func(i, j int) bool { return s.SharedInfrastructure[i].Address < s.SharedInfrastructure[j].Address })
	sort.Slice(s.AddressScopes, func(i, j int) bool { return s.AddressScopes[i].Address < s.AddressScopes[j].Address })
	raw, _ := json.Marshal(s)
	digest := RawDigest(raw)
	b.snapshot.runtime = &RuntimeCatalog{source: s, digest: digest}
	b.snapshot.metadata.RuntimeCatalog = &RuntimeCatalogIdentity{RuntimeCatalogRef: *b.runtimeRef, SemanticDigest: digest}
	if len(s.SharedInfrastructure) > 0 {
		b.capabilities[CapabilitySharedCode] = true
	}
	if len(s.AddressScopes) > 0 {
		b.capabilities[CapabilityAddressScopes] = true
	}
	return nil
}
