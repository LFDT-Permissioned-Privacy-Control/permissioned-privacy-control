package policybundle

import (
	"encoding/hex"
	"slices"
	"sort"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"privacy-proxy/internal/policycore"
	"privacy-proxy/internal/pricefeedpolicy"
)

const RuntimeCreationIntentAPIVersion = "ops.runtime-policy/v1alpha6"
const FactoryCreationSubtree = "same-namespace-creation-subtree"
const MaxCreationFactories = 64

// FactoryAttribution is an explicit admission-time attribution scope. Merely
// registering a contract never selects this authority, and a proxy code pin
// does not freeze that proxy's implementation or storage.
type FactoryAttribution struct {
	Address        string `json:"address"`
	OrganizationID string `json:"organizationId"`
	CodeHash       string `json:"codeHash"`
	Scope          string `json:"scope"`
}

type CreationAttribution struct {
	Factories []FactoryAttribution `json:"factories"`
}

// RuntimeCreationIntentSource is deliberately a new closed wire shape. Older
// source accessors cannot drop the approved attribution declaration.
type RuntimeCreationIntentSource struct {
	APIVersion           string                  `json:"apiVersion"`
	Kind                 string                  `json:"kind"`
	ReadProfile          string                  `json:"readProfile"`
	IntraOrgGrantTracing bool                    `json:"intraOrgGrantTracing"`
	SharedInfrastructure []SharedInfrastructure  `json:"sharedInfrastructure"`
	AddressScopes        []AddressScope          `json:"addressScopes"`
	NodeEvidenceProfile  string                  `json:"nodeEvidenceProfile"`
	RawSubmissionMode    string                  `json:"rawSubmissionMode"`
	PriceFeed            *pricefeedpolicy.Source `json:"priceFeed,omitempty" optional:"true"`
	CreationAttribution  CreationAttribution     `json:"creationAttribution"`
}

func (s RuntimeCreationIntentSource) commonSource() RuntimeMultiOrgSource {
	return RuntimeMultiOrgSource{
		APIVersion: s.APIVersion, Kind: s.Kind, ReadProfile: s.ReadProfile,
		IntraOrgGrantTracing: s.IntraOrgGrantTracing,
		SharedInfrastructure: s.SharedInfrastructure, AddressScopes: s.AddressScopes,
		NodeEvidenceProfile: s.NodeEvidenceProfile, RawSubmissionMode: s.RawSubmissionMode,
		PriceFeed: s.PriceFeed,
	}
}

func creationIntentSource(s RuntimeMultiOrgSource, factories []FactoryAttribution) RuntimeCreationIntentSource {
	return RuntimeCreationIntentSource{
		APIVersion: s.APIVersion, Kind: s.Kind, ReadProfile: s.ReadProfile,
		IntraOrgGrantTracing: s.IntraOrgGrantTracing,
		SharedInfrastructure: s.SharedInfrastructure, AddressScopes: s.AddressScopes,
		NodeEvidenceProfile: s.NodeEvidenceProfile, RawSubmissionMode: s.RawSubmissionMode,
		PriceFeed: s.PriceFeed, CreationAttribution: CreationAttribution{Factories: slices.Clone(factories)},
	}
}

func (r *RuntimeCatalog) CreationIntentSource() (RuntimeCreationIntentSource, bool) {
	if r == nil || r.creationIntentSource == nil {
		return RuntimeCreationIntentSource{}, false
	}
	s := *r.creationIntentSource
	s.SharedInfrastructure = cloneShared(s.SharedInfrastructure)
	s.AddressScopes = slices.Clone(s.AddressScopes)
	s.CreationAttribution.Factories = slices.Clone(s.CreationAttribution.Factories)
	if s.PriceFeed != nil {
		feed := r.feedDefinition.Source()
		s.PriceFeed = &feed
	}
	return s, true
}

func (b *catalogBuilder) normalizeCreationFactories(shared []SharedInfrastructure, declared []FactoryAttribution) ([]FactoryAttribution, error) {
	entries := slices.Clone(declared)
	bad := func() ([]FactoryAttribution, error) {
		return nil, fail(InvalidSchema, "", "", "creationAttribution", "invalid approved factory attribution")
	}
	if entries == nil || len(entries) > MaxCreationFactories {
		return bad()
	}
	sharedAddresses := map[common.Address]bool{}
	for _, entry := range shared {
		sharedAddresses[common.HexToAddress(entry.Address)] = true
	}
	seen := map[common.Address]bool{}
	for i := range entries {
		e := &entries[i]
		if len(e.Address) != 42 || !strings.HasPrefix(e.Address, "0x") || !common.IsHexAddress(e.Address) || e.Scope != FactoryCreationSubtree {
			return bad()
		}
		a := common.HexToAddress(e.Address)
		owner, registered := b.addresses[addressKey(e.Address)]
		if a == (common.Address{}) || seen[a] || sharedAddresses[a] || policycore.IsPraguePrecompile(a) || !registered || owner != e.OrganizationID {
			return bad()
		}
		if len(e.CodeHash) != 66 || !strings.HasPrefix(e.CodeHash, "0x") || e.CodeHash != strings.ToLower(e.CodeHash) || common.HexToHash(e.CodeHash) == (common.Hash{}) {
			return bad()
		}
		if _, err := hex.DecodeString(e.CodeHash[2:]); err != nil {
			return bad()
		}
		e.Address = addressKey(e.Address)
		seen[a] = true
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Address < entries[j].Address })
	return entries, nil
}
