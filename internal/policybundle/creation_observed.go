package policybundle

import (
	"slices"

	"privacy-proxy/internal/creationfacts"
	"privacy-proxy/internal/pricefeedpolicy"
)

const RuntimeCreationObservedAPIVersion = "ops.runtime-policy/v1alpha7"

// RuntimeCreationObservedSource requires original capture-time coverage. Earlier
// source variants remain truthful journal-only or execution-only integrations.
type RuntimeCreationObservedSource struct {
	APIVersion              string                  `json:"apiVersion"`
	Kind                    string                  `json:"kind"`
	ReadProfile             string                  `json:"readProfile"`
	IntraOrgGrantTracing    bool                    `json:"intraOrgGrantTracing"`
	SharedInfrastructure    []SharedInfrastructure  `json:"sharedInfrastructure"`
	AddressScopes           []AddressScope          `json:"addressScopes"`
	NodeEvidenceProfile     string                  `json:"nodeEvidenceProfile"`
	RawSubmissionMode       string                  `json:"rawSubmissionMode"`
	PriceFeed               *pricefeedpolicy.Source `json:"priceFeed,omitempty" optional:"true"`
	CreationAttribution     CreationAttribution     `json:"creationAttribution"`
	CaptureReadinessProfile string                  `json:"captureReadinessProfile"`
}

func (s RuntimeCreationObservedSource) commonSource() RuntimeMultiOrgSource {
	return RuntimeMultiOrgSource{APIVersion: s.APIVersion, Kind: s.Kind, ReadProfile: s.ReadProfile, IntraOrgGrantTracing: s.IntraOrgGrantTracing, SharedInfrastructure: s.SharedInfrastructure, AddressScopes: s.AddressScopes, NodeEvidenceProfile: s.NodeEvidenceProfile, RawSubmissionMode: s.RawSubmissionMode, PriceFeed: s.PriceFeed}
}
func creationObservedSource(s RuntimeMultiOrgSource, factories []FactoryAttribution) RuntimeCreationObservedSource {
	return RuntimeCreationObservedSource{APIVersion: s.APIVersion, Kind: s.Kind, ReadProfile: s.ReadProfile, IntraOrgGrantTracing: s.IntraOrgGrantTracing, SharedInfrastructure: s.SharedInfrastructure, AddressScopes: s.AddressScopes, NodeEvidenceProfile: s.NodeEvidenceProfile, RawSubmissionMode: s.RawSubmissionMode, PriceFeed: s.PriceFeed, CreationAttribution: CreationAttribution{Factories: slices.Clone(factories)}, CaptureReadinessProfile: creationfacts.CaptureProfile}
}
func (r *RuntimeCatalog) CreationObservedSource() (RuntimeCreationObservedSource, bool) {
	if r == nil || r.creationObservedSource == nil {
		return RuntimeCreationObservedSource{}, false
	}
	s := *r.creationObservedSource
	s.SharedInfrastructure = cloneShared(s.SharedInfrastructure)
	s.AddressScopes = slices.Clone(s.AddressScopes)
	s.CreationAttribution.Factories = slices.Clone(s.CreationAttribution.Factories)
	if s.PriceFeed != nil {
		feed := r.feedDefinition.Source()
		s.PriceFeed = &feed
	}
	return s, true
}
