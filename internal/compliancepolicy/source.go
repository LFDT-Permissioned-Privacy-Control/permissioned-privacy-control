// Package compliancepolicy compiles approved, immutable compliance settings.
// It performs no provider request, SQL operation or admission check.
package compliancepolicy

const APIVersion = "ops.compliance-policy/v1alpha1"
const Kind = "CompliancePolicy"

type SourceSettings struct {
	Enabled            bool    `json:"enabled"`
	ThresholdFiat      float64 `json:"thresholdFiat"`
	Currency           string  `json:"currency"`
	UnknownPricePolicy string  `json:"unknownPricePolicy"`
	EnforcementMode    string  `json:"enforcementMode"`
}
type SourceThreshold struct {
	ID            string  `json:"id"`
	Address       string  `json:"address"`
	ThresholdFiat float64 `json:"thresholdFiat"`
	Note          string  `json:"note"`
}
type SourceTokenPrice struct {
	ID               string             `json:"id"`
	TokenAddress     string             `json:"tokenAddress"`
	Symbol           string             `json:"symbol"`
	Decimals         int                `json:"decimals"`
	PricesByCurrency map[string]float64 `json:"pricesByCurrency"`
	CoingeckoID      string             `json:"coingeckoId"`
}
type SourceSpec struct {
	Settings          SourceSettings     `json:"settings"`
	AddressThresholds []SourceThreshold  `json:"addressThresholds"`
	TokenPrices       []SourceTokenPrice `json:"tokenPrices"`
}
type OrganizationPolicy struct {
	OrganizationID     string     `json:"organizationId"`
	Spec               SourceSpec `json:"spec"`
	RecordMaxSeconds   int64      `json:"recordMaxSeconds"`
	PriceMaxAgeSeconds int64      `json:"priceMaxAgeSeconds"`
}
type SourceSanction struct {
	ID             string `json:"id"`
	Scope          string `json:"scope"`
	OrganizationID string `json:"organizationId"`
	Address        string `json:"address"`
	Reason         string `json:"reason"`
	Source         string `json:"source"`
}
type Source struct {
	APIVersion    string               `json:"apiVersion"`
	Kind          string               `json:"kind"`
	Organizations []OrganizationPolicy `json:"organizations"`
	Sanctions     []SourceSanction     `json:"sanctions"`
}

type Limits struct {
	MaxDocumentBytes, MaxJSONDepth, MaxOrganizations, MaxThresholds, MaxTokenPrices, MaxSanctions, MaxStringBytes int
}

func DefaultLimits() Limits { return Limits{1 << 20, 32, 256, 4096, 4096, 4096, 1 << 20} }
func (l Limits) Valid() bool {
	return l.MaxDocumentBytes > 0 && l.MaxDocumentBytes <= 1<<20 && l.MaxJSONDepth > 0 && l.MaxJSONDepth <= 32 && l.MaxOrganizations > 0 && l.MaxOrganizations <= 256 && l.MaxThresholds > 0 && l.MaxThresholds <= 4096 && l.MaxTokenPrices > 0 && l.MaxTokenPrices <= 4096 && l.MaxSanctions > 0 && l.MaxSanctions <= 4096 && l.MaxStringBytes > 0 && l.MaxStringBytes <= 1<<20
}

// OrgIndex is used and discarded during compilation only.
type OrgIndex interface{ OrganizationIDs() []string }
