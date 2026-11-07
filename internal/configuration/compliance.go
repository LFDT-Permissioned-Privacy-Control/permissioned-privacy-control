package configuration

import (
	"fmt"
	"sort"
	"strings"

	"github.com/ethereum/go-ethereum/common"

	"privacy-proxy/internal/compliance"
	"privacy-proxy/internal/compliancepolicy"
)

type ComplianceSettings struct {
	Enabled            bool    `json:"enabled"`
	ThresholdFiat      float64 `json:"thresholdFiat"`
	Currency           string  `json:"currency"`
	UnknownPricePolicy string  `json:"unknownPricePolicy"`
	EnforcementMode    string  `json:"enforcementMode"`
}
type AddressThreshold struct {
	ID            string  `json:"id"`
	Address       string  `json:"address"`
	ThresholdFiat float64 `json:"thresholdFiat"`
	Note          string  `json:"note"`
}
type TokenPrice struct {
	ID               string             `json:"id"`
	TokenAddress     string             `json:"tokenAddress"`
	Symbol           string             `json:"symbol"`
	Decimals         int                `json:"decimals"`
	PricesByCurrency map[string]float64 `json:"pricesByCurrency"`
	CoingeckoID      string             `json:"coingeckoId"`
}
type ComplianceSpec struct {
	Settings          ComplianceSettings `json:"settings"`
	AddressThresholds []AddressThreshold `json:"addressThresholds"`
	TokenPrices       []TokenPrice       `json:"tokenPrices"`
}

func (ComplianceSpec) configurationKind() Kind { return Compliance }

type ComplianceSnapshot struct {
	Scope          Scope          `json:"scope"`
	ActiveRevision int64          `json:"activeRevision"`
	Spec           ComplianceSpec `json:"spec"`
	ManagedIDs     []string       `json:"managedIds"`
}
type ResourceChange struct {
	Action   string `json:"action"`
	Resource string `json:"resource"`
	ID       string `json:"id"`
}
type ComplianceDiff struct {
	Changes        []ResourceChange `json:"changes"`
	PreservedDrift []string         `json:"preservedDrift"`
	Projection     ComplianceSpec   `json:"projection"`
}

func normalizeCompliance(s *ComplianceSpec) error {
	v := compliancepolicy.SourceSpec{Settings: compliancepolicy.SourceSettings{Enabled: s.Settings.Enabled, ThresholdFiat: s.Settings.ThresholdFiat, Currency: s.Settings.Currency, UnknownPricePolicy: s.Settings.UnknownPricePolicy, EnforcementMode: s.Settings.EnforcementMode}, AddressThresholds: make([]compliancepolicy.SourceThreshold, len(s.AddressThresholds)), TokenPrices: make([]compliancepolicy.SourceTokenPrice, len(s.TokenPrices))}
	for i, r := range s.AddressThresholds {
		v.AddressThresholds[i] = compliancepolicy.SourceThreshold{ID: r.ID, Address: r.Address, ThresholdFiat: r.ThresholdFiat, Note: r.Note}
	}
	for i, r := range s.TokenPrices {
		v.TokenPrices[i] = compliancepolicy.SourceTokenPrice{ID: r.ID, TokenAddress: r.TokenAddress, Symbol: r.Symbol, Decimals: r.Decimals, PricesByCurrency: r.PricesByCurrency, CoingeckoID: r.CoingeckoID}
	}
	if err := compliancepolicy.NormalizeSpec(&v); err != nil {
		return err
	}
	// Preserve the original backing-slice sorting behavior for legacy callers.
	for i, r := range v.AddressThresholds {
		s.AddressThresholds[i] = AddressThreshold{ID: r.ID, Address: r.Address, ThresholdFiat: r.ThresholdFiat, Note: r.Note}
	}
	for i, r := range v.TokenPrices {
		s.TokenPrices[i] = TokenPrice{ID: r.ID, TokenAddress: r.TokenAddress, Symbol: r.Symbol, Decimals: r.Decimals, PricesByCurrency: r.PricesByCurrency, CoingeckoID: r.CoingeckoID}
	}
	return nil
}
func validateComplianceWireNumbers(value any) error { return compliance.ValidateWireNumbers(value) }
func canonicalAddress(v string) bool {
	return len(v) == 42 && strings.ToLower(v) == v && common.IsHexAddress(v)
}

// A non-nil error is a *SourceError.
func DiffCompliance(doc *Document, snapshot ComplianceSnapshot) (ComplianceDiff, error) {
	v0, err := diffCompliance(doc, snapshot)
	if err != nil {
		return v0, sourceError(err)
	}
	return v0, nil
}

// diffCompliance is DiffCompliance before its error is typed.
func diffCompliance(doc *Document, snapshot ComplianceSnapshot) (ComplianceDiff, error) {
	result := ComplianceDiff{Changes: []ResourceChange{}, PreservedDrift: []string{}}
	if doc == nil || doc.Kind != Compliance || doc.Scope != snapshot.Scope || doc.BaseRevision != snapshot.ActiveRevision {
		return result, fmt.Errorf("compliance scope or base changed")
	}
	spec, ok := doc.Spec.(ComplianceSpec)
	if !ok {
		return result, fmt.Errorf("invalid compliance source")
	}
	used := map[string]bool{}
	thresholds, changes, drift, err := diffResources("addressThreshold", snapshot.Spec.AddressThresholds, spec.AddressThresholds, snapshot.ManagedIDs, doc.Deletions, used, func(v AddressThreshold) string { return v.ID })
	if err != nil {
		return result, err
	}
	result.Changes = append(result.Changes, changes...)
	result.PreservedDrift = append(result.PreservedDrift, drift...)
	prices, changes, drift, err := diffResources("tokenPrice", snapshot.Spec.TokenPrices, spec.TokenPrices, snapshot.ManagedIDs, doc.Deletions, used, func(v TokenPrice) string { return v.ID })
	if err != nil {
		return result, err
	}
	result.Changes = append(result.Changes, changes...)
	result.PreservedDrift = append(result.PreservedDrift, drift...)
	for _, del := range doc.Deletions {
		if !used[del.ID] {
			return result, fmt.Errorf("deletion names unknown resource %s", del.ID)
		}
	}
	if snapshot.Spec.Settings != spec.Settings {
		result.Changes = append(result.Changes, ResourceChange{Action: "update", Resource: "settings", ID: "settings"})
	}
	result.Projection = ComplianceSpec{Settings: spec.Settings, AddressThresholds: thresholds, TokenPrices: prices}
	if err := normalizeCompliance(&result.Projection); err != nil {
		return result, err
	}
	sort.Strings(result.PreservedDrift)
	return result, nil
}
