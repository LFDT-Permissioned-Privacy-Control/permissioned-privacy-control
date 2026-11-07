// Package policyprofiles selects compiled policy validation profiles for tools
// and startup. A source document cannot register a validator or runtime feature.
package policyprofiles

import (
	"fmt"

	"privacy-proxy/internal/compliancepolicy"
	"privacy-proxy/internal/disclosurepolicy"
	"privacy-proxy/internal/identity"
	"privacy-proxy/internal/policybundle"
	"privacy-proxy/internal/rpcmethoddata"
)

type Description struct {
	ID                   string `json:"id"`
	EvaluatorVersion     string `json:"evaluatorVersion"`
	MethodCatalogVersion string `json:"methodCatalogVersion"`
	ValidationOnly       bool   `json:"validationOnly"`
	IntegrationScope     string `json:"integrationScope,omitempty"`
}

func Supported() []Description {
	return []Description{
		{ID: policybundle.FoundationProfileID, EvaluatorVersion: policybundle.NativeEvaluatorVersion, MethodCatalogVersion: rpcmethoddata.Version, ValidationOnly: true},
		{ID: policybundle.IdentityProfileID, EvaluatorVersion: policybundle.NativeEvaluatorVersion, MethodCatalogVersion: rpcmethoddata.Version, ValidationOnly: true},
		{ID: policybundle.NativeV2ProfileID, EvaluatorVersion: policybundle.NativeV2EvaluatorVersion, MethodCatalogVersion: rpcmethoddata.Version, ValidationOnly: true},
		{ID: policybundle.RuntimeCallProfileID, EvaluatorVersion: policybundle.NativeV2EvaluatorVersion, MethodCatalogVersion: rpcmethoddata.Version, ValidationOnly: true, IntegrationScope: "eth_call integration slice; not a complete runtime"},
		{ID: policybundle.RuntimeRawSendProfileID, EvaluatorVersion: policybundle.NativeV2EvaluatorVersion, MethodCatalogVersion: rpcmethoddata.Version, ValidationOnly: true, IntegrationScope: "eth_call and raw CALL submission integration; not a complete runtime"},
		{ID: policybundle.RuntimeMultiOrgProfileID, EvaluatorVersion: policybundle.NativeV3EvaluatorVersion, MethodCatalogVersion: rpcmethoddata.Version, ValidationOnly: true, IntegrationScope: "multi-org eth_call and raw CALL integration; not a complete runtime"},
		{ID: policybundle.RuntimeLifecycleProfileID, EvaluatorVersion: policybundle.NativeV4EvaluatorVersion, MethodCatalogVersion: rpcmethoddata.Version, ValidationOnly: true, IntegrationScope: "lifecycle eth_call and signed deployment integration; not a complete runtime"},
		{ID: policybundle.RuntimeSimulationProfileID, EvaluatorVersion: policybundle.NativeV4EvaluatorVersion, MethodCatalogVersion: rpcmethoddata.Version, ValidationOnly: true, IntegrationScope: "unsigned deployment simulation and lifecycle signed integration; not a complete runtime"},
		{ID: policybundle.RuntimeCreationIntentProfileID, EvaluatorVersion: policybundle.NativeV4EvaluatorVersion, MethodCatalogVersion: rpcmethoddata.Version, ValidationOnly: true, IntegrationScope: "atomic creation intent recording; no observed ownership or pending authority"},
		{ID: policybundle.DisclosureProfileID, EvaluatorVersion: policybundle.NativeV2EvaluatorVersion, MethodCatalogVersion: rpcmethoddata.Version, ValidationOnly: true},
		{ID: policybundle.ComplianceProfileID, EvaluatorVersion: policybundle.NativeV2EvaluatorVersion, MethodCatalogVersion: rpcmethoddata.Version, ValidationOnly: true},
		{ID: policybundle.BrokerMultiProfileID, EvaluatorVersion: policybundle.NativeV2EvaluatorVersion, MethodCatalogVersion: rpcmethoddata.Version, ValidationOnly: true},
		{ID: policybundle.BrokerProfileID, EvaluatorVersion: policybundle.NativeV2EvaluatorVersion, MethodCatalogVersion: rpcmethoddata.Version, ValidationOnly: true},
	}
}

func Options(id string) (policybundle.Options, Description, error) {
	seed := rpcmethoddata.BuiltinCatalog()
	options := policybundle.Options{Limits: policybundle.DefaultLimits(), Methods: policybundle.MethodCatalog{
		Version: seed.Version, Assignable: seed.Assignable, Aliases: seed.Aliases,
		Wildcard: seed.Wildcard, RequiredClaims: seed.RequiredClaims,
	}}
	evaluator := policybundle.NativeEvaluatorVersion
	switch id {
	case policybundle.FoundationProfileID:
		options.Profile = policybundle.FoundationProfile(seed.Version)
	case policybundle.IdentityProfileID:
		options.Profile = policybundle.IdentityProfile(seed.Version)
		options.IdentityLimits = identity.DefaultLimits()
	case policybundle.NativeV2ProfileID:
		options.Profile = policybundle.NativeV2Profile(seed.Version)
		options.IdentityLimits = identity.DefaultLimits()
		evaluator = policybundle.NativeV2EvaluatorVersion
	case policybundle.RuntimeCallProfileID:
		options.Profile = policybundle.RuntimeCallProfile(seed.Version)
		options.IdentityLimits = identity.DefaultLimits()
		evaluator = policybundle.NativeV2EvaluatorVersion
	case policybundle.DisclosureProfileID:
		options.Profile = policybundle.DisclosureProfile(seed.Version)
		options.IdentityLimits = identity.DefaultLimits()
		options.DisclosureLimits = disclosurepolicy.DefaultLimits()
		evaluator = policybundle.NativeV2EvaluatorVersion
	case policybundle.RuntimeRawSendProfileID:
		options.Profile = policybundle.RuntimeRawSendProfile(seed.Version)
		options.IdentityLimits = identity.DefaultLimits()
		options.ComplianceLimits = compliancepolicy.DefaultLimits()
		evaluator = policybundle.NativeV2EvaluatorVersion
	case policybundle.RuntimeMultiOrgProfileID:
		options.Profile = policybundle.RuntimeMultiOrgProfile(seed.Version)
		options.IdentityLimits = identity.DefaultLimits()
		options.ComplianceLimits = compliancepolicy.DefaultLimits()
		evaluator = policybundle.NativeV3EvaluatorVersion
	case policybundle.ComplianceProfileID:
		options.Profile = policybundle.ComplianceProfile(seed.Version)
		options.IdentityLimits = identity.DefaultLimits()
		options.ComplianceLimits = compliancepolicy.DefaultLimits()
		evaluator = policybundle.NativeV2EvaluatorVersion
	case policybundle.RuntimeLifecycleProfileID:
		options.Profile = policybundle.RuntimeLifecycleProfile(seed.Version)
		options.IdentityLimits = identity.DefaultLimits()
		options.ComplianceLimits = compliancepolicy.DefaultLimits()
		evaluator = policybundle.NativeV4EvaluatorVersion
	case policybundle.RuntimeSimulationProfileID:
		options.Profile = policybundle.RuntimeSimulationProfile(seed.Version)
		options.IdentityLimits = identity.DefaultLimits()
		options.ComplianceLimits = compliancepolicy.DefaultLimits()
		evaluator = policybundle.NativeV4EvaluatorVersion
	case policybundle.RuntimeCreationIntentProfileID:
		options.Profile = policybundle.RuntimeCreationIntentProfile(seed.Version)
		options.IdentityLimits = identity.DefaultLimits()
		options.ComplianceLimits = compliancepolicy.DefaultLimits()
		evaluator = policybundle.NativeV4EvaluatorVersion
	case policybundle.BrokerMultiProfileID:
		options.Profile = policybundle.BrokerMultiProfile(seed.Version)
		options.IdentityLimits = identity.DefaultLimits()
		evaluator = policybundle.NativeV2EvaluatorVersion
	case policybundle.BrokerProfileID:
		options.Profile = policybundle.BrokerProfile(seed.Version)
		options.IdentityLimits = identity.DefaultLimits()
		evaluator = policybundle.NativeV2EvaluatorVersion
	default:
		return policybundle.Options{}, Description{}, fmt.Errorf("unsupported compiled policy profile %q", id)
	}
	description := Description{ID: id, EvaluatorVersion: evaluator, MethodCatalogVersion: seed.Version, ValidationOnly: true}
	if id == policybundle.RuntimeCallProfileID {
		description.IntegrationScope = "eth_call integration slice; not a complete runtime"
	}
	if id == policybundle.RuntimeRawSendProfileID {
		description.IntegrationScope = "eth_call and raw CALL submission integration; not a complete runtime"
	}
	if id == policybundle.RuntimeMultiOrgProfileID {
		description.IntegrationScope = "multi-org eth_call and raw CALL integration; not a complete runtime"
	}
	if id == policybundle.RuntimeLifecycleProfileID {
		description.IntegrationScope = "lifecycle eth_call and signed deployment integration; not a complete runtime"
	}
	if id == policybundle.RuntimeSimulationProfileID {
		description.IntegrationScope = "unsigned deployment simulation and lifecycle signed integration; not a complete runtime"
	}
	if id == policybundle.RuntimeCreationIntentProfileID {
		description.IntegrationScope = "atomic creation intent recording; no observed ownership or pending authority"
	}
	return options, description, nil
}
