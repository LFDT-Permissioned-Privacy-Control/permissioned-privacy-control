package policybundle

import (
	"slices"
	"sort"

	"privacy-proxy/internal/compliancepolicy"
	"privacy-proxy/internal/disclosurepolicy"
	"privacy-proxy/internal/identity"
)

const (
	FoundationProfileID              = "catalog-foundation/v1"
	IdentityProfileID                = "catalog-identity/v1"
	NativeV2ProfileID                = "catalog-native-v2/v1"
	RuntimeCallProfileID             = "catalog-runtime-call/v1"
	RuntimeRawSendProfileID          = "catalog-runtime-raw-send/v1"
	RuntimeMultiOrgProfileID         = "catalog-runtime-multi-org/v1"
	RuntimeLifecycleProfileID        = "catalog-runtime-lifecycle/v1"
	RuntimeSimulationProfileID       = "catalog-runtime-simulation/v1"
	RuntimeCreationIntentProfileID   = "catalog-runtime-creation-intent/v1"
	RuntimeCreationObservedProfileID = "catalog-runtime-creation-observed/v1"
	DisclosureProfileID              = "catalog-disclosure/v1"
	ComplianceProfileID              = "catalog-compliance/v1"
	BrokerProfileID                  = "catalog-broker/v1"
	BrokerMultiProfileID             = "catalog-broker-multi/v1"
	CapabilityIdentity               = "identity.claims/v1"
	NativeEvaluatorVersion           = "policycore/native-v1alpha1"
	NativeV2EvaluatorVersion         = "policycore/native-v1alpha2"
	NativeV3EvaluatorVersion         = "policycore/native-v1alpha3"
	NativeV4EvaluatorVersion         = "policycore/native-v1alpha4"
	CapabilityNativeValidate         = "catalog.native-validate"
	CapabilityPrincipal              = "inputs.verified-principal"
	CapabilityFrames                 = "inputs.complete-frames"
	CapabilityCalldata               = "inputs.calldata"
	CapabilitySigner                 = "inputs.verified-signer"
	CapabilityLinkedWallets          = "inputs.linked-wallets"
	CapabilityCaller                 = "inputs.immediate-caller"
	CapabilityValue                  = "inputs.value"
	CapabilityDepth                  = "inputs.depth"
	CapabilityRPCCredential          = "secrets.rpc-credential"
	CapabilityDynamicPayload         = "privacy.dynamic-event-payload"
	CapabilityRuntimeCall            = "runtime.eth-call/v1"
	CapabilityRuntimeRawSend         = "runtime.raw-send/v1"
	CapabilityAdmission              = "operational.admission/v1"
	CapabilityWalletProofs           = "operational.wallet-proofs/v1"
	CapabilityGuardDelivery          = "delivery.guard-v1/v1"
	CapabilitySignedCall             = "acquisition.signed-call/v1"
	CapabilityAnchoredCode           = "inputs.anchored-code/v1"
	CapabilityClassification         = "inputs.classification"
	CapabilityOwnership              = "inputs.ownership"
	CapabilitySharedCode             = "inputs.shared-code"
	CapabilityUpgradeFacts           = "inputs.upgrade-facts"
	CapabilityAddressScopes          = "policy.address-scopes/v1"
	CapabilityMultiOrg               = "runtime.multi-org-execution/v1"
	CapabilityForeignCode            = "inputs.foreign-code-access/v1"
	CapabilityPriceFeed              = "operational.price-feed/v1"
	CapabilityLifecycle              = "runtime.lifecycle/v1"
	CapabilityTemporalCode           = "inputs.temporal-code/v1"
	CapabilityCreationContext        = "inputs.creation-context/v1"
	CapabilityLifecycleBeneficiary   = "inputs.lifecycle-beneficiary/v1"
	CapabilityUnsignedSimulation     = "runtime.unsigned-create-simulation/v1"
	CapabilityCreationIntents        = "operational.creation-intent/v1"
	CapabilityCreationCoverage       = "operational.creation-capture-coverage/v1"
)

// ValidationProfile is opaque: files cannot register validators or enable
// deferred features. The fixed profiles remain validation-only libraries.
type ValidationProfile struct{ id, evaluatorVersion, methodCatalogVersion string }

func FoundationProfile(methodCatalogVersion string) ValidationProfile {
	return ValidationProfile{FoundationProfileID, NativeEvaluatorVersion, methodCatalogVersion}
}

func IdentityProfile(methodCatalogVersion string) ValidationProfile {
	return ValidationProfile{IdentityProfileID, NativeEvaluatorVersion, methodCatalogVersion}
}

// NativeV2Profile validates native-v2 depth bounds with identity and the same
// bounded static rule matrix. It does not enable operational target classes.
func NativeV2Profile(methodCatalogVersion string) ValidationProfile {
	return ValidationProfile{NativeV2ProfileID, NativeV2EvaluatorVersion, methodCatalogVersion}
}

// RuntimeCallProfile selects only the qualified eth_call integration. Other
// runtime methods and lifecycle/deployment evidence require successor profiles.
func RuntimeCallProfile(methodCatalogVersion string) ValidationProfile {
	return ValidationProfile{RuntimeCallProfileID, NativeV2EvaluatorVersion, methodCatalogVersion}
}

// RuntimeRawSendProfile composes the call and bounded signed CALL consumers
// with approved compliance. Deployment and lifecycle inputs remain unsupported.
func RuntimeRawSendProfile(methodCatalogVersion string) ValidationProfile {
	return ValidationProfile{RuntimeRawSendProfileID, NativeV2EvaluatorVersion, methodCatalogVersion}
}

// RuntimeMultiOrgProfile adds qualified private calls across mapped orgs and
// approved optional feed definitions. Lifecycle/history still require successors.
func RuntimeMultiOrgProfile(methodCatalogVersion string) ValidationProfile {
	return ValidationProfile{RuntimeMultiOrgProfileID, NativeV3EvaluatorVersion, methodCatalogVersion}
}

func RuntimeLifecycleProfile(methodCatalogVersion string) ValidationProfile {
	return ValidationProfile{RuntimeLifecycleProfileID, NativeV4EvaluatorVersion, methodCatalogVersion}
}

func RuntimeSimulationProfile(methodCatalogVersion string) ValidationProfile {
	return ValidationProfile{RuntimeSimulationProfileID, NativeV4EvaluatorVersion, methodCatalogVersion}
}

func RuntimeCreationIntentProfile(methodCatalogVersion string) ValidationProfile {
	return ValidationProfile{RuntimeCreationIntentProfileID, NativeV4EvaluatorVersion, methodCatalogVersion}
}

func RuntimeCreationObservedProfile(methodCatalogVersion string) ValidationProfile {
	return ValidationProfile{RuntimeCreationObservedProfileID, NativeV4EvaluatorVersion, methodCatalogVersion}
}

func lifecycleRuntimeProfile(id string) bool {
	return id == RuntimeLifecycleProfileID || id == RuntimeSimulationProfileID || id == RuntimeCreationIntentProfileID || id == RuntimeCreationObservedProfileID
}

func multiOrgRuntimeProfile(id string) bool {
	return id == RuntimeMultiOrgProfileID || lifecycleRuntimeProfile(id)
}

func runtimeProfile(id string) bool {
	return id == RuntimeCallProfileID || rawRuntimeProfile(id)
}

func rawRuntimeProfile(id string) bool {
	return id == RuntimeRawSendProfileID || multiOrgRuntimeProfile(id)
}

// DisclosureProfile validates explicit rules and identity with the native-v2
// static matrix. It does not attest operational stores or data/report handlers.
func DisclosureProfile(methodCatalogVersion string) ValidationProfile {
	return ValidationProfile{DisclosureProfileID, NativeV2EvaluatorVersion, methodCatalogVersion}
}

func ComplianceProfile(methodCatalogVersion string) ValidationProfile {
	return ValidationProfile{ComplianceProfileID, NativeV2EvaluatorVersion, methodCatalogVersion}
}

func BrokerMultiProfile(methodCatalogVersion string) ValidationProfile {
	return ValidationProfile{BrokerMultiProfileID, NativeV2EvaluatorVersion, methodCatalogVersion}
}

func BrokerProfile(methodCatalogVersion string) ValidationProfile {
	return ValidationProfile{BrokerProfileID, NativeV2EvaluatorVersion, methodCatalogVersion}
}

// MethodCatalog is trusted startup data. Names are exact; aliases carry no
// implicit passthrough authority. Wildcard is an explicit subset of Assignable.
type MethodCatalog struct {
	Version        string
	Assignable     []string
	Aliases        map[string]string
	Wildcard       []string
	RequiredClaims map[string]string
}

type Options struct {
	Limits           Limits
	Profile          ValidationProfile
	Methods          MethodCatalog
	IdentityLimits   identity.Limits
	DisclosureLimits disclosurepolicy.Limits
	ComplianceLimits compliancepolicy.Limits
}

type Requirements struct {
	Capabilities []string
	SecretRefs   []string
}

type methodIndex struct {
	assignable     map[string]bool
	aliases        map[string]string
	wildcard       []string
	requiredClaims map[string]string
}

func prepareOptions(options Options) (methodIndex, error) {
	p := options.Profile
	expectedEvaluator := NativeEvaluatorVersion
	if p.id == NativeV2ProfileID || p.id == RuntimeCallProfileID || p.id == RuntimeRawSendProfileID || p.id == DisclosureProfileID || p.id == ComplianceProfileID || p.id == BrokerProfileID || p.id == BrokerMultiProfileID {
		expectedEvaluator = NativeV2EvaluatorVersion
	}
	if p.id == RuntimeMultiOrgProfileID {
		expectedEvaluator = NativeV3EvaluatorVersion
	}
	if lifecycleRuntimeProfile(p.id) {
		expectedEvaluator = NativeV4EvaluatorVersion
	}
	if !options.Limits.valid() || (p.id != FoundationProfileID && p.id != IdentityProfileID && p.id != NativeV2ProfileID && !runtimeProfile(p.id) && p.id != DisclosureProfileID && p.id != ComplianceProfileID && p.id != BrokerProfileID && p.id != BrokerMultiProfileID) || (p.id != FoundationProfileID && !options.IdentityLimits.Valid()) || (p.id == DisclosureProfileID && !options.DisclosureLimits.Valid()) || ((p.id == ComplianceProfileID || rawRuntimeProfile(p.id)) && !options.ComplianceLimits.Valid()) || p.evaluatorVersion != expectedEvaluator || !boundedName(p.methodCatalogVersion, 128) || options.Methods.Version != p.methodCatalogVersion {
		return methodIndex{}, fail(InvalidSelection, "", "", "options", "invalid limits or pinned foundation/method profile")
	}
	m := methodIndex{map[string]bool{}, map[string]string{}, slices.Clone(options.Methods.Wildcard), map[string]string{}}
	for _, name := range options.Methods.Assignable {
		if !methodPattern.MatchString(name) || name == "*" || m.assignable[name] {
			return methodIndex{}, fail(InvalidSelection, "", "", "methods", "invalid or duplicate assignable method")
		}
		m.assignable[name] = true
	}
	for name, target := range options.Methods.Aliases {
		if name == target || !m.assignable[name] || !m.assignable[target] {
			return methodIndex{}, fail(InvalidSelection, "", "", "methods.aliases", "alias must name distinct declared assignable methods")
		}
		if _, chain := options.Methods.Aliases[target]; chain {
			return methodIndex{}, fail(InvalidSelection, "", "", "methods.aliases", "alias chains are not supported")
		}
		m.aliases[name] = target
	}
	if err := sortUnique(m.wildcard); err != nil {
		return methodIndex{}, fail(InvalidSelection, "", "", "methods.wildcard", err.Error())
	}
	for _, name := range m.wildcard {
		if !m.assignable[name] {
			return methodIndex{}, fail(InvalidSelection, "", "", "methods.wildcard", "wildcard contains an unassignable method")
		}
	}
	for name, claim := range options.Methods.RequiredClaims {
		if !m.assignable[name] || !knownClaim(claim) {
			return methodIndex{}, fail(InvalidSelection, "", "", "methods.requiredClaims", "invalid method or required claim")
		}
		m.requiredClaims[name] = claim
	}
	return m, nil
}

func compareCapabilities(declared []string, inferred map[string]bool) error {
	if err := sortUnique(declared); err != nil {
		return fail(CapabilityMismatch, "", "", "requiredCapabilities", err.Error())
	}
	want := make([]string, 0, len(inferred))
	for name := range inferred {
		want = append(want, name)
	}
	sort.Strings(want)
	if !slices.Equal(declared, want) {
		for _, name := range want {
			if !slices.Contains(declared, name) {
				return fail(CapabilityMismatch, "", "", "requiredCapabilities", "missing inferred capability "+name)
			}
		}
		for _, name := range declared {
			if !inferred[name] {
				return fail(CapabilityMismatch, "", "", "requiredCapabilities", "unknown or unused capability "+name)
			}
		}
	}
	return nil
}
