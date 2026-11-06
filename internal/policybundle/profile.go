package policybundle

import (
	"slices"
	"sort"
)

const (
	FoundationProfileID      = "catalog-foundation/v1"
	NativeEvaluatorVersion   = "policycore/native-v1alpha1"
	CapabilityNativeValidate = "catalog.native-validate"
	CapabilityPrincipal      = "inputs.verified-principal"
	CapabilityFrames         = "inputs.complete-frames"
	CapabilityCalldata       = "inputs.calldata"
	CapabilitySigner         = "inputs.verified-signer"
	CapabilityLinkedWallets  = "inputs.linked-wallets"
	CapabilityCaller         = "inputs.immediate-caller"
	CapabilityValue          = "inputs.value"
	CapabilityDepth          = "inputs.depth"
	CapabilityRPCCredential  = "secrets.rpc-credential"
	CapabilityDynamicPayload = "privacy.dynamic-event-payload"
)

// ValidationProfile is opaque: files cannot register validators or enable
// deferred features. Only the fixed validation-only foundation exists here.
type ValidationProfile struct{ id, evaluatorVersion, methodCatalogVersion string }

func FoundationProfile(methodCatalogVersion string) ValidationProfile {
	return ValidationProfile{FoundationProfileID, NativeEvaluatorVersion, methodCatalogVersion}
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
	Limits  Limits
	Profile ValidationProfile
	Methods MethodCatalog
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
	if !options.Limits.valid() || p.id != FoundationProfileID || p.evaluatorVersion != NativeEvaluatorVersion || !boundedName(p.methodCatalogVersion, 128) || options.Methods.Version != p.methodCatalogVersion {
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
