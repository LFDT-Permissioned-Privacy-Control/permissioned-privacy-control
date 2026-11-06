package evm

import (
	"errors"
	"testing"

	"privacy-proxy/internal/policycore"
)

func TestAllBackendEntryPointsRejectNativeV2BeforeCompilerLookup(t *testing.T) {
	// A nonexistent compiler must never mask the source-version error. Include
	// zero bindings: per-group build must reject before its empty loop can pass.
	for _, hasRules := range []bool{false, true} {
		p := &policycore.Policy{APIVersion: policycore.NativeV2APIVersion, Kind: policycore.Kind, Org: orgID, NestedCalls: policycore.NestedCallsRequireOwnRule}
		if hasRules {
			p.Bindings = []policycore.Binding{{Group: groupID, Allow: []policycore.FrameRule{{StorageAddress: vaultAddr, Selector: "*"}}}}
		}
		v, err := policycore.ValidateNativeV2(p, testCatalog(t))
		if err != nil {
			t.Fatal(err)
		}
		compiler := &Compiler{Path: "/does-not-exist/native-source-must-reject-first"}
		for name, build := range map[string]func() error{
			"GenerateSolidity": func() error { _, err := GenerateSolidity(v); return err },
			"Build":            func() error { _, err := compiler.Build(t.Context(), v); return err },
			"BuildPerGroup":    func() error { _, err := compiler.BuildPerGroup(t.Context(), v); return err },
			"BuildSet":         func() error { _, err := compiler.BuildSet(t.Context(), v); return err },
		} {
			var unsupported *UnsupportedPolicyError
			if err := build(); !errors.As(err, &unsupported) || unsupported.Version != policycore.NativeV2APIVersion {
				t.Fatalf("%s rules=%v: expected source error, got %v", name, hasRules, err)
			}
		}
	}
}
