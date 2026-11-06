package policybundle_test

import (
	"testing"

	"privacy-proxy/internal/policybundle"
	"privacy-proxy/internal/policycore"
)

func nativeV2Fixture(t *testing.T) fixture {
	f := identityFixture(t)
	f.options.Profile = policybundle.NativeV2Profile("rpc-test/v1")
	f.manifest.Profile, f.manifest.EvaluatorVersion = policybundle.NativeV2ProfileID, policybundle.NativeV2EvaluatorVersion
	f.edit(t, "execution.json", func(d map[string]any) {
		p := spec(d)["policy"].(map[string]any)
		p["apiVersion"] = policycore.NativeV2APIVersion
		rule(d)["minDepth"] = 1
	})
	return f
}

func TestNativeV2ProfileIsExplicitAndRetainsStaticLimits(t *testing.T) {
	f := nativeV2Fixture(t)
	s := load(t, f)
	v, ok := s.Execution(orgID)
	if !ok || v.Policy().APIVersion != policycore.NativeV2APIVersion || *v.Policy().Bindings[0].Allow[0].MinDepth != 1 {
		t.Fatal("native version or depth lost")
	}
	for name, edit := range map[string]func(*fixture){
		"old profile rejects new source": func(f *fixture) {
			f.options.Profile = policybundle.IdentityProfile("rpc-test/v1")
			f.manifest.Profile, f.manifest.EvaluatorVersion = policybundle.IdentityProfileID, policybundle.NativeEvaluatorVersion
		},
		"old evaluator label":      func(f *fixture) { f.manifest.EvaluatorVersion = policybundle.NativeEvaluatorVersion },
		"identity required":        func(f *fixture) { f.manifest.IdentityCatalog = nil; delete(f.docs, "identity.json") },
		"identity limits required": func(f *fixture) { f.options.IdentityLimits.MaxProfiles = 0 },
		"depth declaration cannot hide usage": func(f *fixture) {
			f.edit(t, "execution.json", func(d map[string]any) { delete(rule(d), "maxDepth") })
			removeCapability(f, policybundle.CapabilityDepth)
		},
		"v1 source cannot use v2 profile": func(f *fixture) {
			f.edit(t, "execution.json", func(d map[string]any) {
				spec(d)["policy"].(map[string]any)["apiVersion"] = policycore.APIVersion
				delete(rule(d), "minDepth")
			})
		},
		"classes still need runtime providers": func(f *fixture) {
			f.edit(t, "execution.json", func(d map[string]any) {
				p := spec(d)["policy"].(map[string]any)
				p["bindings"] = []any{map[string]any{"group": groupID, "allow": []any{map[string]any{"targetClass": "shared", "selector": "*", "storageAddress": "", "abiDigest": "", "minDepth": 1}}}}
			})
		},
		"null minimum": func(f *fixture) { f.edit(t, "execution.json", func(d map[string]any) { rule(d)["minDepth"] = nil }) },
		"null maximum": func(f *fixture) { f.edit(t, "execution.json", func(d map[string]any) { rule(d)["maxDepth"] = nil }) },
	} {
		t.Run(name, func(t *testing.T) {
			f := nativeV2Fixture(t)
			edit(&f)
			reject(t, f.write(t), f.options, t.Context())
		})
	}
}
