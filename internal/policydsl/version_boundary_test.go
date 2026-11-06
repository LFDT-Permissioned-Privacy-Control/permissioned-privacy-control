package policydsl_test

import (
	"encoding/json"
	"testing"

	"privacy-proxy/internal/policycore"
	"privacy-proxy/internal/policydsl"
)

func TestLegacyFacadeDoesNotSelectNativeV2(t *testing.T) {
	p := &policycore.Policy{APIVersion: policycore.NativeV2APIVersion, Kind: policycore.Kind, Org: "org", NestedCalls: policycore.NestedCallsRequireOwnRule, Bindings: []policycore.Binding{}}
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := policydsl.Parse(raw)
	if err != nil {
		t.Fatal("legacy parser must keep version validation at its existing stage", err)
	}
	if _, err := policydsl.Validate(parsed, policydsl.Catalog{Org: "org"}); err == nil {
		t.Fatal("legacy facade silently selected native-v2 validation")
	}
	if _, err := policydsl.Parse([]byte(`{"bindings":[{"allow":[{"minDepth":0}]}]}`)); err == nil {
		t.Fatal("legacy facade accepted minDepth")
	}
}
