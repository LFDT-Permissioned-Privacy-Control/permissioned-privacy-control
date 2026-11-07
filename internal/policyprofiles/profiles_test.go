package policyprofiles_test

import (
	"testing"

	"privacy-proxy/internal/policybundle"
	"privacy-proxy/internal/policyprofiles"
)

func TestProfilesStayExplicitAndRegistryDataDetached(t *testing.T) {
	profiles := policyprofiles.Supported()
	if len(profiles) != 11 {
		t.Fatal("compiled profiles changed without a registry test")
	}
	for _, expected := range profiles {
		options, actual, err := policyprofiles.Options(expected.ID)
		if err != nil || actual != expected || !actual.ValidationOnly {
			t.Fatal("profile metadata disagrees with compiled options", err)
		}
		if expected.ID == policybundle.NativeV2ProfileID && actual.EvaluatorVersion != policybundle.NativeV2EvaluatorVersion {
			t.Fatal("native V2 was labeled with old semantics")
		}
		if expected.ID == policybundle.RuntimeMultiOrgProfileID && (actual.EvaluatorVersion != policybundle.NativeV3EvaluatorVersion || actual.IntegrationScope == "") {
			t.Fatal("multi-org semantics lack an explicit version/scope")
		}
		if expected.ID == policybundle.RuntimeLifecycleProfileID && (actual.EvaluatorVersion != policybundle.NativeV4EvaluatorVersion || actual.IntegrationScope == "") {
			t.Fatal("lifecycle semantics lack an explicit version/scope")
		}
		if expected.ID == policybundle.RuntimeSimulationProfileID && (actual.EvaluatorVersion != policybundle.NativeV4EvaluatorVersion || actual.IntegrationScope == "") {
			t.Fatal("simulation source lacks explicit native-v4 semantics/scope")
		}
		if expected.ID == policybundle.RuntimeCallProfileID && actual.IntegrationScope == "" {
			t.Fatal("runtime slice lacks explicit qualification scope")
		}
		if expected.ID == policybundle.BrokerProfileID && actual.EvaluatorVersion != policybundle.NativeV2EvaluatorVersion {
			t.Fatal("broker profile lost native-v2 source boundary")
		}
		options.Methods.Assignable[0] = "mutated"
		other, _, err := policyprofiles.Options(expected.ID)
		if err != nil || other.Methods.Assignable[0] == "mutated" {
			t.Fatal("caller mutated pinned method data")
		}
	}
	if _, _, err := policyprofiles.Options("auto"); err == nil {
		t.Fatal("unknown profile accepted")
	}
}
