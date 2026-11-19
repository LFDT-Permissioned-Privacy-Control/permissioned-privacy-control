package policycli_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"privacy-proxy/internal/policycli"
	"privacy-proxy/internal/policycore"
	"testing"
)

func TestPolicyScenarioUsesActualPinnedGoEvaluator(t *testing.T) {
	draft := source(t)
	org := "11111111-1111-1111-1111-111111111111"
	group := "22222222-2222-2222-2222-222222222222"
	address := "0x1111111111111111111111111111111111111111"
	write := func(name string, value any) {
		t.Helper()
		b, e := json.Marshal(value)
		if e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(filepath.Join(draft, name), b, 0600); e != nil {
			t.Fatal(e)
		}
	}
	document := func(kind string, spec any) any {
		return map[string]any{"apiVersion": "ops.policy-document/v1alpha1", "kind": kind, "organizationId": org, "spec": spec}
	}
	write("groups.json", document("groups", map[string]any{"groups": []any{map[string]any{"id": group, "slug": "payments", "name": "Payments", "description": "", "isOrgAdmin": false, "isOrgReadonlyAdmin": false, "allowedMethods": []string{}, "claims": []string{}, "verboseErrors": false}}}))
	write("registry.json", document("contract-registry", map[string]any{"contracts": []any{map[string]any{"id": "33333333-3333-3333-3333-333333333333", "address": address, "name": "Vault", "abi": []any{}, "allowVisibleToUnlock": false, "eventsAllowDynamicPayload": false, "readGrants": []any{}}}}))
	write("execution.json", document("execution-rules", map[string]any{"policy": map[string]any{"apiVersion": "privacy.gateway.fm/v1alpha1", "kind": "ContractExecutionPolicy", "org": org, "nestedCalls": "requireOwnRule", "bindings": []any{map[string]any{"group": group, "allow": []any{map[string]any{"storageAddress": address, "selector": "*", "abiDigest": "", "args": []any{}}}}}}}))
	bundle := filepath.Join(t.TempDir(), "artifact")
	code, raw, errs := invoke(t, t.Context(), "policy", "prepare", "--source", draft, "--output", bundle, "--profile", "catalog-foundation/v1")
	if code != 0 {
		t.Fatalf("prepare: %s", errs)
	}
	var prepared policycli.Report
	if e := json.Unmarshal(raw, &prepared); e != nil {
		t.Fatal(e)
	}
	scenario := filepath.Join(t.TempDir(), "scenario.json")
	run := func(groups []string) map[string]json.RawMessage {
		t.Helper()
		s := map[string]any{"apiVersion": "ops.policy-scenario/v1", "context": map[string]any{"Org": org, "Groups": groups}, "frames": []any{map[string]any{"callType": "call", "storageAddress": address, "codeAddress": address, "calldata": "0x12345678", "value": "0", "depth": 0, "facts": map[string]any{"CodeOrg": org, "StorageOrg": org}}}}
		b, _ := json.Marshal(s)
		if e := os.WriteFile(scenario, b, 0600); e != nil {
			t.Fatal(e)
		}
		code, raw, errs := invoke(t, t.Context(), "policy", "simulate", "--bundle", bundle, "--expected-digest", string(prepared.ManifestDigest), "--environment", "local", "--chain-id", "31337", "--profile", "catalog-foundation/v1", "--scenario", scenario)
		if code != 0 {
			t.Fatalf("simulate: %s", errs)
		}
		var result map[string]json.RawMessage
		if e := json.Unmarshal(raw, &result); e != nil {
			t.Fatal(e)
		}
		return result
	}
	allowed := run([]string{group})
	denied := run([]string{})
	var a, b policycore.Decision
	if json.Unmarshal(allowed["decision"], &a) != nil || json.Unmarshal(denied["decision"], &b) != nil || !a.Allowed || b.Allowed || b.Code != policycore.DenialNoMatchingRule {
		t.Fatalf("actual evaluator mismatch: %s %s", allowed["decision"], denied["decision"])
	}
	if string(allowed["hypothetical"]) != "true" || string(allowed["approved"]) != "false" || string(allowed["deploymentVerified"]) != "false" || string(allowed["scenarioDigest"]) == string(denied["scenarioDigest"]) {
		t.Fatal("scenario report lost conditional or exact-byte identity")
	}
	if string(allowed["profile"]) != `"catalog-foundation/v1"` || len(allowed["evaluatorVersion"]) == 0 {
		t.Fatal("scenario report lost the selected Go compiler profile")
	}
	valid, err := os.ReadFile(scenario)
	if err != nil {
		t.Fatal(err)
	}
	for _, invalid := range [][]byte{
		bytes.Replace(valid, []byte(`"value":"0"`), []byte(`"value":"-1"`), 1),
		bytes.Replace(valid, []byte(`"facts":{`), []byte(`"facts":{"CallType":"call",`), 1),
		bytes.Replace(valid, []byte(`"apiVersion":`), []byte(`"apiVersion":"duplicate","apiVersion":`), 1),
	} {
		if err := os.WriteFile(scenario, invalid, 0600); err != nil {
			t.Fatal(err)
		}
		code, out, errs := invoke(t, t.Context(), "policy", "simulate", "--bundle", bundle, "--expected-digest", string(prepared.ManifestDigest), "--environment", "local", "--chain-id", "31337", "--profile", "catalog-foundation/v1", "--scenario", scenario)
		if code == 0 || len(out) != 0 || !json.Valid(errs) {
			t.Fatal("invalid hypothetical facts were evaluated")
		}
	}
}
