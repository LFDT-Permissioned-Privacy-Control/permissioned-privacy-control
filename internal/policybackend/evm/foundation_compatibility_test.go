package evm

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	. "privacy-proxy/internal/policycore"
)

// These digests were captured before the package split. They pin generated
// source and both bytecodes, including whole-document per-group provenance.
func TestFoundationArtifactCompatibility(t *testing.T) {
	p, cat := conformancePolicy(t)
	v, err := Validate(p, cat)
	if err != nil {
		t.Fatal(err)
	}
	record, err := Parse(recordPolicyJSON(t, "getPaymentInfo", nil))
	if err != nil {
		t.Fatal(err)
	}
	recordCatalog := testCatalog(t)
	recordCatalog.Contracts[vaultAddr] = ContractInfo{ABI: recordABI}
	recordValidated, err := Validate(record, recordCatalog)
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]*Validated{
		"conformance":        v,
		"traders":            v.ForGroup(groupID),
		"auditors":           v.ForGroup(auditorsGroup),
		"record-party":       recordValidated,
		"record-party-group": recordValidated.ForGroup(groupID),
	}
	type digests struct {
		Policy   string `json:"policy"`
		Source   string `json:"source"`
		Runtime  string `json:"runtime"`
		Creation string `json:"creation"`
	}
	got := map[string]digests{}
	for name, validated := range cases {
		artifact, err := requireCompiler(t).Build(t.Context(), validated)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		creation := sha256.Sum256(artifact.CreationBytecode)
		got[name] = digests{artifact.PolicyDigest, artifact.SourceDigest, artifact.RuntimeDigest, hex.EncodeToString(creation[:])}
	}
	encoded, err := os.ReadFile("testdata/foundation-artifacts.json")
	if err != nil {
		t.Fatal(err)
	}
	var want map[string]digests
	if err := json.Unmarshal(encoded, &want); err != nil {
		t.Fatal(err)
	}
	if len(got) != len(want) {
		t.Fatalf("got %d cases, want %d", len(got), len(want))
	}
	for name, expected := range want {
		if actual, ok := got[name]; !ok || actual != expected {
			t.Errorf("%s changed artifact/provenance: got %+v, want %+v", name, actual, expected)
		}
	}
}
