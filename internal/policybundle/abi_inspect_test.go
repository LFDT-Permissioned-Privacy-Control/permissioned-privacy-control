package policybundle_test

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"

	"privacy-proxy/internal/policybundle"
)

func TestABIInspectionMatchesRegistryAndSeparatesRawBytes(t *testing.T) {
	raw := []byte(contractABI)
	inspection, err := policybundle.InspectABI(raw, policybundle.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	catalog := load(t, baseFixture(t))
	contract, ok := catalog.Contract(orgID, common.HexToAddress(address))
	if !ok || inspection.CanonicalByteDigest != policybundle.RawDigest(contract.ABI) || inspection.ABIDigest != strings.TrimPrefix(string(inspection.CanonicalByteDigest), "sha256:") {
		t.Fatal("inspection does not describe the registry's canonical ABI")
	}
	if inspection.FileByteDigest != policybundle.RawDigest(raw) || inspection.DeploymentVerified || len(inspection.Functions) != 1 || inspection.Functions[0].Signature != "transfer(address,uint256)" || inspection.Functions[0].Selector != "0xa9059cbb" {
		t.Fatal("incorrect inspection identity or selector")
	}
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		t.Fatal(err)
	}
	reordered, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	other, err := policybundle.InspectABI(reordered, policybundle.DefaultLimits())
	if err != nil || other.CanonicalByteDigest != inspection.CanonicalByteDigest || other.FileByteDigest == inspection.FileByteDigest {
		t.Fatal("raw file identity confused with normalized ABI identity", err)
	}
	original := inspection
	inspection.Functions[0].Selector = "mutated"
	inspection.Events[0].Signature = "mutated"
	again, err := policybundle.InspectABI(raw, policybundle.DefaultLimits())
	if err != nil || again.Functions[0].Selector != "0xa9059cbb" || again.Events[0].Signature != "Transfer(address)" {
		t.Fatal("inspection output shares mutable state", err)
	}
	// Ignore the two deliberately edited aggregate fields when checking stable identities.
	if again.CanonicalByteDigest != original.CanonicalByteDigest {
		t.Fatal("repeat changed canonical identity")
	}
}

func TestABIInspectionAnonymousEventsAreNotTopicRules(t *testing.T) {
	raw := []byte(`[{"type":"event","name":"Z","inputs":[],"anonymous":false},{"type":"event","name":"A","inputs":[],"anonymous":true}]`)
	report, err := policybundle.InspectABI(raw, policybundle.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Events) != 2 || report.Events[0].Signature != "A()" || !report.Events[0].Anonymous || report.Events[0].Topic0 != "" || report.Events[0].TopicRuleEligible || report.Events[0].SignatureHash == "" {
		t.Fatal("anonymous signature was advertised as emitted topic0")
	}
	if report.Events[1].Signature != "Z()" || report.Events[1].Anonymous || !report.Events[1].TopicRuleEligible || report.Events[1].Topic0 != report.Events[1].SignatureHash {
		t.Fatal("ordinary event topic was not advertised correctly")
	}
	again, err := policybundle.InspectABI(raw, policybundle.DefaultLimits())
	if err != nil || !reflect.DeepEqual(report, again) {
		t.Fatal("inspection order is unstable")
	}
}

func TestABIInspectionRejectsRegistryAmbiguitiesAndUnsafeShapes(t *testing.T) {
	for name, raw := range map[string]string{
		"duplicate key":               `[{"type":"function","type":"event"}]`,
		"not array":                   `{}`,
		"null":                        `null`,
		"selector collision":          `[{"type":"function","name":"burn","inputs":[{"name":"a","type":"uint256"}]},{"type":"function","name":"collate_propagate_storage","inputs":[{"name":"a","type":"bytes16"}]}]`,
		"conflicting event layout":    `[{"type":"event","name":"E","inputs":[{"name":"a","type":"address","indexed":false}]},{"type":"event","name":"E","inputs":[{"name":"a","type":"address","indexed":true}]}]`,
		"reflected dynamic expansion": `[{"type":"function","name":"f","inputs":[{"name":"a","type":"string[4096][4096]"}]}]`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := policybundle.InspectABI([]byte(raw), policybundle.DefaultLimits()); err == nil {
				t.Fatal("unsafe ABI accepted")
			}
		})
	}
	limits := policybundle.DefaultLimits()
	limits.MaxDocumentBytes = int64(len(contractABI) - 1)
	if _, err := policybundle.InspectABI([]byte(contractABI), limits); err == nil {
		t.Fatal("ABI byte budget bypassed")
	}
	if _, err := policybundle.InspectABI([]byte("[]"), policybundle.Limits{}); err == nil {
		t.Fatal("invalid limits accepted")
	}
}
