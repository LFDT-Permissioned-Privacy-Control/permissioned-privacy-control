package readprivacyabi

import (
	"encoding/json"
	"testing"
)

func TestMovedRuleJSONAndConstrainedFirstFold(t *testing.T) {
	for _, raw := range []string{"null", "[]", `"*"`, `[{"topic0":"0xab","name":"A","param_rules":[{"index":0,"must_be":"self"}]}]`} {
		var f EventRulesField
		if err := json.Unmarshal([]byte(raw), &f); err != nil {
			t.Fatal(err)
		}
		out, err := json.Marshal(f)
		if err != nil || raw != "[]" && string(out) != raw || raw == "[]" && string(out) != "null" {
			t.Fatalf("event-rule JSON state drift: %s => %s (%v)", raw, out, err)
		}
	}
	a := &EventRulesField{Rules: []EventRule{{Topic0: "0xAB", ParamRules: []ParamRule{{Index: 0, MustBe: "self"}}}}}
	b := &EventRulesField{Rules: []EventRule{{Topic0: "0xab", ParamRules: []ParamRule{{Index: 1, MustBe: "0x12"}}}}}
	for _, pair := range [][2]*EventRulesField{{a, b}, {b, a}} {
		out := UnionEventRules(pair[0], pair[1])
		if len(out.Rules) != 1 || len(out.Rules[0].ParamRules) != 1 || out.Rules[0].ParamRules[0] != pair[0].Rules[0].ParamRules[0] {
			t.Fatal("mechanical extraction changed the legacy constrained-first fold to OR")
		}
	}
	if out := UnionEventRules(a, &EventRulesField{Rules: []EventRule{{Topic0: "0xab"}}}); len(out.Rules[0].ParamRules) != 0 {
		t.Fatal("unconstrained same-topic alternative stopped dominating")
	}
	if UnionEventRules(nil, &EventRulesField{}) != nil || !UnionEventRules(a, &EventRulesField{Wildcard: true}).Wildcard {
		t.Fatal("deny/wildcard union drift")
	}
}
