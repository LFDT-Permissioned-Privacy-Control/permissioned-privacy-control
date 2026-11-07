package disclosuresql

import (
	c "privacy-proxy/internal/disclosurecase"
	"testing"
)

func TestSummaryClosedLegacyAndExtendedShapes(t *testing.T) {
	for _, raw := range []string{`{"count":1,"ruleContext":"current"}`, `{"count":0,"ruleContext":"original-history"}`} {
		var out c.EventSummary
		if e := decodeSummary([]byte(raw), &out); e != nil || out.Exposure != nil {
			t.Fatal("legacy variant changed", raw, e)
		}
	}
	for _, raw := range []string{`{"count":1,"ruleContext":"current","exposure":null}`, `{"count":1,"count":2,"ruleContext":"current"}`, `{"count":1,"ruleContext":"current","authority":true}`, `{"count":1,"ruleContext":"current","exposure":{"v":1,"verified":true}}`} {
		var out c.EventSummary
		if e := decodeSummary([]byte(raw), &out); e == nil {
			t.Fatal("unreviewed private summary shape accepted", raw)
		}
	}
}
