package disclosuredata

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	p "privacy-proxy/internal/disclosurepolicy"
)

func nativeFinanceFixture(t *testing.T, report bool) (SourcePlan, ReadScope, []SourceDescriptor, Facts, RenderContext) {
	t.Helper()
	if report {
		s, plan, ds, f, rc := retainedFixture(t, p.ComplianceReport, Report, p.Full)
		plan.Version, plan.Profile = 3, NativeFinanceSourceProfile
		for i := range ds {
			if ds[i].Kind == FinanceSource {
				ds[i].Version, ds[i].FormatDigest = 2, FinanceSummaryFormat()
				f.Compliance.Evidence = nil
				f.Compliance.Finance = &FinanceSummary{MatchingRetainedCount: "20001", ObservedAt: ds[i].AsOf}
			}
		}
		return plan, s, ds, f, rc
	}
	plan, s, ds, f, rc := financePageFixture(t)
	plan.Version, plan.Profile = 3, NativeFinanceSourceProfile
	ds[0].Version, ds[0].FormatDigest = 2, FinanceLiveFormat()
	items := f.FinanceEvidence.Items
	items[0], items[1] = items[1], items[0]
	f.FinanceLive = &FinanceLivePage{Items: items, MatchingRetainedCount: "20001", ObservedAt: ds[0].AsOf}
	f.FinanceEvidence = nil
	last := items[len(items)-1]
	f.Next = &Position{Kind: FinanceSource, FinanceLive: &FinanceLivePosition{ObservedAtMicros: last.DecisionAt.UnixMicro(), ID: last.ID}}
	return plan, s, ds, f, rc
}

func TestNativeFinanceReportAndLivePageDTOSerialize(t *testing.T) {
	for _, report := range []bool{true, false} {
		plan, scope, descriptors, facts, render := nativeFinanceFixture(t, report)
		if err := ValidateFactsRetained(plan, scope, descriptors, facts, nil); err != nil {
			t.Fatal("native facts", report, err)
		}
		result, err := RenderRetained(plan, scope, descriptors, facts, render, "88888888-8888-4888-8888-888888888888")
		if err != nil {
			t.Fatal("native render", report, err)
		}
		raw, err := json.Marshal(result)
		if err != nil || !strings.Contains(string(raw), `"v":2`) || !strings.Contains(string(raw), `"matchingRetainedCount":"20001"`) || !strings.Contains(string(raw), `"observedAt":`) {
			t.Fatal("native DTO", string(raw), err)
		}
		if report && (strings.Contains(string(raw), `"evidence":`) || !strings.Contains(string(raw), `"detailView":"list"`)) {
			t.Fatal("aggregate still claims inline complete evidence", string(raw))
		}
		if !report && !strings.Contains(string(raw), `"pagination":"live-keyset"`) {
			t.Fatal("live meaning absent", string(raw))
		}
		t.Logf("native-finance report=%v JSON=%s", report, raw)
	}
}

func TestLiveFinanceCursorProfileTupleAndDomain(t *testing.T) {
	plan, scope, descriptors, facts, render := nativeFinanceFixture(t, false)
	identity, err := FinanceLiveIdentity(plan, descriptors[0])
	if err != nil {
		t.Fatal(err)
	}
	ring, err := NewCursor(render.Keys)
	if err != nil {
		t.Fatal(err)
	}
	generation, _ := RenderGeneration(render.Keys)
	binding := CursorBinding{Namespace: scope.Namespace, CaseID: scope.CaseID, CaseVersion: scope.CaseVersion, RecipientActorID: scope.RecipientActorID, BundleDigest: scope.BundleDigest, RuleDigest: scope.RuleDigest, QueryDigest: scope.Query.Digest(), RenderGeneration: generation, SourcePlanDigest: plan.PlanDigest}
	raw, err := ring.SealLiveFinance(plan, binding, identity, *facts.Next, render.PreparedAt.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	got, err := ring.OpenLiveFinance(raw, plan, binding, render.PreparedAt)
	if err != nil || got.SourceIdentity() != identity || got.Position().FinanceLive.ObservedAtMicros != facts.Next.FinanceLive.ObservedAtMicros || got.Position().FinanceLive.ID != facts.Next.FinanceLive.ID {
		t.Fatal("live cursor", got, err)
	}
	changed := binding
	changed.QueryDigest = testDigest(99)
	if _, err = ring.OpenLiveFinance(raw, plan, changed, render.PreparedAt); err == nil {
		t.Fatal("changed query admitted")
	}
	if _, err = ring.OpenRetained(raw, plan, binding, p.ComplianceReport, render.PreparedAt); err == nil {
		t.Fatal("live parsed as retained")
	}
	if _, err = ring.OpenLiveFinance(strings.Replace(raw, "df1.", "dd2.", 1), plan, binding, render.PreparedAt); err == nil {
		t.Fatal("retained parsed as live")
	}
	if _, err = ring.OpenLiveFinance(raw, plan, binding, render.PreparedAt.Add(time.Minute)); err == nil {
		t.Fatal("expired cursor admitted")
	}
}

func TestNativeFinanceClosedFactsAndPrivacy(t *testing.T) {
	for _, name := range []string{"count below rows", "noncanonical count", "wrong observation", "wrong ordering", "old position", "mixed branch", "wrong format", "old profile"} {
		t.Run(name, func(t *testing.T) {
			plan, scope, ds, facts, _ := nativeFinanceFixture(t, false)
			switch name {
			case "count below rows":
				facts.FinanceLive.MatchingRetainedCount = "1"
			case "noncanonical count":
				facts.FinanceLive.MatchingRetainedCount = "020001"
			case "wrong observation":
				facts.FinanceLive.ObservedAt = facts.FinanceLive.ObservedAt.Add(time.Microsecond)
			case "wrong ordering":
				facts.FinanceLive.Items[0], facts.FinanceLive.Items[1] = facts.FinanceLive.Items[1], facts.FinanceLive.Items[0]
			case "old position":
				facts.Next = &Position{Kind: FinanceSource, Finance: &FinancePosition{ID: facts.Next.FinanceLive.ID}}
			case "mixed branch":
				facts.FinanceEvidence = &FinanceEvidencePage{Items: []ComplianceEvidence{}, MatchingRetainedCount: "0", BeforeCount: "0"}
			case "wrong format":
				ds[0].FormatDigest = FinanceSummaryFormat()
			case "old profile":
				plan.Version, plan.Profile = 2, RetainedSourceProfile
			}
			if ValidateFactsRetained(plan, scope, ds, facts, nil) == nil {
				t.Fatal("invalid native facts admitted")
			}
		})
	}
	for _, level := range []p.Level{p.Redacted, p.Pseudonymous, p.Full} {
		plan, scope, ds, facts, render := nativeFinanceFixture(t, false)
		scope.Query.scope.Level, render.Query.scope.Level = level, level
		result, err := RenderRetained(plan, scope, ds, facts, render, "88888888-8888-4888-8888-888888888888")
		if err != nil {
			t.Fatal(err)
		}
		raw, err := json.Marshal(result)
		if err != nil {
			t.Fatal(err)
		}
		if level != p.Full && (strings.Contains(string(raw), `"transactionHash"`) || strings.Contains(string(raw), `"quote"`) || strings.Contains(string(raw), `"recordId"`)) {
			t.Fatal("private evidence leaked", level, string(raw))
		}
		if level == p.Full && !strings.Contains(string(raw), `"transactionHash"`) {
			t.Fatal("Full detail removed")
		}
	}
	plan, scope, ds, facts, _ := nativeFinanceFixture(t, true)
	plan.Version, plan.Profile = 2, RetainedSourceProfile
	for i := range ds {
		if ds[i].Kind == FinanceSource {
			ds[i].Version = 1
		}
	}
	if ValidateFactsRetained(plan, scope, ds, facts, nil) == nil {
		t.Fatal("native aggregate reinterpreted as old inline report")
	}
}
