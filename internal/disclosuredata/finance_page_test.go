package disclosuredata

import (
	"encoding/json"
	"strings"
	"testing"

	p "privacy-proxy/internal/disclosurepolicy"
)

func financePageFixture(t *testing.T) (SourcePlan, ReadScope, []SourceDescriptor, Facts, RenderContext) {
	t.Helper()
	s, ds, _, rc := testFixture(t, p.ComplianceReport, Report, p.Full)
	n, err := NormalizeRetained(Query{Version: 1, Resource: p.ComplianceReport, View: List, Limit: ptr(uint16(2))}, s.Query.Scope())
	if err != nil {
		t.Fatal(err)
	}
	s.Query = n
	rc.Query = n
	var finance SourceDescriptor
	for _, desc := range ds {
		if desc.Kind == FinanceSource {
			finance = desc
		}
	}
	plan := SourcePlan{Version: 2, Profile: RetainedSourceProfile, BundleDigest: s.BundleDigest, NetworkKey: finance.NetworkKey, PlanDigest: finance.PlanDigest, Resources: []p.Resource{p.ComplianceReport}}
	event := func(id Count) ComplianceEvidence {
		return ComplianceEvidence{ID: id, Provenance: Provenance{Source: finance.Reference, DataOrganizationID: s.DataOrganizationID, TargetActorIDs: []string{testActor(1)}, Kind: "ADMISSION_DECISION"}, DecisionAt: rc.PreparedAt, Decision: "allowed", Kind: "admission_only", Coverage: "not_detected", PolicyDigest: testDigest(30)}
	}
	f := Facts{FinanceEvidence: &FinanceEvidencePage{Items: []ComplianceEvidence{event("1"), event("3")}, MatchingRetainedCount: "3", BeforeCount: "0"}, End: false, Next: &Position{Kind: FinanceSource, Finance: &FinancePosition{ID: "3"}}}
	return plan, s, []SourceDescriptor{finance}, f, rc
}

func TestRetainedFinancePageClosedProfileCountsAndPrivacy(t *testing.T) {
	plan, s, ds, f, rc := financePageFixture(t)
	if _, err := Normalize(Query{Version: 1, Resource: p.ComplianceReport, View: List}, s.Query.Scope()); err == nil {
		t.Fatal("legacy normalization widened")
	}
	rawQuery := []byte(`{"v":1,"resource":"compliance_report","view":"list","limit":2}`)
	if _, err := DecodeQuery(rawQuery); err == nil {
		t.Fatal("legacy wire widened")
	}
	if _, err := DecodeRetainedQuery(rawQuery); err != nil {
		t.Fatal(err)
	}
	if BasisForResourceView(p.ComplianceReport, List, RetainedBasis{}) != nil || BasisForResource(p.ComplianceReport, RetainedBasis{}) == nil {
		t.Fatal("list/report basis confused")
	}
	if _, err := SourceSetDigest(ds, p.ComplianceReport, List); err == nil {
		t.Fatal("legacy source profile widened")
	}
	if err := ValidateFactsRetained(plan, s, ds, f, nil); err != nil {
		t.Fatal(err)
	}
	for _, level := range []p.Level{p.Full, p.Pseudonymous, p.Redacted} {
		n, _ := NormalizeRetained(Query{Version: 1, Resource: p.ComplianceReport, View: List, Limit: ptr(uint16(2)), Level: &level}, s.Query.Scope())
		s.Query = n
		rc.Query = n
		result, err := RenderRetained(plan, s, ds, f, rc, "88888888-8888-4888-8888-888888888888")
		if err != nil {
			t.Fatal(err)
		}
		if result.ReturnedRows() != 2 || result.QualifiedTotal() == nil || *result.QualifiedTotal() != "3" {
			t.Fatal("finance count replaced with activity total")
		}
		result, err = result.WithCursor("owned-cursor")
		if err != nil {
			t.Fatal(err)
		}
		raw, err := json.Marshal(result)
		if err != nil {
			t.Fatal(err)
		}
		var got struct {
			Coverage CoverageDTO
			Result   struct {
				Items                 []map[string]any
				NextCursor            *string
				MatchingRetainedCount Count
			}
		}
		if json.Unmarshal(raw, &got) != nil || got.Coverage.Status != "RETAINED_AT_READ" || got.Coverage.SourceCutDigest != "" || got.Coverage.SourceBasisDigest == "" || got.Result.MatchingRetainedCount != "3" || got.Result.NextCursor == nil {
			t.Fatal(string(raw))
		}
		for _, item := range got.Result.Items {
			_, has := item["transactionHash"]
			if has != (level == p.Full) {
				t.Fatal("field-level omission", string(raw))
			}
		}
	}
}

func TestRetainedFinancePageRejectsWrongFactsAndProgress(t *testing.T) {
	plan, s, ds, base, _ := financePageFixture(t)
	for name, change := range map[string]func(*Facts){
		"wrong count":             func(f *Facts) { f.FinanceEvidence.MatchingRetainedCount = "1" },
		"false end":               func(f *Facts) { f.End = true; f.Next = nil },
		"invented initial offset": func(f *Facts) { f.FinanceEvidence.BeforeCount = "1" },
		"missing items":           func(f *Facts) { f.FinanceEvidence.Items = nil },
		"multiple branches":       func(f *Facts) { f.ActivitySummary = &ActivityAggregate{} },
		"duplicate key":           func(f *Facts) { f.FinanceEvidence.Items[1].ID = "1" },
		"wrong next":              func(f *Facts) { f.Next.Finance.ID = "2" },
		"zero key":                func(f *Facts) { f.FinanceEvidence.Items[0].ID = "0" },
		"overflow key":            func(f *Facts) { f.FinanceEvidence.Items[0].ID = "9223372036854775808" },
		"foreign actor":           func(f *Facts) { f.FinanceEvidence.Items[0].Provenance.TargetActorIDs = []string{testActor(99)} },
		"unknown quote":           func(f *Facts) { f.FinanceEvidence.Items[0].QuoteDigest = ptr(testDigest(40)) },
	} {
		t.Run(name, func(t *testing.T) {
			f, _ := DetachFacts(base)
			change(&f)
			if ValidateFactsRetained(plan, s, ds, f, nil) == nil {
				t.Fatal("accepted invalid page")
			}
		})
	}
	f, _ := DetachFacts(base)
	f.FinanceEvidence.Items = f.FinanceEvidence.Items[1:]
	f.FinanceEvidence.Items[0].ID = "9"
	f.FinanceEvidence.BeforeCount = "2"
	f.End = true
	f.Next = nil
	after := &Position{Kind: FinanceSource, Finance: &FinancePosition{ID: "3"}}
	if ValidateFactsRetained(plan, s, ds, f, after) != nil {
		t.Fatal("last page rejected")
	}
	f.FinanceEvidence.BeforeCount = "0"
	if ValidateFactsRetained(plan, s, ds, f, after) == nil {
		t.Fatal("missing consumed count")
	}
}

func TestRetainedFinanceCursorSeparateResourceViewAndQuery(t *testing.T) {
	plan, s, ds, f, rc := financePageFixture(t)
	set, _ := SourceSetDigestRetained(plan, ds, p.ComplianceReport, List)
	keys := Keys{Active: Key{ID: "data", Bytes: []byte(strings.Repeat("x", 32))}}
	codec, _ := NewCursor(keys)
	generation, _ := RenderGeneration(rc.Keys)
	b := CursorBinding{Namespace: s.Namespace, CaseID: s.CaseID, CaseVersion: s.CaseVersion, RecipientActorID: s.RecipientActorID, BundleDigest: s.BundleDigest, RuleDigest: s.RuleDigest, QueryDigest: s.Query.Digest(), RenderGeneration: generation, SourcePlanDigest: plan.PlanDigest}
	refs, _ := SourceReferencesRetained(plan, ds)
	if _, err := codec.Seal(b, set, refs, *f.Next, rc.EffectiveUntil); err == nil {
		t.Fatal("legacy cursor admitted retained-only finance position")
	}
	raw, err := codec.SealRetained(plan, b, p.ComplianceReport, RetainedBasis{}, set, refs, *f.Next, rc.EffectiveUntil)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := codec.OpenRetained(raw, plan, b, p.ComplianceReport, rc.PreparedAt)
	if err != nil || opened.Position().Finance.ID != "3" || opened.Basis() != (RetainedBasis{}) {
		t.Fatal("finance-only continuation", err)
	}
	if _, err := codec.OpenRetained(raw, plan, b, p.ActivityLogs, rc.PreparedAt); err == nil {
		t.Fatal("resource transplant")
	}
	b.QueryDigest = testDigest(99)
	if _, err := codec.OpenRetained(raw, plan, b, p.ComplianceReport, rc.PreparedAt); err == nil {
		t.Fatal("query transplant")
	}
}
