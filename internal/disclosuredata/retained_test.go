package disclosuredata

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	p "privacy-proxy/internal/disclosurepolicy"
)

func retainedFixture(t *testing.T, resource p.Resource, view View, level p.Level) (ReadScope, SourcePlan, []SourceDescriptor, Facts, RenderContext) {
	t.Helper()
	s, descriptors, facts, render := testFixture(t, resource, view, level)
	plan := SourcePlan{Version: 2, Profile: RetainedSourceProfile, BundleDigest: s.BundleDigest, NetworkKey: descriptors[0].NetworkKey, PlanDigest: descriptors[0].PlanDigest, Resources: []p.Resource{resource}}
	for i := range descriptors {
		descriptors[i].Version, descriptors[i].Population = retainedPopulation(descriptors[i].Kind)
	}
	for i := range facts.Addresses {
		facts.Addresses[i].Provenance.Kind = RetainedHistoryPopulation
	}
	for i := range facts.Transactions {
		facts.Transactions[i].Provenance.Kind = RetainedHistoryPopulation
	}
	return s, plan, descriptors, facts, render
}

func testRetainedBasis() RetainedBasis {
	count := uint32(17)
	return RetainedBasis{Version: 2, NetworkKey: testDigest(13), NodeSource: testDigest(30), APIVersion: "chain_indexer.v2", DatasetEpoch: "77777777-7777-4777-8777-777777777777", Upper: RetainedAnchor{Number: "100", Hash: hashString(testHash(41)), ParentHash: hashString(testHash(40)), Timestamp: "1800000000", Transactions: &count}}
}

func TestRetainedTransactionListAllowsBoundedEarlyContinuationOnly(t *testing.T) {
	s, plan, descriptors, facts, _ := retainedFixture(t, p.Transactions, List, p.Full)
	tx := facts.Transactions[0]
	facts.End = false
	facts.Next = &Position{Kind: HistorySource, Transaction: &TransactionPosition{tx.BlockNumber, tx.TransactionIndex, tx.Hash}}
	if len(facts.Transactions) >= int(s.Query.Limit()) {
		t.Fatal("fixture must exercise a short nonterminal page")
	}
	if err := ValidateFactsRetained(plan, s, descriptors, facts, nil); err != nil {
		t.Fatal("bounded early retained continuation rejected", err)
	}
	for _, change := range []func(*Facts){
		func(f *Facts) { f.Transactions = []TransactionFact{} },
		func(f *Facts) { f.Next = nil },
		func(f *Facts) { f.Next = ClonePosition(f.Next); f.Next.Transaction.TransactionIndex++ },
		func(f *Facts) { f.End = true },
	} {
		bad := facts
		change(&bad)
		if err := ValidateFactsRetained(plan, s, descriptors, bad, nil); err == nil {
			t.Fatal("invalid early continuation accepted")
		}
	}
	legacyScope, legacyDescriptors, legacyFacts, _ := testFixture(t, p.Transactions, List, p.Full)
	legacyFacts.End, legacyFacts.Next = false, facts.Next
	if _, err := validateFacts(legacyScope, legacyDescriptors, legacyFacts, nil); err == nil {
		t.Fatal("legacy exact-fill contract widened")
	}
	addressScope, addressPlan, addressDescriptors, addressFacts, _ := retainedFixture(t, p.AddressHistory, List, p.Full)
	addressFacts.End = false
	addressFacts.Next = &Position{Kind: HistorySource, Address: &AddressPosition{Address: addressFacts.Addresses[0].Address}}
	if err := ValidateFactsRetained(addressPlan, addressScope, addressDescriptors, addressFacts, nil); err == nil {
		t.Fatal("address exact-fill contract widened")
	}
}

func TestRetainedCursorOriginalAnchorAndSeparateDomain(t *testing.T) {
	s, plan, descriptors, facts, render := retainedFixture(t, p.Transactions, List, p.Full)
	generation, _ := RenderGeneration(render.Keys)
	binding := CursorBinding{Namespace: s.Namespace, CaseID: s.CaseID, CaseVersion: s.CaseVersion, RecipientActorID: s.RecipientActorID, BundleDigest: s.BundleDigest, RuleDigest: s.RuleDigest, QueryDigest: s.Query.Digest(), RenderGeneration: generation, SourcePlanDigest: plan.PlanDigest}
	set, err := SourceSetDigestRetained(plan, descriptors, p.Transactions, List)
	if err != nil {
		t.Fatal(err)
	}
	refs, _ := SourceReferencesRetained(plan, descriptors)
	tx := facts.Transactions[0]
	position := Position{Kind: HistorySource, Transaction: &TransactionPosition{tx.BlockNumber, tx.TransactionIndex, tx.Hash}}
	ring, err := NewCursor(Keys{Active: Key{ID: "data", Bytes: bytes.Repeat([]byte{71}, 32)}})
	if err != nil {
		t.Fatal(err)
	}
	basis := testRetainedBasis()
	raw, err := ring.SealRetained(plan, binding, p.Transactions, basis, set, refs, position, render.EffectiveUntil)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ring.OpenRetained(raw, plan, binding, p.Transactions, render.PreparedAt)
	if err != nil || !got.Basis().Equal(basis) || got.VerifySourceSet(set) != nil {
		t.Fatal("original anchor not preserved", err)
	}
	// A detached continuation never mutates when the caller or next head changes.
	copy := got.Basis()
	*copy.Upper.Transactions = 999
	basis.Upper.Number = "101"
	if got.Basis().Upper.Number != "100" || *got.Basis().Upper.Transactions != 17 {
		t.Fatal("mutable or advanced anchor")
	}
	if _, err := ring.Open(raw, binding, render.PreparedAt); err == nil {
		t.Fatal("dd1 accepted dd2")
	}
	old, err := ring.Seal(binding, set, refs, position, render.EffectiveUntil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ring.OpenRetained(old, plan, binding, p.Transactions, render.PreparedAt); err == nil {
		t.Fatal("dd2 accepted dd1")
	}
	for _, change := range []func(*CursorBinding){func(b *CursorBinding) { b.RecipientActorID = testActor(9) }, func(b *CursorBinding) { b.CaseVersion++ }, func(b *CursorBinding) { b.QueryDigest = testDigest(90) }} {
		bad := binding
		change(&bad)
		if _, err := ring.OpenRetained(raw, plan, bad, p.Transactions, render.PreparedAt); !errors.Is(err, ErrConflict) {
			t.Fatal("cross-case/query continuation", err)
		}
	}
	if _, err := ring.OpenRetained(raw, plan, binding, p.Transactions, render.EffectiveUntil); err == nil {
		t.Fatal("expired continuation")
	}
	changed := []byte(raw)
	changed[len(changed)-5] ^= 1
	if _, err := ring.OpenRetained(string(changed), plan, binding, p.Transactions, render.PreparedAt); err == nil {
		t.Fatal("unauthenticated anchor")
	}
	if _, err := ring.OpenRetained(strings.Replace(raw, "dd2.", "dd1.", 1), plan, binding, p.Transactions, render.PreparedAt); err == nil {
		t.Fatal("prefix domain confusion")
	}
}

func TestRetainedProfileCoverageAndLegacySeparation(t *testing.T) {
	for _, resource := range []p.Resource{p.AddressHistory, p.Transactions, p.ActivitySummary, p.SanctionsReport, p.ComplianceReport} {
		t.Run(string(resource), func(t *testing.T) {
			view := Report
			if resource == p.AddressHistory || resource == p.Transactions {
				view = List
			}
			s, plan, descriptors, facts, render := retainedFixture(t, resource, view, p.Full)
			if err := ValidateFactsRetained(plan, s, descriptors, facts, nil); err != nil {
				t.Fatal(err)
			}
			result, err := RenderRetained(plan, s, descriptors, facts, render, "88888888-8888-4888-8888-888888888888")
			if err != nil {
				t.Fatal(err)
			}
			raw, err := json.Marshal(result)
			if err != nil {
				t.Fatal(err)
			}
			var wire struct {
				Coverage CoverageDTO `json:"coverage"`
			}
			if err = json.Unmarshal(raw, &wire); err != nil {
				t.Fatal(err)
			}
			kinds, _ := RequiredKinds(resource)
			history := false
			for _, k := range kinds {
				history = history || k == HistorySource
			}
			if history {
				if wire.Coverage.Status != "RETAINED_AT_READ" || wire.Coverage.SourceBasisDigest == "" || wire.Coverage.SourceCutDigest != "" {
					t.Fatal("retained report claimed immutable completeness", string(raw))
				}
			} else if wire.Coverage.Status != "COMPLETE_AT_CUT" || wire.Coverage.SourceCutDigest == "" || wire.Coverage.SourceBasisDigest != "" {
				t.Fatal("immutable activity coverage changed")
			}
			if _, err := SourceReferences(descriptors); err == nil {
				t.Fatal("legacy profile accepted retained descriptor")
			}
			descriptors[0].Population = "WRONG"
			if _, err := SourceSetDigestRetained(plan, descriptors, resource, view); err == nil {
				t.Fatal("unrecognized population")
			}
		})
	}
}

func TestRetainedBasisClosedShapeAndResourceChoice(t *testing.T) {
	basis := testRetainedBasis()
	if !basis.Valid() || BasisForResource(p.Transactions, basis) != nil || BasisForResource(p.ActivityLogs, RetainedBasis{}) != nil {
		t.Fatal("valid selection")
	}
	if BasisForResource(p.ActivityLogs, basis) == nil || BasisForResource(p.Transactions, RetainedBasis{}) == nil {
		t.Fatal("anchor omission/resource confusion")
	}
	for _, change := range []func(*RetainedBasis){func(b *RetainedBasis) { b.Upper.Number = "0100" }, func(b *RetainedBasis) { b.Upper.Timestamp = "1800000000000" }, func(b *RetainedBasis) { b.Upper.Hash = "0x" + strings.Repeat("0", 64) }, func(b *RetainedBasis) { b.DatasetEpoch = "00000000-0000-0000-0000-000000000000" }, func(b *RetainedBasis) { b.Version = 1 }} {
		bad := basis.Clone()
		change(&bad)
		if bad.Valid() {
			t.Fatal("malformed basis accepted")
		}
	}
	for _, level := range []p.Level{p.Redacted, p.Pseudonymous} {
		scope := p.Scope{TargetActors: []string{testActor(1)}, Resources: []p.Resource{p.Transactions}, Addresses: p.Addresses{Mode: "all-target-addresses", Values: []string{}}, DataTime: p.Interval{Start: time.Unix(1800000000, 0).Add(-time.Hour).Unix(), End: 1800000000}, Level: level}
		if _, err := Normalize(Query{Version: 1, Resource: p.Transactions, View: Detail, AddressID: ptr("da1.key.AAAAAAAAAAAAAAAAAAAAAA"), TransactionHash: ptr(hashString(testHash(2)))}, scope); err == nil {
			t.Fatal("lower-detail gate changed")
		}
	}
}
