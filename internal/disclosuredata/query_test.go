package disclosuredata

import (
	"encoding/json"
	"errors"
	"testing"

	p "privacy-proxy/internal/disclosurepolicy"
)

func TestClosedQueryAndCanonicalSubset(t *testing.T) {
	for _, raw := range []string{`{"v":1,"resource":"activity_summary","view":"report"}`, `{"v":1,"resource":"events","view":"list"}`} {
		if _, e := DecodeQuery([]byte(raw)); e != nil {
			t.Fatal(raw, e)
		}
	}
	for _, raw := range []string{`{"v":1,"resource":"activity_summary","view":"report","cursor":null}`, `{"v":1,"v":1,"resource":"activity_summary","view":"report"}`, `{"v":1,"resource":"activity_summary","view":"report","dataTime":{"start":null,"end":0}}`, `{"v":1,"resource":"activity_summary","view":"report","dataTime":{"end":0}}`, `{"v":1e0,"resource":"activity_summary","view":"report"}`, `{"v":1,"resource":"activity_summary","view":"report","url":"https://evil.test"}`, `{"v":1,"resource":"activity_summary","view":"report"} {}`, `{"v":1,"resource":"activity_summary","view":"report","limit":1}`} {
		if _, e := DecodeQuery([]byte(raw)); e == nil {
			t.Fatal("closed query accepted", raw)
		}
	}
	s, _, _, _ := testFixture(t, p.ActivitySummary, Report, p.Full)
	period := p.Interval{Start: 1790812800, End: 1793491199}
	original := s.Query.Scope()
	original.DataTime = p.Interval{Start: 0, End: p.MaxUnixSeconds}
	q := Query{Version: 1, Resource: p.ActivitySummary, View: Report, DataTime: &period}
	n, e := Normalize(q, original)
	if e != nil || n.Scope().DataTime != period {
		t.Fatal("month period acquired unrelated block/row cap", e)
	}
	raw, _ := json.Marshal(q)
	q2, e := DecodeQuery(raw)
	if e != nil {
		t.Fatal(e)
	}
	n2, e := Normalize(q2, original)
	if e != nil || n.Digest() != n2.Digest() {
		t.Fatal("canonical query identity", e)
	}
	changed := n.Scope()
	changed.TargetActors[0] = testActor(99)
	if n.Scope().TargetActors[0] == testActor(99) {
		t.Fatal("mutable normalized scope")
	}
	original.Addresses = p.Addresses{Mode: "list", Values: []string{addressString(testAddress(1))}}
	if _, e := Normalize(q, original); !errors.Is(e, ErrUnsupported) {
		t.Fatal("address predicate silently dropped", e)
	}
}
func TestDetailValuesDeferredUntilServiceFullGate(t *testing.T) {
	q, e := DecodeQuery([]byte(`{"v":1,"resource":"transactions","view":"detail","transactionHash":"malformed"}`))
	if e != nil {
		t.Fatal("decoder ran value/required check before service Full gate", e)
	}
	s, _, _, _ := testFixture(t, p.Transactions, List, p.Full)
	if _, e := Normalize(q, s.Query.Scope()); e == nil {
		t.Fatal("Full normalization ignored malformed locator/hash")
	}
}
