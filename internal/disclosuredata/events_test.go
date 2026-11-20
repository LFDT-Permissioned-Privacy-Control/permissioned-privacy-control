package disclosuredata

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"

	p "privacy-proxy/internal/disclosurepolicy"
)

func eventsFixture(t *testing.T, level p.Level) (ReadScope, SourcePlan, []SourceDescriptor, Facts, RenderContext) {
	s, plan, ds, f, c := retainedFixture(t, p.Transactions, List, level)
	base := s.Query.Scope()
	base.Resources = []p.Resource{p.Events}
	q, err := NormalizeRetained(Query{Version: 1, Resource: p.Events, View: List}, base)
	if err != nil {
		t.Fatal(err)
	}
	s.Query = q
	c.Query = q
	plan.Version, plan.Profile, plan.Resources = 4, NativeEventsSourceProfile, []p.Resource{p.Events}
	for i := range ds {
		if ds[i].Kind == HistorySource {
			ds[i].Version, ds[i].Population, ds[i].FormatDigest = 3, RetainedEventsPopulation, EventsFormat()
		}
	}
	tx := f.Transactions[0]
	tx.Provenance.Kind = RetainedEventsPopulation
	f.Transactions = nil
	event := EventFact{Transaction: tx, Emitter: testAddress(3), LogIndex: 1}
	if level == p.Full {
		event.Payload = &EventPayload{Topics: [][32]byte{testHash(7)}, Data: []byte{1, 2, 3}}
	}
	f.Events = []EventFact{event}
	return s, plan, ds, f, c
}

func TestEventsClosedProjectionAndActualSerializerFixture(t *testing.T) {
	outputs := map[string]json.RawMessage{}
	for _, level := range []p.Level{p.Full, p.Pseudonymous, p.Redacted} {
		s, plan, ds, f, c := eventsFixture(t, level)
		if err := ValidateFactsRetained(plan, s, ds, f, nil); err != nil {
			t.Fatal(err)
		}
		r, err := RenderRetained(plan, s, ds, f, c, "88888888-8888-4888-8888-888888888888")
		if err != nil {
			t.Fatal(err)
		}
		raw, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		var wire struct {
			Result struct {
				Items []map[string]any `json:"items"`
			} `json:"result"`
		}
		if json.Unmarshal(raw, &wire) != nil || len(wire.Result.Items) != 1 {
			t.Fatal("wrong events shape")
		}
		item := wire.Result.Items[0]
		if level == p.Full {
			if item["data"] != "0x010203" || item["payload"] != "disclosed" || item["transactionHash"] != hashString(testHash(2)) {
				t.Fatal("Full payload changed")
			}
		} else {
			for _, field := range []string{"topics", "data", "transactionHash", "blockHash"} {
				if _, ok := item[field]; ok {
					t.Fatal("private field present", field)
				}
			}
			if bytes.Contains(raw, []byte(addressString(testAddress(3)))) || bytes.Contains(raw, []byte(hashString(testHash(7)))) {
				t.Fatal("private value leaked")
			}
		}
		outputs[string(level)] = raw
	}
	s, plan, ds, f, c := eventsFixture(t, p.Redacted)
	f.Events = []EventFact{}
	f.End = false
	f.Next = &Position{Kind: HistorySource, Events: &EventsPosition{Parent: TransactionPosition{"5", 0, testHash(2)}, Mode: "pending", NextLogIndex: ptr(uint32(2))}}
	if err := ValidateFactsRetained(plan, s, ds, f, nil); err != nil {
		t.Fatal("empty advancing page", err)
	}
	r, err := RenderRetained(plan, s, ds, f, c, "88888888-8888-4888-8888-888888888888")
	if err != nil {
		t.Fatal(err)
	}
	r, err = r.WithCursor("opaque-events-next")
	if err != nil {
		t.Fatal(err)
	}
	outputs["emptyAdvancing"], err = json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if file := os.Getenv("OPS_TEST_EVENTS_DTO_FILE"); file != "" {
		raw, _ := json.MarshalIndent(outputs, "", "  ")
		if err = os.WriteFile(file, append(raw, '\n'), 0600); err != nil {
			t.Fatal(err)
		}
	}
}

func TestEventsOriginalCursorProgressAndLegacyIsolation(t *testing.T) {
	s, plan, ds, f, c := eventsFixture(t, p.Full)
	parent := TransactionPosition{"5", 0, testHash(2)}
	start := &Position{Kind: HistorySource, Events: &EventsPosition{Parent: parent, Mode: "pending", NextLogIndex: ptr(uint32(1))}}
	f.End = false
	f.Next = ClonePosition(start)
	f.Next.Events.NextLogIndex = ptr(uint32(2))
	if err := ValidateFactsRetained(plan, s, ds, f, start); err != nil {
		t.Fatal("next unscanned log must be includable", err)
	}
	after := ClonePosition(start)
	after.Events.Mode = "after"
	after.Events.NextLogIndex = nil
	if ValidateFactsRetained(plan, s, ds, f, after) == nil {
		t.Fatal("already scanned parent repeated")
	}
	f.End = false
	f.Next = ClonePosition(start)
	if ValidateFactsRetained(plan, s, ds, f, start) == nil {
		t.Fatal("nonadvancing cursor")
	}
	f.Next.Events.NextLogIndex = ptr(uint32(2))
	if err := ValidateFactsRetained(plan, s, ds, f, start); err != nil {
		t.Fatal(err)
	}
	generation, _ := RenderGeneration(c.Keys)
	b := CursorBinding{Namespace: s.Namespace, CaseID: s.CaseID, CaseVersion: s.CaseVersion, RecipientActorID: s.RecipientActorID, BundleDigest: s.BundleDigest, RuleDigest: s.RuleDigest, QueryDigest: s.Query.Digest(), RenderGeneration: generation, SourcePlanDigest: plan.PlanDigest}
	set, err := SourceSetDigestRetained(plan, ds, p.Events, List)
	if err != nil {
		t.Fatal(err)
	}
	refs, _ := SourceReferencesRetained(plan, ds)
	keys := Keys{Active: Key{ID: "data", Bytes: bytes.Repeat([]byte{81}, 32)}}
	cursor, _ := NewCursor(keys)
	raw, err := cursor.SealRetained(plan, b, p.Events, testRetainedBasis(), set, refs, *f.Next, c.EffectiveUntil)
	if err != nil {
		t.Fatal(err)
	}
	got, err := cursor.OpenRetained(raw, plan, b, p.Events, c.PreparedAt)
	if err != nil {
		t.Fatal(err)
	}
	pos := got.Position()
	if pos.Events == nil || *pos.Events.NextLogIndex != 2 {
		t.Fatal("pending position lost")
	}
	if _, err = cursor.Seal(b, set, refs, *f.Next, c.EffectiveUntil); err == nil {
		t.Fatal("legacy dd1 accepted Events")
	}
	if PositionForQuery(NormalizedQuery{view: List, resource: p.Transactions}, f.Next) == nil {
		t.Fatal("event cursor accepted as transaction")
	}
	old := plan
	old.Version, old.Profile = 3, NativeFinanceSourceProfile
	if ValidRetainedPlan(old) || ValidateFactsRetained(old, s, ds, f, nil) == nil {
		t.Fatal("old native profile gained event access")
	}
}
