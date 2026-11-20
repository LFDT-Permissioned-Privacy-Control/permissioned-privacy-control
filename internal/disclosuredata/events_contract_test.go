package disclosuredata

import (
	"bytes"
	"encoding/json"
	"testing"

	p "privacy-proxy/internal/disclosurepolicy"
)

func TestEventsOpaqueIdentityBindsNetworkCaseRecipientAndRenderGeneration(t *testing.T) {
	project := func(s ReadScope, plan SourcePlan, ds []SourceDescriptor, facts Facts, c RenderContext) string {
		t.Helper()
		result, err := RenderRetained(plan, s, ds, facts, c, "88888888-8888-4888-8888-888888888888")
		if err != nil {
			t.Fatal(err)
		}
		raw, err := json.Marshal(result)
		if err != nil {
			t.Fatal(err)
		}
		var dto struct{ Result struct{ Items []EventDTO } }
		if json.Unmarshal(raw, &dto) != nil || len(dto.Result.Items) != 1 {
			t.Fatal("event projection", string(raw))
		}
		return dto.Result.Items[0].EventID
	}
	s, plan, ds, facts, c := eventsFixture(t, p.Full)
	base := project(s, plan, ds, facts, c)
	for _, name := range []string{"network", "case", "recipient", "namespace", "render generation"} {
		t.Run(name, func(t *testing.T) {
			s, plan, ds, facts, c := eventsFixture(t, p.Full)
			switch name {
			case "network":
				plan.NetworkKey = testDigest(91)
				for i := range ds {
					ds[i].NetworkKey = plan.NetworkKey
				}
			case "case":
				s.CaseID = "99999999-9999-4999-8999-999999999999"
				c.CaseID = s.CaseID
			case "recipient":
				s.RecipientActorID = testActor(9)
				c.RecipientActorID = s.RecipientActorID
			case "namespace":
				s.Namespace = testDigest(92)
				c.Namespace = s.Namespace
			case "render generation":
				c.Keys.Active = Key{ID: "next", Bytes: bytes.Repeat([]byte{81}, 32)}
			}
			if id := project(s, plan, ds, facts, c); id == base {
				t.Fatal("event identity crossed its context", name, id)
			}
		})
	}
	s, plan, ds, facts, c = eventsFixture(t, p.Full)
	c.Keys.Previous = &Key{ID: "previous", Bytes: bytes.Repeat([]byte{82}, 32)}
	if got := project(s, plan, ds, facts, c); got != base {
		t.Fatal("adding an inactive decode key changed active render identity")
	}
	for _, level := range []p.Level{p.Pseudonymous, p.Redacted} {
		s, plan, ds, facts, c := eventsFixture(t, level)
		if got := project(s, plan, ds, facts, c); got != base {
			t.Fatal("same case event changed identity solely with privacy level", level)
		}
	}
}

func TestEventsRejectContradictoryParentPayloadAndSourceFacts(t *testing.T) {
	for _, name := range []string{"missing participant", "failed parent", "duplicate global log", "same block conflicting hash", "same parent conflicting hash", "mixed branch", "missing Full payload", "too many topics", "Events descriptor on Transactions", "transaction descriptor on Events"} {
		t.Run(name, func(t *testing.T) {
			s, plan, ds, facts, _ := eventsFixture(t, p.Full)
			switch name {
			case "missing participant":
				facts.Events[0].Transaction.From = testAddress(8)
				facts.Events[0].Transaction.To = ptr(testAddress(9))
			case "failed parent":
				facts.Events[0].Transaction.Status = 0
			case "duplicate global log":
				second := facts.Events[0]
				second.Transaction.TransactionIndex++
				second.Transaction.Hash = testHash(8)
				facts.Events = append(facts.Events, second)
			case "same block conflicting hash":
				second := facts.Events[0]
				second.Transaction.TransactionIndex++
				second.Transaction.Hash = testHash(8)
				second.Transaction.BlockHash = testHash(9)
				second.LogIndex++
				facts.Events = append(facts.Events, second)
			case "same parent conflicting hash":
				second := facts.Events[0]
				second.Transaction.Hash = testHash(8)
				second.LogIndex++
				facts.Events = append(facts.Events, second)
			case "mixed branch":
				facts.Transactions = []TransactionFact{}
			case "missing Full payload":
				facts.Events[0].Payload = nil
			case "too many topics":
				facts.Events[0].Payload.Topics = make([][32]byte, 5)
			case "Events descriptor on Transactions":
				plan.Resources = []p.Resource{p.Events, p.Transactions}
				if _, err := SourceSetDigestRetained(plan, ds, p.Transactions, List); err == nil {
					t.Fatal("Events evidence became generic transaction evidence")
				}
				return
			case "transaction descriptor on Events":
				for i := range ds {
					if ds[i].Kind == HistorySource {
						ds[i].Version = 2
						ds[i].Population = RetainedHistoryPopulation
						ds[i].FormatDigest = testDigest(16)
					}
				}
			}
			if ValidateFactsRetained(plan, s, ds, facts, nil) == nil {
				t.Fatal("contradictory event facts accepted", name)
			}
		})
	}
	s, plan, ds, facts, _ := eventsFixture(t, p.Redacted)
	facts.Events[0].Payload = &EventPayload{Topics: [][32]byte{}, Data: []byte{}}
	if ValidateFactsRetained(plan, s, ds, facts, nil) == nil {
		t.Fatal("lower-level facts accepted even an empty raw payload branch")
	}
}

func TestEventsPendingInputCannotClaimGlobalEndOrAnotherParent(t *testing.T) {
	s, plan, ds, facts, _ := eventsFixture(t, p.Full)
	ev := facts.Events[0]
	parent := TransactionPosition{ev.Transaction.BlockNumber, ev.Transaction.TransactionIndex, ev.Transaction.Hash}
	after := &Position{Kind: HistorySource, Events: &EventsPosition{Parent: parent, Mode: "pending", NextLogIndex: ptr(ev.LogIndex)}}
	facts.End = false
	facts.Next = &Position{Kind: HistorySource, Events: &EventsPosition{Parent: parent, Mode: "after"}}
	if err := ValidateFactsRetained(plan, s, ds, facts, after); err != nil {
		t.Fatal("completed pending receipt must request separate exhaustion probe", err)
	}
	for _, name := range []string{"global end", "next parent", "visible parent"} {
		bad, err := DetachFacts(facts)
		if err != nil {
			t.Fatal(err)
		}
		switch name {
		case "global end":
			bad.End = true
			bad.Next = nil
		case "next parent":
			bad.Next.Events.Parent.BlockNumber = "6"
		case "visible parent":
			bad.Events[0].Transaction.TransactionIndex++
			bad.Next.Events.Parent.TransactionIndex++
		}
		if ValidateFactsRetained(plan, s, ds, bad, after) == nil {
			t.Fatal("pending cursor closure violated", name)
		}
	}
}

func TestEventsPayloadBytesAreNotContainerCardinality(t *testing.T) {
	s, plan, ds, facts, c := eventsFixture(t, p.Full)
	facts.Events[0].Payload.Data = bytes.Repeat([]byte{0x7a}, 32<<10)
	if err := ValidateFactsRetained(plan, s, ds, facts, nil); err != nil {
		t.Fatal("valid >16384-byte payload was charged as container entries", err)
	}
	result, err := RenderRetained(plan, s, ds, facts, c, "88888888-8888-4888-8888-888888888888")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	var dto struct{ Result struct{ Items []EventDTO } }
	if json.Unmarshal(raw, &dto) != nil || len(dto.Result.Items) != 1 || dto.Result.Items[0].Data == nil || len(*dto.Result.Items[0].Data) != 2+(32<<10)*2 {
		t.Fatal("payload was truncated or omitted")
	}
	facts.Events[0].Payload.Data = make([]byte, MaxVariableBytes+1)
	if CheckFactsBudget(facts) == nil {
		t.Fatal("payload bytes escaped shared owned-facts byte ceiling")
	}
}
