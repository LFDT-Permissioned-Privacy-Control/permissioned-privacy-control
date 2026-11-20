package protectedsource

import (
	"math"
	"testing"

	d "privacy-proxy/internal/disclosuredata"
	r "privacy-proxy/internal/rpcexecution"
)

func TestEventsPayloadAdmissionIsAtomicAndPaysBeforeCloning(t *testing.T) {
	meta := r.HistoryLogMetadata{TopicCount: 4, DataBytes: 180 << 10}
	work, projection, err := eventCost(meta, 64, true)
	if err != nil || work < 3*meta.DataBytes || projection < 2*meta.DataBytes+66*meta.TopicCount {
		t.Fatal("Full admission undercharges detached raw bytes plus hex output", work, projection, err)
	}
	for _, initial := range []eventPageBudget{{work: work - 1, projection: projection}, {work: work, projection: projection - 1}} {
		budget := initial
		if budget.try(meta, 64, true) || budget != initial {
			t.Fatal("failed first event consumed credits or allowed a raw clone", initial, budget)
		}
	}
	budget := eventPageBudget{work: work, projection: projection}
	if !budget.try(meta, 64, true) || budget != (eventPageBudget{}) {
		t.Fatal("exact affordable event was not charged", budget)
	}
	if budget.try(meta, 64, true) || budget != (eventPageBudget{}) {
		t.Fatal("second event was free or refunded")
	}
	for _, bad := range []r.HistoryLogMetadata{{DataBytes: -1}, {DataBytes: math.MaxInt}, {TopicCount: -1}, {TopicCount: 5}} {
		before := eventPageBudget{work: math.MaxInt, projection: math.MaxInt}
		budget := before
		if budget.try(bad, 64, true) || budget != before {
			t.Fatal("invalid or overflowing metadata affected admission", bad)
		}
	}
	if _, _, err = eventCost(meta, math.MaxInt, true); err == nil {
		t.Fatal("unbounded participant evidence bypassed checked arithmetic")
	}
}

func TestEventsLowerProjectionDoesNotChargeOrCloneRawPayload(t *testing.T) {
	empty := r.HistoryLogMetadata{}
	large := r.HistoryLogMetadata{DataBytes: d.MaxResponseBytes, TopicCount: 4}
	w0, p0, err := eventCost(empty, 64, false)
	if err != nil {
		t.Fatal(err)
	}
	w1, p1, err := eventCost(large, 64, false)
	if err != nil || w0 != w1 || p0 != p1 {
		t.Fatal("lower-level work depended on withheld payload size", w0, p0, w1, p1, err)
	}
	// Source acquisition is charged separately; this reservation covers only
	// the metadata/provenance projection, with no payload/hex getter credit.
	node := &nodeRead{}
	budget, err := node.reserveEvent(false)
	if err != nil || node.owned != eventMetadataWorkingBytes {
		t.Fatal("lower reservation", node.owned, err)
	}
	for i := 0; i < 5; i++ {
		if !budget.try(large, 64, false) {
			t.Fatal("bounded metadata occurrences inherited Full payload ceiling", i)
		}
	}
}

func TestEventsReserveUsesExistingOwnedWorkCeilingWithoutRefunds(t *testing.T) {
	for _, full := range []bool{false, true} {
		reserve := eventMetadataWorkingBytes
		if full {
			reserve = eventFullWorkingBytes
		}
		node := &nodeRead{owned: maxNodeOwned - reserve + 1}
		before := node.owned
		if budget, err := node.reserveEvent(full); err == nil || budget != nil || node.owned != before {
			t.Fatal("unaffordable reservation crossed original limit or changed spent credits", full, node.owned, err)
		}
		node = &nodeRead{owned: maxNodeOwned - reserve}
		if _, err := node.reserveEvent(full); err != nil || node.owned != maxNodeOwned {
			t.Fatal("exact remaining owned capacity not respected", full, node.owned, err)
		}
	}
}
