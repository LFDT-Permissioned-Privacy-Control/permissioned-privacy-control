package rpcexecution

import (
	f "privacy-proxy/internal/creationfacts"
	"testing"
)

func TestMinedFiniteBudgetCoversAcquisitionAndRepeatedDelivery(t *testing.T) {
	fixture := newMinedFixture(t, 2, false, false)
	limits := DefaultMinedTraceLimits()
	limits.MaxRequests = 16
	envelope, err := fixture.client.AcquireMinedEnvelope(t.Context(), fixture.tx.Hash(), limits)
	if err != nil {
		t.Fatal(err)
	}
	execution, err := envelope.AcquireTrace(t.Context(), false)
	if err != nil {
		t.Fatal(err)
	}
	checkpoint, err := execution.DeliveryCheckpoint()
	if err != nil {
		t.Fatal(err)
	}
	exhausted := false
	for i := 0; i < 8; i++ {
		if checkpoint.RequireCurrent(t.Context(), f.Header{}) != nil {
			exhausted = true
			break
		}
	}
	if !exhausted || len(fixture.methods) > limits.MaxRequests {
		t.Fatal("physical budget reset across acquisition/delivery", len(fixture.methods))
	}
	fixture = newMinedFixture(t, 2, false, false)
	limits = DefaultMinedTraceLimits()
	limits.MaxResponseBytes = 1
	if _, err = fixture.client.AcquireMinedEnvelope(t.Context(), fixture.tx.Hash(), limits); err == nil || len(fixture.methods) != 0 {
		t.Fatal("delivery byte reserve bypassed before node work", err, fixture.methods)
	}
}

func TestMinedActualTraceRecordLimitFailsClosed(t *testing.T) {
	fixture := newMinedFixture(t, 2, false, false)
	fixture.root["calls"] = []any{map[string]any{"type": "CALL", "from": fixture.tx.To().Hex(), "to": fixture.tx.To().Hex(), "input": "0x", "value": "0x0", "gas": "0x10", "gasUsed": "0x1", "output": "0xdead"}}
	limits := DefaultMinedTraceLimits()
	limits.Execution.Trace.MaxRecords = 1
	envelope, err := fixture.client.AcquireMinedEnvelope(t.Context(), fixture.tx.Hash(), limits)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = envelope.AcquireTrace(t.Context(), false); err == nil {
		t.Fatal("over-limit mined trace produced output")
	}
}
