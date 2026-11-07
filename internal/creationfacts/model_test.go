package creationfacts

import (
	"bytes"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
)

func TestCaptureFenceIndependentSHA256Goldens(t *testing.T) {
	// Independently calculated with Python hashlib from the protocol domain.
	if CaptureFence(Digest{}) != -6031844697154263870 {
		t.Fatal("cross-process fence domain changed")
	}
	var ones Digest
	for i := range ones {
		ones[i] = 1
	}
	if CaptureFence(ones) != -7589445979260398814 {
		t.Fatal("network fence identity changed")
	}
}
func TestCoverageBoundsAndLiveTTLAreNotHistoricalExpiry(t *testing.T) {
	epoch := "11111111-1111-1111-1111-111111111111"
	start := time.Unix(100, 0).UTC()
	h := Header{Number: 1, Hash: common.Hash{1}}
	r := CoverageRecord{Version: 1, Policy: CaptureProfile, Network: Digest{1}, State: State{Generation: epoch}, ObserverEpoch: epoch, CaptureEpoch: epoch, SourceSet: Digest{2}, Reference: Digest{3}, Ingress: Digest{4}, HighWater: h, Latest: h, HeaderVersion: 1, LeaseFence: 1, ProbeStarted: start, ProbeFinished: start.Add(time.Second), ValidUntil: start.Add(2 * time.Second)}
	raw, err := r.Canonical()
	if err != nil || len(raw) > MaxCoverageBytes {
		t.Fatal("valid bounded original observation", len(raw), err)
	}
	if !bytes.Contains(raw, []byte(CaptureProfile)) {
		t.Fatal("lost capture variant")
	}
	// The original diagnostic expiry is in1970. Shape validation preserves
	// this historical first observation; no current-time freshness claim.
	if r.Digest() == (Digest{}) {
		t.Fatal("historical observation expired")
	}
	for _, change := range []func(*CoverageRecord){func(v *CoverageRecord) { v.ProbeFinished = v.ProbeStarted.Add(CaptureTimeout + 1) }, func(v *CoverageRecord) { v.ValidUntil = v.ProbeFinished.Add(HeartbeatTTL + 1) }, func(v *CoverageRecord) { v.Policy = "" }, func(v *CoverageRecord) { v.CaptureEpoch = "" }, func(v *CoverageRecord) { v.HighWater.Number = 2 }} {
		bad := r
		change(&bad)
		if _, err := bad.Canonical(); err == nil {
			t.Fatal("invalid observation accepted")
		}
	}
	cp := Checkpoint{Network: r.Network, State: r.State, ObserverEpoch: epoch, CaptureEpoch: epoch, SourceSet: r.SourceSet, Reference: r.Reference, HighWater: h, HeaderVersion: 1, LeaseFence: 1, RemainingTTL: HeartbeatTTL}
	if !cp.Valid() {
		t.Fatal("valid live checkpoint rejected")
	}
	for _, ttl := range []time.Duration{0, -1, HeartbeatTTL + 1, time.Duration(1<<63 - 1)} {
		cp.RemainingTTL = ttl
		if cp.Valid() {
			t.Fatal("unbounded live TTL accepted", ttl)
		}
	}
}
