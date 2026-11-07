package admission

import (
	"math"
	"strings"
	"testing"
	"time"
)

func TestNetworkIndependentLengthPrefixedVectorAndCanonicalRange(t *testing.T) {
	n := NetworkBinding{Environment: "test", ChainID: "1", GenesisHash: "0x" + strings.Repeat("0", 63) + "1", DeploymentID: "test-deployment"}
	key, err := n.Key()
	if err != nil || key.String() != "sha256:308c17e9717958e307cf48c146ecedfe1f51e7e3e712b3cc57ab53fe8b27d44a" {
		t.Fatal("independent Python SHA256/uint32BE vector", key, err)
	}
	for _, chain := range []string{"0", "01", "-1", "+1", "1.0", "18446744073709551616"} {
		changed := n
		changed.ChainID = chain
		if _, err := changed.Key(); err == nil {
			t.Fatal("invalid chain", chain)
		}
	}
	n.ChainID = "18446744073709551615"
	if _, err := n.Key(); err != nil {
		t.Fatal("uint64 max", err)
	}
}
func TestCanonicalFiatPreservesFractionalCentsAndFloatRange(t *testing.T) {
	for _, row := range []struct {
		value float64
		want  string
	}{{0, "0"}, {0.001, "0.001"}, {0.30000000000000004, "0.30000000000000004"}, {math.SmallestNonzeroFloat64, "5e-324"}, {1e99, "1e+99"}} {
		got, err := CanonicalFiat(row.value)
		if err != nil || got != row.want {
			t.Fatalf("%v => %q %v", row.value, got, err)
		}
		round, err := ParseFiat(got)
		if err != nil || round != row.value {
			t.Fatal("round trip", got, err)
		}
	}
	for _, value := range []float64{-1, math.Inf(1), math.Inf(-1), math.NaN(), 1e100} {
		if _, err := CanonicalFiat(value); err == nil {
			t.Fatal("invalid valuation", value)
		}
	}
}
func TestQuoteSnapshotOwnsAndNormalizesProviderObservations(t *testing.T) {
	at := time.Unix(1800000000, 123456789).UTC()
	input := []Quote{{ID: "ethereum", Currency: "eur", Value: 2.001, SourceID: "provider", FetchedAt: at, ProviderAsOf: at.Add(-time.Second)}}
	snapshot, err := NewQuoteSnapshot(input)
	if err != nil {
		t.Fatal(err)
	}
	input[0].Value = 100
	q, ok := snapshot.Get("ethereum", "eur")
	if !ok || q.Value != 2.001 || q.FetchedAt.Nanosecond() != 123456000 || q.Digest != quoteDigest(q) {
		t.Fatal("quote ownership/timestamp binding")
	}
	if _, ok := snapshot.Get("ethereum", "usd"); ok {
		t.Fatal("currency fallback")
	}
	if q.Fresh(at.Add(-2*time.Second), time.Minute) || q.Fresh(at.Add(61*time.Second), time.Minute) || !q.Fresh(at, time.Minute) {
		t.Fatal("freshness interval")
	}
	if _, err := NewQuoteSnapshot([]Quote{q, q}); err == nil {
		t.Fatal("duplicate quote")
	}
}
func TestCursorScopeAndKeyRotation(t *testing.T) {
	now := time.Unix(1800000000, 0).UTC()
	old := CursorKey{ID: "old", Key: []byte(strings.Repeat("a", 32))}
	fresh := CursorKey{ID: "new", Key: []byte(strings.Repeat("b", 32))}
	ring, err := newCursorRing(CursorKeyring{Active: old})
	if err != nil {
		t.Fatal(err)
	}
	c := pageCursor{Version: 1, Purpose: "events", Network: "network", Generation: "generation", Coverage: "coverage", Org: "org", Viewer: "actor", Manifest: "manifest", Query: "50", At: now, ID: "10", Expires: now.Add(time.Minute).Unix()}
	raw, err := ring.seal(c)
	if err != nil {
		t.Fatal(err)
	}
	rotated, err := newCursorRing(CursorKeyring{Active: fresh, Overlap: &old})
	if err != nil {
		t.Fatal(err)
	}
	if got, err := rotated.open(raw, c, now); err != nil || got.ID != "10" {
		t.Fatal("overlap", err)
	}
	for _, change := range []func(*pageCursor){func(c *pageCursor) { c.Viewer = "other" }, func(c *pageCursor) { c.Manifest = "other" }, func(c *pageCursor) { c.Generation = "other" }, func(c *pageCursor) { c.Coverage = "other" }, func(c *pageCursor) { c.Org = "other" }, func(c *pageCursor) { c.Network = "other" }, func(c *pageCursor) { c.Purpose = "records" }, func(c *pageCursor) { c.Query = "100" }} {
		other := c
		change(&other)
		if _, err := rotated.open(raw, other, now); err == nil {
			t.Fatal("scope escaped")
		}
	}
	if _, err := rotated.open(raw, c, now.Add(time.Minute)); err == nil {
		t.Fatal("expired cursor")
	}
	if _, err := newCursorRing(CursorKeyring{Active: CursorKey{ID: "zero", Key: make([]byte, 32)}}); err == nil {
		t.Fatal("zero key")
	}
}
