package historynamespace

import (
	"encoding/hex"
	"encoding/json"
	"math"
	"strings"
	"testing"
	"time"
)

// Public preimages and expected hashes were independently computed with Python
// hashlib/struct/uuid before the Go implementation existed.
func TestSegmentKeyCompatibilityGoldens(t *testing.T) {
	var network Digest
	var address Address
	var runtime Hash
	for i := range network {
		network[i] = byte(i + 1)
	}
	for i := range address {
		address[i] = byte(i + 1)
	}
	for i := range runtime {
		runtime[i] = 0xab
	}
	const lifetime = "12345678-1234-4234-8234-123456789abc"
	tests := []struct{ kind, changed, expected string }{
		{"legacy", "base", "4d313b196b6c4e1386c05a699eada264b1d0d979a4164ea7f3dea5a535635698"},
		{"legacy", "network", "1e37307060532cc95813341e26203ea2488f492da9a318232e1477984476cdb7"},
		{"legacy", "address", "10f662d363931aeae0592ac1e06d32b91a8d8f58627f90069828108f3f0a342f"},
		{"legacy", "uuid", "c1f59fb51eec8f0153648f68a930cdc0afb72d9d9c863a631c4c11f7be9c5961"},
		{"prague", "base", "3a8ab45828613e4abd5de600d3083e7979548af9607fb993591af7442fc5364e"},
		{"prague", "network", "4ead207c723513f2cca27d08274f1b2542e09a6b902b9ede11494a6957ba8928"},
		{"prague", "address", "48cd341505cc49e1087f63f1efd365fd48bb6cada6abcda8f8bbe680076faad0"},
		{"prague", "runtimeHash", "b9c22ba69cab7f91c470cc515a35d6c1b129abe5cacd4c47afa153c3346c1f92"},
		{"prague", "runtimeLength", "d73b6b7c81e9c7a8b2fb791af6b9df425ee20a3a93a9139bb737209c1c648a74"},
	}
	for _, tt := range tests {
		t.Run(tt.kind+"/"+tt.changed, func(t *testing.T) {
			n, a, h, id, size := network, address, runtime, lifetime, uint32(1)
			switch tt.changed {
			case "network":
				for i := range n {
					n[i] = 0x22
				}
			case "address":
				for i := range a {
					a[i] = 0x33
				}
			case "uuid":
				id = "12345678-1234-4234-8234-123456789abd"
			case "runtimeHash":
				for i := range h {
					h[i] = 0xac
				}
			case "runtimeLength":
				size = 2
			}
			var got Digest
			var err error
			if tt.kind == "legacy" {
				got, err = PreEraSegmentKey(n, a, id)
			} else {
				got, err = PragueSegmentKey(n, a, h, size)
			}
			if err != nil || hex.EncodeToString(got[:]) != tt.expected {
				t.Fatalf("key=%s error=%v", got, err)
			}
		})
	}
}

func TestCanonicalMetadataAndBounds(t *testing.T) {
	for _, value := range []string{"00000000-0000-0000-0000-000000000000", "12345678-1234-4234-8234-123456789ABC", "12345678123442348234123456789abc", "12345678--123-4234-8234-123456789abc"} {
		if UUID(value) {
			t.Errorf("accepted noncanonical UUID %q", value)
		}
	}
	if !UUID("12345678-1234-4234-8234-123456789abc") {
		t.Fatal("canonical UUID rejected")
	}
	for _, raw := range []string{`null`, `[]`, `"0X` + strings.Repeat("ab", 32) + `"`, `"0x` + strings.Repeat("AB", 32) + `"`, `"0x0"`} {
		var h Hash
		if json.Unmarshal([]byte(raw), &h) == nil {
			t.Errorf("accepted noncanonical hash %s", raw)
		}
	}
	for _, seconds := range []int64{0, -1, 1801, math.MaxInt64} {
		if _, err := OfflineTimeout(seconds); err == nil {
			t.Errorf("unbounded timeout %d", seconds)
		}
	}
	if got, err := OfflineTimeout(1800); err != nil || got != 30*time.Minute {
		t.Fatalf("maximum timeout=%v %v", got, err)
	}
	limits := DefaultCapacityLimits()
	if !limits.Valid() {
		t.Fatal("default limits rejected")
	}
	limits.Lifetimes++
	if limits.Valid() {
		t.Fatal("capacity ceiling raised")
	}
}
