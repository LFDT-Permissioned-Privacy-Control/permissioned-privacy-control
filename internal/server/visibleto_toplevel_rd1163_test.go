package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"privacy-proxy/internal/db"
)

// Compile-time proof the production rbac store type (*db.DB) satisfies the
// ethAddressResolver capability the call sites assert on. If GetDIDByEthAddress
// changes shape, this fails to compile — catching a silent addr→DID break
// (which would fail-close every top-level `privateFor: [addresses]`).
var _ ethAddressResolver = (*db.DB)(nil)

// fakeEthResolver maps lowercased address → DID; unknown → "" (fail-closed).
type fakeEthResolver struct {
	m   map[string]string
	err error
}

func (f fakeEthResolver) GetDIDByEthAddress(_ context.Context, addr string) (string, error) {
	if f.err != nil {
		return "", f.err
	}
	return f.m[strings.ToLower(addr)], nil
}

// countingEthResolver records how many address lookups happen — used to prove
// the over-cap guard resolves nothing (RD-1163 amplification fix).
type countingEthResolver struct{ calls *int }

func (c countingEthResolver) GetDIDByEthAddress(_ context.Context, addr string) (string, error) {
	*c.calls++
	return "did:test:" + strings.ToLower(addr), nil
}

// TestResolveTopLevelVisibleTo_CapBeforeResolve_RD1163 pins the fix for the
// Copilot amplification finding on PR #364: an over-cap raw list is rejected
// with a 400 BEFORE any address is resolved (zero DB lookups), so a client
// cannot drive one GetDIDByEthAddress query per address for a list bounded only
// by the request body size. A within-cap list resolves with lookups bounded by
// visibleToMaxSize.
func TestResolveTopLevelVisibleTo_CapBeforeResolve_RD1163(t *testing.T) {
	addrs := func(n int) []string {
		out := make([]string, n)
		for i := range out {
			out[i] = fmt.Sprintf("0x%040x", i+1) // 0x + 40 hex → valid isEthAddress, all distinct
		}
		return out
	}

	t.Run("over cap: rejected before any resolution", func(t *testing.T) {
		calls := 0
		got, capErr := resolveTopLevelVisibleTo(context.Background(), countingEthResolver{&calls}, addrs(visibleToMaxSize+1))
		if capErr == nil {
			t.Fatal("expected a 400 ProcessError for an over-cap list, got nil")
		}
		if capErr.StatusCode != http.StatusBadRequest {
			t.Errorf("StatusCode = %d, want %d", capErr.StatusCode, http.StatusBadRequest)
		}
		if got != nil {
			t.Errorf("expected nil result on reject, got %v", got)
		}
		if calls != 0 {
			t.Errorf("resolver called %d times; must be 0 (no DB work before the cap check)", calls)
		}
	})

	t.Run("at cap: resolves, lookups bounded by cap", func(t *testing.T) {
		calls := 0
		got, capErr := resolveTopLevelVisibleTo(context.Background(), countingEthResolver{&calls}, addrs(visibleToMaxSize))
		if capErr != nil {
			t.Fatalf("unexpected error at cap: %+v", capErr)
		}
		if len(got) != visibleToMaxSize {
			t.Errorf("resolved %d DIDs, want %d", len(got), visibleToMaxSize)
		}
		if calls > visibleToMaxSize {
			t.Errorf("resolver called %d times; must be <= %d", calls, visibleToMaxSize)
		}
	})
}

func eqStrs(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestExtractAndStripTopLevelVisibleTo_RD1163(t *testing.T) {
	tests := []struct {
		name         string
		body         string
		wantEntries  []string
		wantStripped bool // body must no longer carry visibleTo/privateFor
	}{
		{
			name:         "top-level visibleTo DIDs",
			body:         `{"jsonrpc":"2.0","id":1,"method":"eth_sendRawTransaction","params":["0xabc"],"visibleTo":["did:test:bob","did:test:carol"]}`,
			wantEntries:  []string{"did:test:bob", "did:test:carol"},
			wantStripped: true,
		},
		{
			name:         "top-level privateFor addresses (Quorum alias)",
			body:         `{"jsonrpc":"2.0","id":1,"method":"eth_sendRawTransaction","params":["0xabc"],"privateFor":["0x70997970C51812dc3A010C7d01b50e0d17dc79C8"]}`,
			wantEntries:  []string{"0x70997970C51812dc3A010C7d01b50e0d17dc79C8"},
			wantStripped: true,
		},
		{
			name:         "both keys unioned",
			body:         `{"jsonrpc":"2.0","id":1,"method":"eth_sendTransaction","params":[{"to":"0x1"}],"visibleTo":["did:test:bob"],"privateFor":["0xabc0000000000000000000000000000000000001"]}`,
			wantEntries:  []string{"did:test:bob", "0xabc0000000000000000000000000000000000001"},
			wantStripped: true,
		},
		{
			name:         "neither present -> nil, body untouched",
			body:         `{"jsonrpc":"2.0","id":1,"method":"eth_sendRawTransaction","params":["0xabc"]}`,
			wantEntries:  nil,
			wantStripped: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &ProcessRequest{Body: []byte(tt.body)}
			got := extractAndStripTopLevelVisibleTo(req)
			if !eqStrs(got, tt.wantEntries) {
				t.Fatalf("entries = %v, want %v", got, tt.wantEntries)
			}
			var env map[string]json.RawMessage
			if err := json.Unmarshal(req.Body, &env); err != nil {
				t.Fatalf("body not valid JSON after strip: %v\n%s", err, req.Body)
			}
			_, hasVT := env["visibleTo"]
			_, hasPF := env["privateFor"]
			// In every case the forwarded body must not carry the field (either
			// stripped, or never present).
			if hasVT || hasPF {
				t.Errorf("visibleTo/privateFor must be absent from forwarded body; body=%s", req.Body)
			}
			// When nothing was present the body must be byte-for-byte untouched.
			if !tt.wantStripped && string(req.Body) != tt.body {
				t.Errorf("body should be untouched when no field present:\n got=%s\nwant=%s", req.Body, tt.body)
			}
			// params + method must always survive.
			if _, ok := env["params"]; !ok {
				t.Errorf("params dropped from body: %s", req.Body)
			}
			if _, ok := env["method"]; !ok {
				t.Errorf("method dropped from body: %s", req.Body)
			}
		})
	}
}

func TestResolveVisibleToEntries_RD1163(t *testing.T) {
	resolver := fakeEthResolver{m: map[string]string{
		"0x70997970c51812dc3a010c7d01b50e0d17dc79c8": "did:test:bob",
	}}
	tests := []struct {
		name     string
		resolver ethAddressResolver
		entries  []string
		want     []string
	}{
		{"DIDs kept", resolver, []string{"did:test:alice", "did:test:bob"}, []string{"did:test:alice", "did:test:bob"}},
		{"address resolved to DID", resolver, []string{"0x70997970C51812dc3A010C7d01b50e0d17dc79C8"}, []string{"did:test:bob"}},
		{"unknown address dropped (fail-closed)", resolver, []string{"0xdeadbeef00000000000000000000000000000000"}, nil},
		{"nil resolver drops all addresses", nil, []string{"0x70997970C51812dc3A010C7d01b50e0d17dc79C8", "did:test:alice"}, []string{"did:test:alice"}},
		{"mixed DID + address (case-insensitive)", resolver, []string{"did:test:alice", "0x70997970c51812dc3a010c7d01b50e0d17dc79c8"}, []string{"did:test:alice", "did:test:bob"}},
		{"dedupe after resolution", resolver, []string{"did:test:bob", "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"}, []string{"did:test:bob"}},
		{"garbage ignored", resolver, []string{"not-a-did", "0xshort", ""}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := resolveVisibleToEntries(context.Background(), tt.resolver, tt.entries)
			if !eqStrs(got, tt.want) {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}

	t.Run("resolver error is fail-closed", func(t *testing.T) {
		errRes := fakeEthResolver{err: context.DeadlineExceeded}
		got := resolveVisibleToEntries(context.Background(), errRes, []string{"0x70997970C51812dc3A010C7d01b50e0d17dc79C8"})
		if len(got) != 0 {
			t.Errorf("expected fail-closed empty on resolver error, got %v", got)
		}
	})
}

func TestIsEthAddress_RD1163(t *testing.T) {
	cases := map[string]bool{
		"0x70997970C51812dc3A010C7d01b50e0d17dc79C8": true,
		"0x0000000000000000000000000000000000000000": true,
		"70997970C51812dc3A010C7d01b50e0d17dc79C8":   false, // no 0x
		"0x123":        false, // too short
		"did:test:bob": false,
		"0xZZ97970C51812dc3A010C7d01b50e0d17dc79C8": false, // non-hex
	}
	for in, want := range cases {
		if got := isEthAddress(in); got != want {
			t.Errorf("isEthAddress(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestUnionVisibleToDIDs_RD1163(t *testing.T) {
	tests := []struct {
		name string
		a, b []string
		want []string
	}{
		{"disjoint", []string{"did:test:a"}, []string{"did:test:b"}, []string{"did:test:a", "did:test:b"}},
		{"overlap deduped", []string{"did:test:a", "did:test:b"}, []string{"did:test:b", "did:test:c"}, []string{"did:test:a", "did:test:b", "did:test:c"}},
		{"empty b", []string{"did:test:a"}, nil, []string{"did:test:a"}},
		{"empty a", nil, []string{"did:test:b"}, []string{"did:test:b"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := unionVisibleToDIDs(tt.a, tt.b); !eqStrs(got, tt.want) {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}
