package tracer

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// RD-915 KD-7 regression net.
//
// The eth_call validation path must NOT consult or update the trace cache,
// because proxy-pattern contracts (EIP-1967, Diamond, Beacon, transparent
// upgradeable) can re-target their internal calls by rewriting a storage
// slot. A (from,to,data,value)-keyed cache yields stale "allow" decisions
// after a cross-org upgrade.
//
// Two tests:
//   TestTraceTransactionUncached_BypassesCachedHit — pre-seeded cache entry
//     is ignored; upstream is called instead.
//   TestTraceTransactionUncached_DoesNotPopulateCache — successful
//     uncached trace leaves the cache untouched.

func mockTraceServer(t *testing.T) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"jsonrpc": "2.0",
			"id":      1,
			"result": map[string]any{
				"type": "CALL",
				"from": "0xsender",
				"to":   "0xcontract",
			},
		})
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

func TestTraceTransactionUncached_BypassesCachedHit(t *testing.T) {
	srv, hits := mockTraceServer(t)

	rt := NewRuntimeTracer(RuntimeTracerConfig{
		NodeURL:  srv.URL,
		Enabled:  true,
		CacheTTL: 30 * time.Second,
		Timeout:  2 * time.Second,
	})
	t.Cleanup(rt.Stop)

	// Pre-seed the cache with a poisoned "allow" entry — single CALL frame
	// to an address an attacker would never legitimately reach. If the
	// uncached path consults the cache, it would receive this and the
	// CallTargets slice would have len=1 with our poison address.
	const from, to, data, value = "0xsender", "0xcontract", "0x", ""
	poison := &TraceResult{CallTargets: []CallTarget{{Type: "CALL", From: "0xpoison", To: "0xpoison"}}}
	rt.cache.Set(from, to, data, value, "latest", poison)

	res, err := rt.TraceTransactionUncached(context.Background(), from, to, data, value, "latest")
	if err != nil {
		t.Fatalf("uncached call failed: %v", err)
	}
	if hits.Load() != 1 {
		t.Errorf("expected 1 upstream hit (cache must be bypassed), got %d", hits.Load())
	}
	if res == nil || len(res.CallTargets) != 1 || res.CallTargets[0].From == "0xpoison" {
		t.Errorf("uncached path returned cached/poison value: %+v", res)
	}
}

func TestTraceTransactionUncached_DoesNotPopulateCache(t *testing.T) {
	srv, _ := mockTraceServer(t)

	rt := NewRuntimeTracer(RuntimeTracerConfig{
		NodeURL:  srv.URL,
		Enabled:  true,
		CacheTTL: 30 * time.Second,
		Timeout:  2 * time.Second,
	})
	t.Cleanup(rt.Stop)

	const from, to, data, value = "0xsender", "0xcontract", "0x", ""
	if _, err := rt.TraceTransactionUncached(context.Background(), from, to, data, value, "latest"); err != nil {
		t.Fatalf("uncached call failed: %v", err)
	}
	if got := rt.cache.Size(); got != 0 {
		t.Errorf("uncached path must not populate cache, got size=%d", got)
	}
}
