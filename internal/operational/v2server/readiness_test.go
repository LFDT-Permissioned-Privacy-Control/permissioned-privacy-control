package v2server

import (
	"context"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/core/types"
	"privacy-proxy/internal/networkidentity"
	"privacy-proxy/internal/rpcexecution"
)

func TestReadinessBoundedSampleAndImmediateLocalFailure(t *testing.T) {
	var calls atomic.Int32
	var closed atomic.Bool
	p := newReadiness(func() error {
		if closed.Load() {
			return ErrInvalid
		}
		return nil
	}, []func(context.Context) error{func(ctx context.Context) error {
		calls.Add(1)
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) > 3*time.Second {
			t.Error("missing original probe deadline")
		}
		return nil
	}})
	for range 2 {
		if !p.check(t.Context()) {
			t.Fatal("healthy dependencies rejected")
		}
	}
	if calls.Load() != 1 {
		t.Fatal("sample was not bounded", calls.Load())
	}
	closed.Store(true)
	if p.check(t.Context()) {
		t.Fatal("cached success survived local shutdown")
	}
	closed.Store(false)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if p.check(ctx) {
		t.Fatal("cached success survived caller expiry")
	}
	p.mu.Lock()
	p.until = time.Time{}
	p.mu.Unlock()
	p.checks = []func(context.Context) error{func(context.Context) error { return errors.New("private dependency failure") }}
	w := httptest.NewRecorder()
	p.handler(w, httptest.NewRequest("GET", "/health/ready", nil))
	if w.Code != 503 || w.Body.Len() != 0 || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("readiness leaked details or accepted unavailable dependency", w.Code, w.Body.String())
	}
}

func TestReadinessDoesNotRequireSyncPermissionForCallOnlyCredential(t *testing.T) {
	genesis := &types.Header{Number: big.NewInt(0), Difficulty: big.NewInt(0), GasLimit: 30000000, TxHash: types.EmptyTxsHash, ReceiptHash: types.EmptyReceiptsHash, UncleHash: types.EmptyUncleHash, Time: 1000, BaseFee: big.NewInt(1)}
	var syncCalls atomic.Int32
	node := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var q struct {
			ID     json.RawMessage
			Method string
		}
		if json.NewDecoder(r.Body).Decode(&q) != nil {
			w.WriteHeader(400)
			return
		}
		if r.Header.Get("Authorization") != "Bearer owned-call-only" {
			t.Error("credential binding changed")
		}
		var value any
		switch q.Method {
		case "eth_chainId":
			value = "0x1"
		case "eth_getHeaderByNumber":
			value = genesis
		case "eth_syncing":
			syncCalls.Add(1)
			_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": q.ID, "error": map[string]any{"code": -32601, "message": "method not permitted"}})
			return
		default:
			t.Error("unexpected method", q.Method)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": q.ID, "result": value})
	}))
	defer node.Close()
	source := rpcexecution.MetadataSource{Network: networkidentity.Binding{Environment: "test", ChainID: "1", GenesisHash: genesis.Hash().Hex(), DeploymentID: "owned-readiness"}, URL: node.URL, CredentialRef: "CALL_ONLY", CredentialHeader: "Authorization"}
	client, err := rpcexecution.NewMetadataClient(node.Client().Transport, source, rpcexecution.Credential{Header: "Authorization", Value: "Bearer owned-call-only"}, rpcexecution.DefaultMetadataLimits())
	if err != nil {
		t.Fatal(err)
	}
	if err = nodeReady(client, false)(t.Context()); err != nil || syncCalls.Load() != 0 {
		t.Fatal("call-only binding was made to require sync permission", err)
	}
	if err = nodeReady(client, true)(t.Context()); err == nil || syncCalls.Load() != 1 {
		t.Fatal("required sync permission failure was ignored", err)
	}
}

func TestReadinessSingleProbeAndOriginalCancellation(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	p := newReadiness(func() error { return nil }, []func(context.Context) error{func(ctx context.Context) error {
		close(entered)
		select {
		case <-release:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}})
	done := make(chan bool, 1)
	go func() { done <- p.check(t.Context()) }()
	<-entered
	if p.check(t.Context()) {
		t.Fatal("second caller executed an overlapping probe")
	}
	close(release)
	if !<-done {
		t.Fatal("original probe failed")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	p = newReadiness(func() error { return nil }, []func(context.Context) error{func(ctx context.Context) error { <-ctx.Done(); return ctx.Err() }})
	if p.check(ctx) {
		t.Fatal("late success after cancellation")
	}
	if !p.until.IsZero() {
		t.Fatal("expired owner wrote a new sample")
	}
}

func TestReadinessCancellationDuringFinalGuardCannotCacheSuccess(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	var guards atomic.Int32
	p := newReadiness(func() error {
		if guards.Add(1) == 2 {
			cancel()
		}
		return nil
	}, []func(context.Context) error{func(context.Context) error { return nil }})
	if p.check(ctx) || !p.until.IsZero() {
		t.Fatal("final guard cancellation produced cached success")
	}
}

func TestReadinessHTTPClosedShape(t *testing.T) {
	p := newReadiness(func() error { return nil }, []func(context.Context) error{func(context.Context) error { return nil }})
	for _, test := range []struct {
		method, path string
		status       int
	}{{"GET", "/health/ready", 204}, {"HEAD", "/health/ready", 405}, {"POST", "/health/ready", 405}, {"GET", "/health/ready?details=1", 400}} {
		w := httptest.NewRecorder()
		p.handler(w, httptest.NewRequest(test.method, test.path, nil))
		if w.Code != test.status || w.Body.Len() != 0 {
			t.Fatal(test, w.Code, w.Body.String())
		}
	}
}
