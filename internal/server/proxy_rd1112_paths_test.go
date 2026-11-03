package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/google/uuid"

	"privacy-proxy/internal/audit"
	"privacy-proxy/internal/audit/buffer"
	"privacy-proxy/internal/config"
	"privacy-proxy/internal/db"
	"privacy-proxy/internal/nodehttp"
	"privacy-proxy/internal/nodepolicy"
	"privacy-proxy/internal/perfgate"
	"privacy-proxy/internal/proxy"
	"privacy-proxy/internal/rbac"
	"privacy-proxy/internal/server/middleware"
	"privacy-proxy/internal/tracer"
)

// RD-1112 processor-level harness for both execution paths (RD-1410). The
// legacy path forwards to the instant canned mock node
// (mockNode). The V2 path runs the production nodeExecutionBridge and strict
// nodepolicy client against the gate-2 mock private node in process, with
// facts kept current by the real publisher running in the background, as in
// the server.
//
// Workloads:
//   - historical (legacy only): the RD-1112 shape, one fixed nonce-0 transfer
//     per user re-sent round-robin, so results stay comparable with the
//     historical 4,997/s and 8,420 TPS;
//   - unique (both paths): unique pre-signed transfers, one key per user,
//     consecutive nonces, so a V2 submission is never a duplicate. The ≥ 95%
//     comparison is legacy-unique against v2-unique. Legacy processing
//     does not depend on uniqueness (decode, ecrecover, RBAC, tiered HasCode,
//     forward, system link of the same sender).
//
// The processor still reaches its mock nodes over loopback HTTP, so every
// harness counts the TCP connections the node clients open; a client that
// churns connections invalidates the run.

const (
	rd1112ChainID    = 31337
	rd1112Deployment = "rd1112-v2"
)

// rd1112Path names a processor configuration under test.
type rd1112Path string

const (
	rd1112Legacy rd1112Path = "legacy"
	rd1112V2     rd1112Path = "v2"
)

func parseRD1112Path(tb testing.TB, value string) rd1112Path {
	switch rd1112Path(value) {
	case "", rd1112Legacy:
		return rd1112Legacy
	case rd1112V2:
		return rd1112V2
	}
	tb.Fatalf("PROXY_LOADTEST_MODE must be legacy or v2, got %q", value)
	return ""
}

// parseRD1112Workload returns "historical" or "unique"; the default keeps the
// historical shape for legacy and is unique for V2.
func parseRD1112Workload(tb testing.TB, path rd1112Path, value string) string {
	switch {
	case value == "" && path == rd1112Legacy:
		return "historical"
	case value == "" || value == "unique":
		return "unique"
	case value == "historical" && path == rd1112Legacy:
		return "historical"
	}
	tb.Fatalf("PROXY_LOADTEST_WORKLOAD must be historical (legacy only) or unique, got %q for %s", value, path)
	return ""
}

// rd1112User is one permitted user with its own linked sending key.
type rd1112User struct {
	DID     string
	Key     *ecdsa.PrivateKey
	Address string
}

// rd1112Workload signs total unique transfers round-robin over users, so each
// user's nonces are consecutive in request order (request i < len(users) is
// that user's nonce 0, used for warm-up).
func (h *rd1112Harness) rd1112Workload(tb testing.TB, total int) []*ProcessRequest {
	tb.Helper()
	to := common.HexToAddress("0x1111111111111111111111111111111111111111")
	signer := types.NewEIP155Signer(big.NewInt(rd1112ChainID))
	out := make([]*ProcessRequest, total)
	for i := range out {
		user := h.Users[i%len(h.Users)]
		nonce := uint64(i / len(h.Users))
		signed, err := types.SignTx(types.NewTransaction(nonce, to, big.NewInt(1), 21000, big.NewInt(1_000_000_000), nil), signer, user.Key)
		if err != nil {
			tb.Fatal(err)
		}
		raw, err := signed.MarshalBinary()
		if err != nil {
			tb.Fatal(err)
		}
		if h.mock != nil {
			// Pre-index so the mock never recovers a signature on the hot path:
			// its CPU must not land on the V2 side only.
			h.mock.Index(strings.ToLower(signed.Hash().Hex()), user.Address, nonce)
		}
		rawHex := "0x" + hex.EncodeToString(raw)
		body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "method": "eth_sendRawTransaction", "params": []string{rawHex}, "id": 1})
		out[i] = &ProcessRequest{UserID: user.DID, Method: "eth_sendRawTransaction", Params: []any{rawHex}, Body: body, ClientIP: "127.0.0.1"}
	}
	return out
}

// requests returns the warm-up requests (one per user) and the measured ones
// for workload: total measured requests, unique or the historical repeats.
func (h *rd1112Harness) requests(tb testing.TB, workload string, total int) (warm, measured []*ProcessRequest) {
	tb.Helper()
	if workload == "historical" {
		warm = h.rd1112Workload(tb, len(h.Users))
		measured = make([]*ProcessRequest, total)
		for i := range measured {
			measured[i] = warm[i%len(warm)]
		}
		return warm, measured
	}
	all := h.rd1112Workload(tb, len(h.Users)+total)
	return all[:len(h.Users)], all[len(h.Users):]
}

// rd1112Harness is a processor for one path plus everything it started.
type rd1112Harness struct {
	Proc     *JSONRPCProcessor
	Users    []rd1112User
	Path     rd1112Path
	mock     *perfgate.MockNode
	conns    map[string]*connCounter // TCP connections per mock listener
	pool     map[string]int64        // the node clients' keep-alive pool sizes per listener
	cleanups []func()
}

func (h *rd1112Harness) Close() {
	for i := len(h.cleanups) - 1; i >= 0; i-- {
		h.cleanups[i]()
	}
}

// connCounter tracks the connections open at once on one listener.
type connCounter struct {
	mu             sync.Mutex
	open, peak     int64
	opened, closed int64
}

func (c *connCounter) state(_ net.Conn, state http.ConnState) {
	c.mu.Lock()
	defer c.mu.Unlock()
	switch state {
	case http.StateNew:
		c.opened++
		c.open++
		c.peak = max(c.peak, c.open)
	case http.StateClosed, http.StateHijacked:
		c.closed++
		c.open--
	}
}

// checkConnections fails the run when a node client held more connections
// open at once than its keep-alive pool allows: it churned, so loopback
// ports, not the processor, bounded the result. (Idle connections that
// expire and reopen during a long run are normal and stay within the peak.)
func (h *rd1112Harness) checkConnections(tb testing.TB) string {
	tb.Helper()
	var parts []string
	for listener, c := range h.conns {
		c.mu.Lock()
		peak, opened := c.peak, c.opened
		c.mu.Unlock()
		parts = append(parts, fmt.Sprintf("%s peak %d/%d (opened %d)", listener, peak, h.pool[listener], opened))
		if peak > h.pool[listener] {
			tb.Errorf("%s node client held %d connections to the %s mock at once, more than its pool of %d: it churned, the result is invalid", h.Path, peak, listener, h.pool[listener])
		}
	}
	return strings.Join(parts, ", ")
}

// countingServer starts an httptest server that tracks its connections.
func (h *rd1112Harness) countingServer(listener string, handler http.Handler, pool int64) *httptest.Server {
	counter := &connCounter{}
	server := httptest.NewUnstartedServer(handler)
	server.Config.ConnState = counter.state
	server.Start()
	h.cleanups = append(h.cleanups, server.Close)
	h.conns[listener], h.pool[listener] = counter, pool
	return server
}

// newRD1112Harness seeds users and builds the processor for path. The
// database must be migrated and reset by the caller.
func newRD1112Harness(tb testing.TB, database *db.DB, path rd1112Path, users int, async bool) *rd1112Harness {
	tb.Helper()
	ctx := context.Background()
	h := &rd1112Harness{Path: path, conns: map[string]*connCounter{}, pool: map[string]int64{}}
	for i := 0; i < users; i++ {
		key, err := crypto.GenerateKey()
		if err != nil {
			tb.Fatal(err)
		}
		user := rd1112User{DID: seedPermittedUser(tb, ctx, database), Key: key, Address: strings.ToLower(crypto.PubkeyToAddress(key.PublicKey).Hex())}
		if path == rd1112V2 {
			// V2 admission requires the sender to be linked to the principal.
			if err := database.SystemLinkEthAddress(ctx, user.DID, user.Address); err != nil {
				tb.Fatalf("link sender: %v", err)
			}
		}
		h.Users = append(h.Users, user)
	}

	// The proxy and the tracer each hold their own nodehttp pool to the node.
	idle := int64(nodehttp.DefaultTransportConfig().MaxIdleConnsPerHost)
	node := h.countingServer("public", mockNodeHandler(), 2*idle)
	rbacCtrl := rbac.NewAccessController(database, 5*time.Minute)
	h.cleanups = append(h.cleanups, rbacCtrl.Stop)
	rt := tracer.NewRuntimeTracer(tracer.RuntimeTracerConfig{NodeURL: node.URL, Enabled: true, TieredEnabled: true, Timeout: 5 * time.Second})
	h.cleanups = append(h.cleanups, rt.Stop)
	cfg := JSONRPCProcessorConfig{
		RBACAccessCtrl:     rbacCtrl,
		RateLimiter:        &noopRateLimiter{},
		Proxy:              proxy.New(node.URL),
		AccessLogger:       database,
		RuntimeTracer:      rt,
		TraceValidator:     rbac.NewTraceValidator(database),
		CircuitBreaker:     middleware.NewCircuitBreaker(),
		ConcurrencyLimiter: middleware.NewConcurrencyLimiter(50, 0),
	}
	if async {
		var dir string
		if t, ok := tb.(*testing.T); ok {
			dir = t.TempDir()
		} else {
			dir = tb.(*testing.B).TempDir()
		}
		buf, err := buffer.Open(dir)
		if err != nil {
			tb.Fatalf("buffer: %v", err)
		}
		h.cleanups = append(h.cleanups, func() { _ = buf.Close() })
		cfg.AuditBuffer = buf
	} else {
		seed, _ := database.GetLatestAccessLogHash(ctx)
		cfg.EnhancedAuditLogger = database
		cfg.HashChain = audit.NewHashChain(seed)
	}
	if path == rd1112V2 {
		cfg.NodeExecution = newRD1112NodeExecution(tb, database, h)
	}
	h.Proc = NewJSONRPCProcessor(cfg)
	return h
}

// newRD1112NodeExecution wires the production V2 bridge to the gate-2 mock
// private node and keeps the facts current with the real publisher.
func newRD1112NodeExecution(tb testing.TB, database *db.DB, h *rd1112Harness) NodeExecutionService {
	tb.Helper()
	token := "rd1112-private-token-0123456789"
	// No block production: the harness measures admission, and the mock's
	// pool accepts consecutive nonces in any arrival order.
	h.mock = perfgate.NewMockNode(perfgate.MockNodeConfig{ChainID: rd1112ChainID, DeploymentID: rd1112Deployment, PrivateToken: token, BlockTime: time.Second, FinalityLag: time.Second})
	network := nodepolicy.Network{ChainID: rd1112ChainID, DeploymentID: rd1112Deployment}
	lanes := nodepolicy.DefaultLanes()
	private := h.countingServer("private", h.mock.Private(), int64(lanes.Control+lanes.Transaction+lanes.Recovery))
	// The same constructor as initNodePolicy, at the default lanes.
	client, err := newNodePolicyClient(config.NodePolicyConfig{URL: private.URL, Token: token}, network)
	if err != nil {
		tb.Fatal(err)
	}
	signer := nodepolicy.Signer{KeyID: "rd1112", PrivateKey: ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))}
	// A fresh consumer per harness: ResetTestDatabase keeps the publication
	// cursors, and every harness has a fresh mock.
	bridge, err := newNodeExecutionBridge(database, client, signer, network, time.Minute, nil)
	if err != nil {
		tb.Fatal(err)
	}
	publisher, err := nodepolicy.NewPublisher(nodepolicy.PublisherConfig{Network: network, ConsumerID: "rd1112-" + uuid.NewString()[:8], Signer: signer, Source: database, Node: observingFactNode{node: client, bridge: bridge}, Lifetime: 30 * time.Second})
	if err != nil {
		tb.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	if err := publisher.Tick(ctx); err != nil {
		cancel()
		tb.Fatalf("publish facts: %v", err)
	}
	done := make(chan struct{})
	go func() { defer close(done); _ = publisher.Run(ctx, time.Second, nil) }()
	h.cleanups = append(h.cleanups, func() { cancel(); <-done })
	waitProbe := bridge.startStatusProbe(ctx, time.Second)
	h.cleanups = append(h.cleanups, func() { cancel(); waitProbe() })
	return bridge
}

// warm sends each request once and fails unless every one succeeds, so a
// measured run starts at steady state (permissions cached, links present).
func (h *rd1112Harness) warm(tb testing.TB, requests []*ProcessRequest) {
	tb.Helper()
	ctx := context.Background()
	for i, req := range requests {
		if res := h.Proc.Process(ctx, req); res.StatusCode != http.StatusOK {
			status, message := res.StatusCode, ""
			if res.Error != nil {
				status, message = res.Error.StatusCode, res.Error.Message
			}
			tb.Fatalf("%s warm-up request %d: status %d %q", h.Path, i, status, message)
		}
	}
}

// TestRD1112HarnessPathsAcceptTheSameWorkload proves both paths of the
// processor harness are wired and succeed on the shared unique workload with
// pooled node connections. It runs in the normal suite; the timed runs stay
// gated (PROXY_BENCH_DSN).
func TestRD1112HarnessPathsAcceptTheSameWorkload(t *testing.T) {
	database, err := db.New(sharedTestDBURL(t))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	for _, path := range []rd1112Path{rd1112Legacy, rd1112V2} {
		t.Run(string(path), func(t *testing.T) {
			if err := db.ResetTestDatabase(database); err != nil {
				t.Fatal(err)
			}
			h := newRD1112Harness(t, database, path, 3, true)
			defer h.Close()
			warm, measured := h.requests(t, "unique", 6)
			h.warm(t, warm)
			for i, req := range measured {
				res := h.Proc.Process(context.Background(), req)
				if res.StatusCode != http.StatusOK {
					t.Fatalf("request %d: %+v", i, res.Error)
				}
			}
			if path == rd1112V2 {
				var rows int
				if err := database.Conn().QueryRow(`SELECT count(*) FROM node_submissions`).Scan(&rows); err != nil || rows != 9 {
					t.Fatalf("node submissions %d %v, want one per unique transaction", rows, err)
				}
			}
			h.checkConnections(t)
		})
	}
}

// BenchmarkProxyTransferPaths is the closed-loop RD-1112 benchmark over both
// paths with the same unique workload and async audit, so the baseline and V2
// are compared the same way (historical reference: 8,420 TPS at concurrency 32,
// processor-only, Linux, historical workload — see
// BenchmarkProxyValueTransferAsyncAudit for that shape).
//
//	PROXY_BENCH_DSN=postgres://... go test -run '^$' -bench BenchmarkProxyTransferPaths -cpu 32 ./internal/server/
func BenchmarkProxyTransferPaths(b *testing.B) {
	dsn := proxyBenchDSN(b)
	for _, path := range []rd1112Path{rd1112Legacy, rd1112V2} {
		b.Run(string(path), func(b *testing.B) {
			database, err := db.New(dsn)
			if err != nil {
				b.Fatalf("db: %v", err)
			}
			defer database.Close()
			if err := db.ResetTestDatabase(database); err != nil {
				b.Fatalf("reset: %v", err)
			}
			h := newRD1112Harness(b, database, path, 100, true)
			defer h.Close()
			warm, requests := h.requests(b, "unique", b.N)
			h.warm(b, warm)
			var next atomic.Int64
			ctx := context.Background()
			b.ReportAllocs()
			b.ResetTimer()
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					req := requests[next.Add(1)-1]
					if res := h.Proc.Process(ctx, req); res.StatusCode != http.StatusOK {
						b.Errorf("%s: status %d %+v", path, res.StatusCode, res.Error)
						return
					}
				}
			})
			b.StopTimer()
			h.checkConnections(b)
		})
	}
}
