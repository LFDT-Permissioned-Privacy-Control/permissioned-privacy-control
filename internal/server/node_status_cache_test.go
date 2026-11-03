package server

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"privacy-proxy/internal/config"
	"privacy-proxy/internal/db"
	"privacy-proxy/internal/nodepolicy"
)

// countingStatusNode is an execution node whose status calls are counted and
// whose status can change under the test.
type countingStatusNode struct {
	mu     sync.Mutex
	status nodepolicy.NodeStatus
	err    error
	calls  atomic.Int64
}

func (n *countingStatusNode) set(status nodepolicy.NodeStatus, err error) {
	n.mu.Lock()
	n.status, n.err = status, err
	n.mu.Unlock()
}
func (n *countingStatusNode) PolicyStatus(context.Context) (nodepolicy.NodeStatus, error) {
	n.calls.Add(1)
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.status, n.err
}
func (n *countingStatusNode) SubmitTransaction(context.Context, []byte, string) (nodepolicy.Submission, error) {
	return nodepolicy.Submission{}, nodepolicy.ErrNodeUnavailable
}
func (n *countingStatusNode) Simulate(context.Context, []byte, []byte) (json.RawMessage, error) {
	return nil, nodepolicy.ErrNodeUnavailable
}

type movingVersion struct{ v atomic.Uint64 }

func (m *movingVersion) NodePolicyVersion(context.Context) (uint64, error) { return m.v.Load(), nil }

// G5 (RD-1410): preparing an identity reads the database fact
// version on every request but never calls the node: the node's status comes
// from a cache refreshed by the background probe and publication. A lagging
// or missing cache causes at most one bounded refresh, and a failing node
// fails requests closed without calling it again per request.
func TestPrepareIdentityMakesNoNodeCall(t *testing.T) {
	network := nodepolicy.Network{ChainID: 31337, DeploymentID: "cache-test"}
	ready := nodepolicy.NodeStatus{ProtocolVersion: 1, Network: network, Capabilities: nodepolicy.RequiredCapabilities(), Version: 7, Digest: strings.Repeat("a", 64), ExpiresAt: 10_000, Ready: true}
	var clock atomic.Int64
	clock.Store(time.Unix(1_000, 0).UnixNano())
	now := func() time.Time { return time.Unix(0, clock.Load()) }
	advance := func(d time.Duration) { clock.Add(int64(d)) }
	node := &countingStatusNode{status: ready}
	versions := &movingVersion{}
	versions.v.Store(7)
	bridge, err := newNodeExecutionBridge(versions, node, nodepolicy.Signer{KeyID: "ops-a", PrivateKey: ed25519.NewKeyFromSeed(make([]byte, 32))}, network, time.Minute, now)
	if err != nil {
		t.Fatal(err)
	}
	request := NodeExecutionIdentityRequest{Scope: "transaction", PrincipalID: "user-a", OrgID: "org-a", Signer: "0x" + strings.Repeat("11", 20), BindingHash: "0x" + strings.Repeat("22", 32)}
	ctx := context.Background()

	bridge.probeNodeStatus(ctx) // the background probe's tick
	primed := node.calls.Load()
	for i := 0; i < 100; i++ {
		if _, err := bridge.PrepareIdentity(ctx, request); err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
	}
	if extra := node.calls.Load() - primed; extra != 0 {
		t.Fatalf("100 identities made %d node status calls, want 0", extra)
	}

	// A revocation raises the database version; the node (without the
	// fact_wait_v1 wait) has not applied it. Requests refuse with
	// ErrFactsPending (503, Retry-After); each refusal rests on a status read
	// that started after its own version read, and those reads are shared and
	// spaced, never one per request in a burst.
	versions.v.Store(8)
	before := node.calls.Load()
	began := time.Now()
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := bridge.PrepareIdentity(ctx, request); !errors.Is(err, nodepolicy.ErrFactsPending) {
				t.Errorf("lagging node: %v, want ErrFactsPending", err)
			}
		}()
	}
	wg.Wait()
	refreshes := node.calls.Load() - before
	if bound := int64(time.Since(began)/nodeStatusRefreshSpacing) + 2; refreshes > bound || refreshes == 0 {
		t.Fatalf("50 concurrent lagging requests made %d status reads, want 1..%d (spaced, shared)", refreshes, bound)
	}
	// The node applies version 8: the next request reads it once and succeeds,
	// and steady state calls the node no more.
	ready8 := ready
	ready8.Version = 8
	node.set(ready8, nil)
	if _, err := bridge.PrepareIdentity(ctx, request); err != nil {
		t.Fatalf("after the node applied: %v", err)
	}
	steady := node.calls.Load()
	for i := 0; i < 100; i++ {
		if _, err := bridge.PrepareIdentity(ctx, request); err != nil {
			t.Fatal(err)
		}
	}
	if node.calls.Load() != steady {
		t.Fatal("steady state called the node")
	}

	// The node becomes unreachable: after the probe sees it, requests fail
	// closed, and a burst of them shares spaced reads instead of calling the
	// node once each.
	node.set(nodepolicy.NodeStatus{}, nodepolicy.ErrNodeUnavailable)
	bridge.probeNodeStatus(ctx)
	failing := node.calls.Load()
	began = time.Now()
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := bridge.PrepareIdentity(ctx, request); err == nil {
				t.Error("identity minted while the node is unavailable")
			}
		}()
	}
	wg.Wait()
	if calls, bound := node.calls.Load()-failing, int64(time.Since(began)/nodeStatusRefreshSpacing)+2; calls > bound {
		t.Fatalf("50 requests to an unavailable node made %d status reads, want <= %d", calls, bound)
	}

	// A status read is aged out: without a successful observation for longer
	// than the staleness bound, requests fail closed.
	node.set(ready8, nil)
	bridge.probeNodeStatus(ctx)
	advance(nodeStatusMaxAge + time.Second)
	node.set(nodepolicy.NodeStatus{}, nodepolicy.ErrNodeUnavailable)
	if _, err := bridge.PrepareIdentity(ctx, request); err == nil {
		t.Fatal("a stale cached status minted an identity")
	}
}

// An observation that started before a newer one never replaces it, so a slow
// probe cannot roll the cache back behind a fresher read.
func TestNodeStatusCacheKeepsTheNewestStartedObservation(t *testing.T) {
	var c nodeStatusCache
	old, fresh := c.begin(time.Unix(1, 0)), c.begin(time.Unix(2, 0))
	c.finish(fresh, nodepolicy.NodeStatus{Version: 8}, nil)
	c.finish(old, nodepolicy.NodeStatus{Version: 7}, nil)
	if got := c.load(); got == nil || got.status.Version != 8 {
		t.Fatalf("cache %+v, want the newest-started observation", got)
	}
}

// slogCapture counts log records by message.
type slogCapture struct {
	mu      sync.Mutex
	counts  map[string]int
	records []slog.Record
}

func (c *slogCapture) Enabled(context.Context, slog.Level) bool { return true }
func (c *slogCapture) Handle(_ context.Context, r slog.Record) error {
	c.mu.Lock()
	c.counts[r.Message]++
	c.records = append(c.records, r)
	c.mu.Unlock()
	return nil
}
func (c *slogCapture) WithAttrs([]slog.Attr) slog.Handler { return c }
func (c *slogCapture) WithGroup(string) slog.Handler      { return c }
func (c *slogCapture) count(message string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.counts[message]
}

func captureSlog(t *testing.T) *slogCapture {
	capture := &slogCapture{counts: map[string]int{}}
	previous := slog.Default()
	slog.SetDefault(slog.New(capture))
	t.Cleanup(func() { slog.SetDefault(previous) })
	return capture
}

type failingNodeExecution struct{ err error }

func (f failingNodeExecution) PrepareIdentity(context.Context, NodeExecutionIdentityRequest) ([]byte, error) {
	return nil, f.err
}
func (f failingNodeExecution) SubmitTransaction(context.Context, []byte, string, NodeSubmissionMetadata) (nodepolicy.Submission, error) {
	return nodepolicy.Submission{}, f.err
}
func (f failingNodeExecution) Simulate(context.Context, []byte, []byte) (json.RawMessage, error) {
	return nil, f.err
}

// G15 (RD-1410): a failing private node costs one warning
// line per interval and error class, not one per request (P0: 61k lines per
// minute). Every request is still answered and audited.
func TestNodeFailureLogsAreRateLimited(t *testing.T) {
	database, err := db.New(sharedTestDBURL(t))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if err := db.ResetTestDatabase(database); err != nil {
		t.Fatal(err)
	}
	h := newRD1112Harness(t, database, rd1112V2, 2, true)
	defer h.Close()
	_, requests := h.requests(t, "unique", 200)
	capture := captureSlog(t)
	h.Proc.nodeExecution = failingNodeExecution{err: nodepolicy.ErrNodeUnavailable}
	for i, req := range requests {
		res := h.Proc.Process(context.Background(), req)
		if res.Error == nil || res.Error.StatusCode != http.StatusServiceUnavailable {
			t.Fatalf("request %d: %+v, want 503", i, res)
		}
	}
	if lines := capture.count("private node execution failed"); lines != 1 {
		t.Fatalf("%d failure lines for 200 failed requests, want 1 per interval", lines)
	}

	// A failing tracking database (no request reaches the node) is logged the
	// same way.
	bridge, node, tracking := newBridgeFixture(t)
	tracking.runtime.Close()
	for i := 0; i < 100; i++ {
		if _, err := newSignedTransfer(t, 0).submit(t, bridge, uuid.NewString(), uuid.NewString()); err == nil {
			t.Fatal("submission accepted without a tracking database")
		}
	}
	if node.calls.Load() != 0 {
		t.Fatal("the node was called without a durable binding")
	}
	if lines := capture.count("execution-tracking admission batch failed"); lines != 1 {
		t.Fatalf("%d tracking failure lines for 100 failures, want 1 per interval", lines)
	}
}

// The config defaults and the client's default lanes are one set of numbers.
func TestNodePolicyLaneDefaultsAgree(t *testing.T) {
	control, transaction, recovery := config.NodePolicyConfig{}.LaneSizes()
	if lanes := nodepolicy.DefaultLanes(); lanes != (nodepolicy.Lanes{Control: control, Transaction: transaction, Recovery: recovery}) {
		t.Fatalf("config defaults %d/%d/%d, client defaults %+v", control, transaction, recovery, lanes)
	}
}
