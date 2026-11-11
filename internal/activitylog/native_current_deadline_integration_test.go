package activitylog_test

import (
	"context"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"privacy-proxy/internal/networkidentity"
	"privacy-proxy/internal/operational/rpcactivity"
	"privacy-proxy/internal/rpcengine"
)

func TestNativeCurrentOriginalDeadlineThroughActualAppend(t *testing.T) {
	d := rawPostgres(t)
	if _, err := d.owner.Exec(t.Context(), `CREATE ROLE raw_observer LOGIN PASSWORD 'raw-test-only';CREATE ROLE raw_facts LOGIN PASSWORD 'raw-test-only'`); err != nil {
		t.Fatal(err)
	}
	var clock atomic.Int64
	clock.Store(now)
	f := metadataFixture()
	f.clock = &clock
	n := &node{}
	engine, token, financial, _ := mountedRawEngine(t, f, n, d, false, creationMountOptions{configure: func(o *rpcengine.RawOptions) {
		o.CurrentAddressLimits = rpcengine.DefaultNativeAddressLimits()
		o.CurrentAddressLimits.Timeout = 200 * time.Millisecond
	}})
	body := `{"jsonrpc":"2.0","id":1,"method":"eth_call","params":[{"to":"` + addressA + `","data":"0x0102"}]}`
	// Canceled acquisition child must NOT become the retained result fence.
	t.Run("prompt-observed-original-parent-positive", func(t *testing.T) {
		r := engine.CallObserved(context.Background(), token, orgA, []byte(body))
		m, err := r.MetadataFor(engine)
		if err != nil || m.Class != rpcengine.SuccessfulCompletion || r.RequireDeliverable(context.Background(), engine) != nil {
			t.Fatal("prompt result retained canceled acquisition child", m, err)
		}
	})
	t.Run("fresh-delivery-context-cannot-revive-canceled-parent", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		r := engine.CallObserved(ctx, token, orgA, []byte(body))
		cancel()
		if r.RequireDeliverable(context.Background(), engine) == nil {
			t.Fatal("fresh delivery caller revived original parent")
		}
	})
	t.Run("background-direct-whole-bound", func(t *testing.T) {
		n.mu.Lock()
		n.onTrace = func() { time.Sleep(300 * time.Millisecond) }
		n.mu.Unlock()
		start := time.Now()
		out := engine.Call(context.Background(), token, orgA, []byte(body))
		if out.Result != nil || out.Error == nil || out.Error.Code != -32002 || time.Since(start) > time.Second {
			t.Fatal("direct Background lacked original bounded deadline", out, time.Since(start))
		}
		n.mu.Lock()
		n.onTrace = nil
		n.mu.Unlock()
	})
	t.Run("short-parent-beats-operation-limit", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
		defer cancel()
		r := engine.CallObserved(ctx, token, orgA, []byte(body))
		n.mu.Lock()
		n.onChain = func() { time.Sleep(150 * time.Millisecond) }
		n.mu.Unlock()
		start := time.Now()
		if r.RequireDeliverable(context.Background(), engine) == nil || time.Since(start) > 140*time.Millisecond {
			t.Fatal("original shorter parent was replaced", time.Since(start))
		}
		n.mu.Lock()
		n.onChain = nil
		n.mu.Unlock()
	})
	net := financial.Metadata().Network
	network := networkidentity.Binding{Environment: net.Environment, ChainID: net.ChainID, GenesisHash: net.GenesisHash, DeploymentID: net.DeploymentID}
	x := setupActivityDatabase(t, network)
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	t.Cleanup(func() { once.Do(func() { close(release) }) })
	recorder := rpcRecorder(t, x, func() time.Time { return time.Unix(clock.Load(), 0) }, func(uint64) error { close(entered); <-release; return nil })
	service, err := rpcactivity.New(rpcactivity.Config{Engine: engine, Recorder: recorder, Network: network})
	if err != nil {
		t.Fatal(err)
	}
	handler, _ := service.Handler(orgA)
	front := httptest.NewTLSServer(handler)
	defer front.Close()
	before := metadataRows(t, x)
	done := requestAsync(t, front.Client(), front.URL, token, body, t.Context())
	await(t, entered)
	// The append is deliberately uncancellable. Credit must remain held even
	// after the original N1 library deadline expires under the HTTP20s fence.
	time.Sleep(250 * time.Millisecond)
	busyWire := bodyResult(t, requestAsync(t, front.Client(), front.URL, token, body, t.Context()))
	if strings.Contains(string(busyWire), "0xfeed") {
		t.Fatal("replacement admitted while actual Append held")
	}
	once.Do(func() { close(release) })
	wire := bodyResult(t, done)
	if strings.Contains(string(wire), "0xfeed") {
		t.Fatal("elapsed Append restarted original deadline", string(wire))
	}
	requireMetadataCode(t, wire, -32002)
	if selected := metadataSealedOne(t, x, before); selected.Outcome != "success" {
		t.Fatal("deadline rewrote selected completion", selected)
	}
}
