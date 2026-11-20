package v2server

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math/big"
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
	"privacy-proxy/internal/creationfacts"
	"privacy-proxy/internal/networkidentity"
	"privacy-proxy/internal/rpcexecution"
	"privacy-proxy/internal/transactioninput"
)

type nodeRoundTripFunc func(*http.Request) (*http.Response, error)

func (f nodeRoundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type nodeTestClock struct{ nanos atomic.Int64 }

func (c *nodeTestClock) now() time.Time          { return time.Unix(1700000000, c.nanos.Load()) }
func (c *nodeTestClock) advance(d time.Duration) { c.nanos.Add(int64(d)) }

func nodeTestConfig(t *testing.T, endpoint string) Config {
	t.Helper()
	t.Setenv("TEST_NODE_A", "private-node-a")
	t.Setenv("TEST_NODE_A_ALIAS", "private-node-a")
	t.Setenv("TEST_NODE_B", "private-node-b")
	return Config{Data: Data{DefaultNode: Endpoint{URL: endpoint, Credential: &Credential{"TEST_NODE_A", "X-Node-Key"}}, Nodes: []Node{
		{URL: endpoint, AllowUnauthenticated: true, Credentials: []Credential{{"TEST_NODE_A", "X-Node-Key"}, {"TEST_NODE_A_ALIAS", "x-node-key"}, {"TEST_NODE_B", "X-Node-Key"}}},
		{URL: endpoint + "/other", Credentials: []Credential{{"TEST_NODE_A", "X-Node-Key"}}},
	}}, Protected: Protected{Nodes: []ProtectedNode{{Endpoint: Endpoint{URL: endpoint + "/protected", Credential: &Credential{"TEST_NODE_A", "X-Node-Key"}}}}}}
}

func nodeTestTransaction(t *testing.T) transactioninput.VerifiedTransaction {
	t.Helper()
	key, err := crypto.HexToECDSA(strings.Repeat("0", 63) + "1")
	if err != nil {
		t.Fatal(err)
	}
	to := common.HexToAddress("0x1111111111111111111111111111111111111111")
	tx, err := types.SignTx(types.NewTx(&types.DynamicFeeTx{ChainID: big.NewInt(1), Nonce: 9, To: &to, Gas: 100000, GasFeeCap: big.NewInt(31), GasTipCap: big.NewInt(2)}), types.LatestSignerForChainID(big.NewInt(1)), key)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := tx.MarshalBinary()
	verified, err := transactioninput.DecodeRaw("0x"+hex.EncodeToString(raw), "1", transactioninput.ProtectedEVMProfile(), transactioninput.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	return verified
}

func nodeTestRawClient(t *testing.T, transport http.RoundTripper, endpoint string) *rpcexecution.Client {
	t.Helper()
	c, err := rpcexecution.NewClient(transport, rpcexecution.NodeBinding{OrganizationID: "11111111-1111-4111-8111-111111111111", URL: endpoint, ChainID: "1", Profile: rpcexecution.SignedCallProfileID, PragueEndExclusive: 1000, AllowUnauthenticated: true, Credentials: map[string]rpcexecution.Credential{
		"A": {Header: "X-Node-Key", Value: "private-node-a"}, "alias": {Header: "x-node-key", Value: "private-node-a"}, "B": {Header: "X-Node-Key", Value: "private-node-b"},
	}}, rpcexecution.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func nodeFailure(t *testing.T, err error) {
	t.Helper()
	var typed *rpcexecution.Error
	if !errors.As(err, &typed) || typed.Code != rpcexecution.NodeFailure || strings.Contains(err.Error(), "private") {
		t.Fatal("expected safe typed node failure", err)
	}
}

type nodeTrackedBody struct {
	io.ReadCloser
	reads, closes *atomic.Int32
}

func (b nodeTrackedBody) Read(p []byte) (int, error) { b.reads.Add(1); return b.ReadCloser.Read(p) }
func (b nodeTrackedBody) Close() error               { b.closes.Add(1); return b.ReadCloser.Close() }

func TestNodeCooldownActualHTTPSelectedAliasesIsolationAndNoReplay(t *testing.T) {
	tx := nodeTestTransaction(t)
	var mu sync.Mutex
	calls := map[string]int{}
	var closed429, read429 atomic.Int32
	node := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := r.URL.Path + ":" + r.Header.Get("X-Node-Key")
		mu.Lock()
		calls[key]++
		n := calls[key]
		mu.Unlock()
		if r.URL.Path == "/" && n == 1 && r.Header.Get("X-Node-Key") != "private-node-b" {
			w.WriteHeader(429)
			_, _ = io.WriteString(w, "private provider detail and credential")
			return
		}
		var q struct {
			ID     json.RawMessage
			Method string
			Params []string
		}
		if json.NewDecoder(r.Body).Decode(&q) != nil || q.Method != "eth_sendRawTransaction" || len(q.Params) != 1 || q.Params[0] != tx.RawHex() {
			t.Error("signed request changed")
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": q.ID, "result": tx.Hash().Hex()})
	}))
	defer node.Close()
	base := node.Client().Transport.(*http.Transport)
	defer base.CloseIdleConnections()
	ctx, cancel := context.WithDeadline(t.Context(), time.Now().Add(3*time.Second))
	defer cancel()
	deadline, _ := ctx.Deadline()
	observed := nodeRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		actual, ok := r.Context().Deadline()
		if r.GetBody != nil || !ok || !actual.Equal(deadline) {
			t.Error("counted POST replay/deadline contract changed")
		}
		response, err := base.RoundTrip(r)
		if response != nil && response.StatusCode == 429 {
			response.Body = nodeTrackedBody{response.Body, &read429, &closed429}
		}
		return response, err
	})
	clock := &nodeTestClock{}
	transport, err := newNodeTransport(observed, nodeTestConfig(t, node.URL), clock.now)
	if err != nil {
		t.Fatal(err)
	}
	if len(transport.endpoints) != 3 || len(transport.endpoints[node.URL].states) != 3 {
		t.Fatal("registry aliases were not deduplicated")
	}
	client := nodeTestRawClient(t, transport, node.URL)
	broadcast := func(ref string, fail bool) {
		t.Helper()
		selected, err := client.WithCredential(ref)
		if err != nil {
			t.Fatal(err)
		}
		hash, err := selected.BroadcastRaw(ctx, tx)
		if fail {
			nodeFailure(t, err)
		} else if err != nil || hash != tx.Hash() {
			t.Fatal("valid broadcast failed", err)
		}
	}
	broadcast("A", true)     // one actual upstream429; acceptance remains unknown
	broadcast("alias", true) // same material, different config reference
	broadcast("A", true)     // no automatic retry, delay or request replay
	broadcast("B", false)    // same endpoint, distinct credential
	broadcast("", true)      // explicitly unauthenticated endpoint also trips
	broadcast("", true)
	broadcast("B", false) // the anonymous cooldown does not suppress a known key
	for _, suffix := range []string{"/other", "/protected"} {
		selected, err := nodeTestRawClient(t, transport, node.URL+suffix).WithCredential("A")
		if err != nil {
			t.Fatal(err)
		}
		if _, err = selected.BroadcastRaw(ctx, tx); err != nil {
			t.Fatal("independent configured endpoint suppressed", err)
		}
	}
	clock.advance(time.Second - time.Nanosecond)
	broadcast("A", true)
	clock.advance(time.Nanosecond)
	broadcast("A", false) // exact expiry permits a new caller attempt, not a retry
	mu.Lock()
	defer mu.Unlock()
	if calls["/:private-node-a"] != 2 || calls["/:private-node-b"] != 2 || calls["/:"] != 1 || len(calls) != 5 || read429.Load() != 0 || closed429.Load() != 2 {
		t.Fatal("unexpected node work or upstream-body handling", calls, read429.Load(), closed429.Load())
	}
}

func TestNodeCooldownCredentialHeaderIsPartOfFixedBinding(t *testing.T) {
	config := nodeTestConfig(t, "http://node.test/rpc")
	t.Setenv("TEST_NODE_SAME_VALUE_OTHER_HEADER", "private-node-a")
	config.Data.Nodes[0].Credentials = append(config.Data.Nodes[0].Credentials, Credential{"TEST_NODE_SAME_VALUE_OTHER_HEADER", "Authorization"})
	// Default, ordinary and protected reads with the same material share state.
	config.Protected.Nodes[0].Endpoint = config.Data.DefaultNode
	var calls atomic.Int32
	base := nodeRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls.Add(1)
		code := 200
		if r.Header.Get("X-Node-Key") != "" {
			code = 429
		}
		_ = r.Body.Close()
		return &http.Response{StatusCode: code, Body: io.NopCloser(strings.NewReader(""))}, nil
	})
	clock := &nodeTestClock{}
	transport, err := newNodeTransport(base, config, clock.now)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		header  string
		allowed bool
	}{{"X-Node-Key", false}, {"x-node-key", false}, {"Authorization", true}} {
		r, _ := http.NewRequestWithContext(t.Context(), "POST", config.Data.DefaultNode.URL, strings.NewReader(`{}`))
		r.Header.Set(tc.header, "private-node-a")
		response, err := transport.RoundTrip(r)
		if tc.allowed {
			if err != nil || response == nil || response.StatusCode != 200 {
				t.Fatal("different credential header suppressed", err)
			}
			response.Body.Close()
		} else if err == nil || response != nil {
			t.Fatal("same binding bypassed cooldown")
		}
	}
	if calls.Load() != 2 || len(transport.endpoints[config.Data.DefaultNode.URL].states) != 4 {
		t.Fatal("credential header or alias isolation changed", calls.Load())
	}
}

func TestNodeCooldownOnlyHTTP429Trips(t *testing.T) {
	for _, mode := range []string{"http503", "rpc-error429"} {
		t.Run(mode, func(t *testing.T) {
			tx := nodeTestTransaction(t)
			var calls atomic.Int32
			node := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var q struct{ ID json.RawMessage }
				if json.NewDecoder(r.Body).Decode(&q) != nil {
					t.Error("invalid owned request")
				}
				if calls.Add(1) == 1 {
					if mode == "http503" {
						w.WriteHeader(503)
					} else {
						_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": q.ID, "error": map[string]any{"code": 429, "message": "private RPC error"}})
					}
					return
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": q.ID, "result": tx.Hash().Hex()})
			}))
			defer node.Close()
			clock := &nodeTestClock{}
			transport, err := newNodeTransport(node.Client().Transport, Config{Data: Data{DefaultNode: Endpoint{URL: node.URL}}}, clock.now)
			if err != nil {
				t.Fatal(err)
			}
			selected, err := nodeTestRawClient(t, transport, node.URL).WithCredential("")
			if err != nil {
				t.Fatal(err)
			}
			_, err = selected.BroadcastRaw(t.Context(), tx)
			nodeFailure(t, err)
			if hash, err := selected.BroadcastRaw(t.Context(), tx); err != nil || hash != tx.Hash() || calls.Load() != 2 {
				t.Fatal("non429 incorrectly blocked a subsequent caller attempt", err, calls.Load())
			}
		})
	}
}

func TestNodeCooldownHistoryBatchMetadataStateAndReadinessShareBinding(t *testing.T) {
	genesis := &types.Header{Number: big.NewInt(0), Difficulty: big.NewInt(0), GasLimit: 30000000, TxHash: types.EmptyTxsHash, ReceiptHash: types.EmptyReceiptsHash, UncleHash: types.EmptyUncleHash, Time: 1000, BaseFee: big.NewInt(1)}
	var calls, batches atomic.Int32
	var throttle atomic.Bool
	throttle.Store(true)
	node := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		raw, _ := io.ReadAll(io.LimitReader(r.Body, 16384))
		if len(raw) > 0 && raw[0] == '[' {
			batches.Add(1)
		}
		if throttle.Load() {
			w.WriteHeader(429)
			return
		}
		var q struct {
			ID     json.RawMessage
			Method string
		}
		if json.Unmarshal(raw, &q) != nil {
			t.Error("unexpected batch after cooldown")
			w.WriteHeader(400)
			return
		}
		var result any
		switch q.Method {
		case "eth_chainId":
			result = "0x1"
		case "eth_getHeaderByNumber":
			result = genesis
		case "eth_syncing":
			result = false
		default:
			t.Error("unexpected readiness call", q.Method)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": q.ID, "result": result})
	}))
	defer node.Close()
	clock := &nodeTestClock{}
	transport, err := newNodeTransport(node.Client().Transport, nodeTestConfig(t, node.URL), clock.now)
	if err != nil {
		t.Fatal(err)
	}
	network := networkidentity.Binding{Environment: "test", ChainID: "1", GenesisHash: genesis.Hash().Hex(), DeploymentID: "node-cooldown"}
	credential := rpcexecution.Credential{Header: "X-Node-Key", Value: "private-node-a"}
	metadataSource := rpcexecution.MetadataSource{Network: network, URL: node.URL, CredentialRef: "A", CredentialHeader: credential.Header}
	metadata, err := rpcexecution.NewMetadataClient(transport, metadataSource, credential, rpcexecution.DefaultMetadataLimits())
	if err != nil {
		t.Fatal(err)
	}
	state, err := rpcexecution.NewStateClient(transport, metadataSource, credential, rpcexecution.DefaultStateLimits())
	if err != nil {
		t.Fatal(err)
	}
	networkKey, _ := network.Key()
	history, err := rpcexecution.NewHistoryReadClient(transport, creationfacts.Source{Network: creationfacts.Network{Key: creationfacts.Digest(networkKey), Environment: network.Environment, ChainID: "1", Genesis: genesis.Hash(), Deployment: network.DeploymentID}, URL: node.URL, CredentialRef: "A", CredentialHeader: credential.Header, Profile: "reth-prague-included-creations/v1", PragueEnd: 1000}, credential, rpcexecution.DefaultHistoryReadLimits())
	if err != nil {
		t.Fatal(err)
	}
	hq, err := rpcexecution.ParseHistoryReadQuery(rpcexecution.HistoryBlockByNumber, []byte(`["latest",false]`), history.Bounds())
	if err != nil {
		t.Fatal(err)
	}
	_, err = history.Acquire(t.Context(), hq)
	nodeFailure(t, err) // actual batch429 trips the same transport state
	mq, err := rpcexecution.ParseMetadataQuery(rpcexecution.MetadataChainID, []byte(`[]`), metadata.Bounds())
	if err != nil {
		t.Fatal(err)
	}
	_, err = metadata.Query(t.Context(), mq)
	nodeFailure(t, err)
	sq, err := rpcexecution.ParseStateQuery(rpcexecution.StateBalance, []byte(`["0x1111111111111111111111111111111111111111"]`), state.Bounds())
	if err != nil {
		t.Fatal(err)
	}
	_, err = state.Query(t.Context(), sq)
	nodeFailure(t, err)
	_, err = history.Acquire(t.Context(), hq)
	nodeFailure(t, err)
	readiness := newReadiness(func() error { return nil }, []func(context.Context) error{nodeReady(metadata, true)})
	w := httptest.NewRecorder()
	readiness.handler(w, httptest.NewRequest("GET", "/health/ready", nil))
	if w.Code != 503 || w.Body.Len() != 0 || calls.Load() != 1 || batches.Load() != 1 {
		t.Fatal("readiness bypassed shared cooldown or exposed provider details", w.Code, calls.Load(), batches.Load())
	}
	observer := newObservedNode(nodeReady(metadata, true), time.Now)
	diagnostics := newDiagnosticsSampler(readiness, map[string][]*observedNode{"owned-org": {observer}})
	for range 2 {
		sample := diagnostics.sample(t.Context(), "owned-org")
		if sample.Node.State != "unavailable" || calls.Load() != 1 || batches.Load() != 1 {
			t.Fatal("diagnostics bypassed shared cooldown or its bounded sample cache", sample, calls.Load(), batches.Load())
		}
	}
	clock.advance(time.Second)
	throttle.Store(false)
	readiness.mu.Lock()
	readiness.until = time.Time{} // explicitly expire only the independent sampled-health cache
	readiness.mu.Unlock()
	w = httptest.NewRecorder()
	readiness.handler(w, httptest.NewRequest("GET", "/health/ready", nil))
	if w.Code != 204 || calls.Load() != 4 {
		t.Fatal("readiness did not recover after cooldown", w.Code, calls.Load())
	}
}

func TestNodeCooldownLateSuccessCannotResetNewerTripAndConcurrentRejects(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	releaseHeld := func() { releaseOnce.Do(func() { close(release) }) }
	var calls atomic.Int32
	node := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			close(entered)
			<-release
			w.WriteHeader(200)
			return
		}
		w.WriteHeader(429)
	}))
	defer node.Close()
	defer releaseHeld()
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	clock := &nodeTestClock{}
	transport, err := newNodeTransport(node.Client().Transport, Config{Data: Data{DefaultNode: Endpoint{URL: node.URL}}}, clock.now)
	if err != nil {
		t.Fatal(err)
	}
	request := func() (*http.Response, error) {
		r, _ := http.NewRequestWithContext(ctx, "POST", node.URL, strings.NewReader(`{}`))
		r.GetBody = nil
		return transport.RoundTrip(r)
	}
	done := make(chan error, 1)
	go func() {
		response, err := request()
		if response != nil {
			response.Body.Close()
		}
		done <- err
	}()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("first request did not reach owned node")
	}
	if response, err := request(); err == nil || response != nil {
		t.Fatal("429 not suppressed")
	}
	releaseHeld()
	if err := <-done; err != nil {
		t.Fatal("original success rewritten", err)
	}
	var wg sync.WaitGroup
	for range 64 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if response, err := request(); err == nil || response != nil {
				t.Error("late200 reset trip")
			}
		}()
	}
	wg.Wait()
	if calls.Load() != 2 || len(transport.endpoints) != 1 || len(transport.endpoints[node.URL].states) != 1 {
		t.Fatal("cooldown created work or dynamic entries", calls.Load())
	}
}

func TestNodeCooldownUnknownBindingsCancellationAndBaseOwnership(t *testing.T) {
	var calls atomic.Int32
	base := nodeRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls.Add(1)
		return nil, errors.New("owned test failure")
	})
	clock := &nodeTestClock{}
	config := nodeTestConfig(t, "http://node.test/rpc")
	transport, err := newNodeTransport(base, config, clock.now)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		endpoint string
		header   http.Header
	}{
		{"http://foreign.test/rpc", nil}, {"http://node.test/rpc?different=1", nil},
		{"http://node.test/rpc", http.Header{"X-Node-Key": {"unconfigured-secret"}}},
		{"http://node.test/rpc", http.Header{"X-Node-Key": {"private-node-a", "private-node-b"}}},
		{"http://node.test/rpc", http.Header{"Authorization": {"unconfigured-secret"}}},
		{"http://node.test/rpc", http.Header{"X-Node-Key": {"private-node-a"}, "Authorization": {"foreign"}}},
	} {
		var reads, closes atomic.Int32
		r, _ := http.NewRequestWithContext(t.Context(), "POST", tc.endpoint, nil)
		r.Header = tc.header
		r.Body = nodeTrackedBody{io.NopCloser(strings.NewReader("private request")), &reads, &closes}
		if response, err := transport.RoundTrip(r); err == nil || response != nil || strings.Contains(err.Error(), "secret") {
			t.Fatal("unknown binding accepted or leaked")
		}
		if reads.Load() != 0 || closes.Load() != 1 {
			t.Fatal("rejected request body read or left open", reads.Load(), closes.Load())
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	r, _ := http.NewRequestWithContext(ctx, "POST", "http://node.test/rpc", nil)
	if response, err := transport.RoundTrip(r); err == nil || response != nil {
		t.Fatal("expired owner reached node")
	}
	if response, err := transport.RoundTrip(nil); err == nil || response != nil {
		t.Fatal("nil request accepted")
	}
	if calls.Load() != 0 || len(transport.endpoints) != 3 || len(transport.endpoints["http://node.test/rpc"].states) != 3 {
		t.Fatal("rejections reached base or grew registry")
	}
	if _, err = newNodeTransport(nil, config, clock.now); err == nil {
		t.Fatal("nil transport accepted")
	}
	if _, err = newNodeTransport(base, config, nil); err == nil {
		t.Fatal("nil clock accepted")
	}
	t.Setenv("TEST_NODE_A", "")
	if _, err = newNodeTransport(base, config, clock.now); err == nil {
		t.Fatal("missing configured credential accepted")
	}
	// The wrapper does not close the shared pool: the composition root's existing
	// baseTransport.CloseIdleConnections callback remains its sole close owner.
	if _, ok := any(transport).(interface{ CloseIdleConnections() }); ok {
		t.Fatal("wrapper acquired duplicate close ownership")
	}
}
