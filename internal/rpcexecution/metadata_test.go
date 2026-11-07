package rpcexecution

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"privacy-proxy/internal/networkidentity"
)

type metadataTestRPC struct {
	ID     uint64            `json:"id"`
	Method string            `json:"method"`
	Params []json.RawMessage `json:"params"`
}

type metadataTestNode struct {
	mu      sync.Mutex
	calls   []metadataTestRPC
	peers   map[string]string
	genesis *types.Header
	chain   string
	results map[string]any
	change  func(http.ResponseWriter, *http.Request, metadataTestRPC) bool
}

func metadataFixture(t *testing.T) (*metadataTestNode, MetadataSource, Transport) {
	t.Helper()
	g := &types.Header{Number: big.NewInt(0), Difficulty: big.NewInt(0), GasLimit: 30000000, Time: 1, UncleHash: types.EmptyUncleHash, TxHash: types.EmptyTxsHash, ReceiptHash: types.EmptyReceiptsHash, Extra: []byte{}}
	n := &metadataTestNode{genesis: g, chain: "0x1", peers: map[string]string{}, results: map[string]any{
		"eth_accounts":    []string{"0x" + strings.Repeat("aB", 20), "0x" + strings.Repeat("aB", 20)},
		"eth_blockNumber": "0x1", "eth_gasPrice": "0x2", "eth_maxPriorityFeePerGas": "0x1", "eth_syncing": false,
		"net_listening": true, "net_peerCount": "0x0", "net_version": "42", "web3_clientVersion": "owned-test/1",
		"eth_feeHistory": metadataFeeFixture(2, 2),
	}}
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.Header.Get("Idempotency-Key") != "metadata-test-only" || r.Header.Get("Content-Type") != "application/json" {
			t.Error("owned request/credential changed")
			w.WriteHeader(400)
			return
		}
		raw, err := io.ReadAll(io.LimitReader(r.Body, (1<<20)+1))
		var request metadataTestRPC
		if err != nil || len(raw) > 1<<20 || json.Unmarshal(raw, &request) != nil {
			t.Error("invalid or unbounded outbound body")
			w.WriteHeader(400)
			return
		}
		n.mu.Lock()
		n.calls = append(n.calls, request)
		n.peers[request.Method] = r.RemoteAddr
		change, chain, genesis := n.change, n.chain, n.genesis
		result, exists := n.results[request.Method]
		n.mu.Unlock()
		if change != nil && change(w, r, request) {
			return
		}
		switch request.Method {
		case "eth_chainId":
			result = chain
		case "eth_getHeaderByNumber":
			if len(request.Params) != 1 || string(request.Params[0]) != `"0x0"` {
				t.Error("genesis selector changed")
			}
			result = genesis
		default:
			if !exists {
				t.Error("unclassified node method", request.Method)
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": request.ID, "result": result})
	}))
	t.Cleanup(s.Close)
	source := MetadataSource{Network: networkidentity.Binding{Environment: "test", ChainID: "1", GenesisHash: g.Hash().Hex(), DeploymentID: "metadata-test"}, URL: s.URL, CredentialRef: "owned", CredentialHeader: "Idempotency-Key"}
	transport := headerLaneTransportFunc(func(r *http.Request) (*http.Response, error) {
		if r.GetBody != nil {
			t.Error("metadata POST can transparently replay")
		}
		return s.Client().Transport.RoundTrip(r)
	})
	return n, source, transport
}

func metadataClient(t *testing.T, s MetadataSource, tr Transport, l MetadataLimits) *MetadataClient {
	t.Helper()
	c, err := NewMetadataClient(tr, s, Credential{s.CredentialHeader, "metadata-test-only"}, l)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func metadataQuery(t *testing.T, m MetadataMethod, params string) MetadataQuery {
	t.Helper()
	q, err := ParseMetadataQuery(m, []byte(params), DefaultMetadataLimits())
	if err != nil {
		t.Fatal(err)
	}
	return q
}

func metadataFeeFixture(blocks, percentiles int) map[string]any {
	fees, ratios := make([]string, blocks+1), make([]float64, blocks)
	rows := make([][]string, blocks)
	for i := range fees {
		fees[i] = "0x" + strings.Repeat("f", 64)
	}
	for i := range rows {
		rows[i] = make([]string, percentiles)
		for j := range rows[i] {
			rows[i][j] = fees[0]
		}
		ratios[i] = 0.5
	}
	return map[string]any{"oldestBlock": "0x0", "gasUsedRatio": ratios, "baseFeePerGas": fees, "baseFeePerBlobGas": fees, "blobGasUsedRatio": ratios, "reward": rows}
}

func TestMetadataMethodsOwnedTLSAndLocalHash(t *testing.T) {
	for method := MetadataAccounts; method <= MetadataKeccak; method++ {
		t.Run(method.String(), func(t *testing.T) {
			n, source, transport := metadataFixture(t)
			params := "[]"
			if method == MetadataFeeHistory {
				params = `[2,"latest",[0,100]]`
			}
			if method == MetadataKeccak {
				params = `["0x0102"]`
			}
			c := metadataClient(t, source, transport, DefaultMetadataLimits())
			q := metadataQuery(t, method, params)
			obs, err := c.Query(t.Context(), q)
			if err != nil || obs == nil || obs.Method() != method || obs.Source() != c.Source() {
				t.Fatal("metadata query failed", err)
			}
			expectedCalls := 3
			if method == MetadataChainID {
				expectedCalls = 2
			}
			if method == MetadataKeccak {
				expectedCalls = 0
				want, _ := json.Marshal("0x" + fmt.Sprintf("%x", crypto.Keccak256([]byte{1, 2})))
				if string(obs.ResultJSON()) != string(want) {
					t.Fatal("local hash mismatch")
				}
			}
			if len(n.calls) != expectedCalls {
				t.Fatal("wrong physical call count", len(n.calls), expectedCalls)
			}
			if method == MetadataAccounts && string(obs.ResultJSON()) != `["0x`+strings.Repeat("ab", 20)+`","0x`+strings.Repeat("ab", 20)+`"]` {
				t.Fatal("accounts were not normalized or duplicates/order lost")
			}
			out := obs.ResultJSON()
			out[0] = '!'
			if obs.ResultJSON()[0] == '!' {
				t.Fatal("result getter alias")
			}
			detached := c.Source()
			detached.Network.DeploymentID = "other"
			if c.Source().Network.DeploymentID != source.Network.DeploymentID {
				t.Fatal("source getter alias")
			}
			encoded, _ := json.Marshal(c.Source())
			if strings.Contains(string(encoded), "metadata-test-only") {
				t.Fatal("source getter exposed credential")
			}
		})
	}
}

func TestMetadataFullUint64Domains(t *testing.T) {
	n, s, tr := metadataFixture(t)
	n.mu.Lock()
	n.chain, s.Network.ChainID = "0xffffffffffffffff", "18446744073709551615"
	n.results["net_peerCount"] = "0xffffffffffffffff"
	n.mu.Unlock()
	c := metadataClient(t, s, tr, DefaultMetadataLimits())
	for _, m := range []MetadataMethod{MetadataChainID, MetadataPeerCount} {
		if _, err := c.Query(t.Context(), metadataQuery(t, m, "[]")); err != nil {
			t.Fatal("uint64 domain narrowed", m, err)
		}
	}
	n.mu.Lock()
	n.results["eth_blockNumber"] = "0x8000000000000000"
	n.mu.Unlock()
	if obs, err := c.Query(t.Context(), metadataQuery(t, MetadataBlockNumber, "[]")); err == nil || obs != nil {
		t.Fatal("height crossed signed63 support")
	}
}

func TestMetadataQueryBoundsBeforeAnyIO(t *testing.T) {
	_, s, _ := metadataFixture(t)
	panicWire := headerLaneTransportFunc(func(*http.Request) (*http.Response, error) { t.Fatal("unexpected node I/O"); return nil, nil })
	for _, edit := range []func(*MetadataLimits){
		func(l *MetadataLimits) { l.MaxParamsBytes = 4 },
		func(l *MetadataLimits) { l.MaxHistoryBlocks = 1 },
		func(l *MetadataLimits) { l.MaxPercentiles = 1 },
	} {
		l := DefaultMetadataLimits()
		edit(&l)
		c := metadataClient(t, s, panicWire, l)
		if obs, err := c.Query(t.Context(), metadataQuery(t, MetadataFeeHistory, `[2,"latest",[0,100]]`)); err == nil || obs != nil {
			t.Fatal("looser opaque query bypassed selected lower limits")
		}
	}
	c := metadataClient(t, s, panicWire, DefaultMetadataLimits())
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := c.Query(ctx, metadataQuery(t, MetadataAccounts, "[]")); err == nil {
		t.Fatal("canceled parent accepted")
	}
	if _, err := c.Query(t.Context(), MetadataQuery{}); err == nil {
		t.Fatal("zero query accepted")
	}
	// Local digest remains independent of any reachable node and owns its input.
	raw := []byte(`["0x"]`)
	q, _ := ParseMetadataQuery(MetadataKeccak, raw, DefaultMetadataLimits())
	raw[2] = 'z'
	if _, err := c.Query(t.Context(), q); err != nil {
		t.Fatal("local digest depended on node or caller bytes", err)
	}
	l := DefaultMetadataLimits()
	l.MaxResultBytes = 67
	if _, err := metadataClient(t, s, panicWire, l).Query(t.Context(), q); err == nil {
		t.Fatal("known local result bound ignored")
	}
}

func TestMetadataParameterShapes(t *testing.T) {
	bad := []struct {
		method MetadataMethod
		params string
	}{
		{InvalidMetadataMethod, `[]`}, {MetadataMethod(255), `[]`}, {MetadataAccounts, `[1]`}, {MetadataAccounts, `{}`},
		{MetadataFeeHistory, `[1]`}, {MetadataFeeHistory, `[1025,"latest"]`}, {MetadataFeeHistory, `[-1,"latest"]`},
		{MetadataFeeHistory, `[1,"latest",[1,1]]`}, {MetadataFeeHistory, `[1,"latest",[-1]]`}, {MetadataFeeHistory, `[1,"latest",[101]]`},
		{MetadataFeeHistory, `[1,"latest",[1e1000]]`}, {MetadataFeeHistory, `[1,{"blockHash":"0x01"}]`},
		{MetadataKeccak, `["0x0"]`}, {MetadataKeccak, `["xx00"]`}, {MetadataKeccak, `[1]`},
		{MetadataAccounts, `[] []`},
	}
	for _, x := range bad {
		if _, err := ParseMetadataQuery(x.method, []byte(x.params), DefaultMetadataLimits()); err == nil {
			t.Fatal("bad params accepted", x.method, x.params)
		}
	}
	for _, params := range []string{"", "null", "[]"} {
		if _, err := ParseMetadataQuery(MetadataAccounts, []byte(params), DefaultMetadataLimits()); err != nil {
			t.Fatal("no-arg compatibility lost", params, err)
		}
	}
	for _, count := range []string{"0", `"0x0"`, `"1024"`, `"0001"`} {
		if _, err := ParseMetadataQuery(MetadataFeeHistory, []byte(`[`+count+`,"earliest",null]`), DefaultMetadataLimits()); err != nil {
			t.Fatal("supported block-count shape rejected", count, err)
		}
	}
}

func TestMetadataLargestFeeAndCollectionLimits(t *testing.T) {
	n, s, tr := metadataFixture(t)
	points := make([]string, 100)
	for i := range points {
		points[i] = strconv.Itoa(i)
	}
	q := metadataQuery(t, MetadataFeeHistory, `[1024,"latest",[`+strings.Join(points, ",")+`]]`)
	fees := metadataFeeFixture(1024, 100)
	raw, _ := json.Marshal(fees)
	if len(raw) >= 8<<20 || len(raw) < 6<<20 {
		t.Fatal("largest logical fixture not meaningful", len(raw))
	}
	n.mu.Lock()
	n.results["eth_feeHistory"] = fees
	n.mu.Unlock()
	obs, err := metadataClient(t, s, tr, DefaultMetadataLimits()).Query(t.Context(), q)
	if err != nil || len(obs.ResultJSON()) != len(raw) {
		t.Fatal("full1024x100 shape failed declared work/wire budget", err)
	}
	for _, count := range []int{4096, 4097} {
		accounts := make([]string, count)
		for i := range accounts {
			accounts[i] = "0x" + strings.Repeat("ab", 20)
		}
		n.mu.Lock()
		n.results["eth_accounts"] = accounts
		n.mu.Unlock()
		_, err := metadataClient(t, s, tr, DefaultMetadataLimits()).Query(t.Context(), metadataQuery(t, MetadataAccounts, "[]"))
		if (err != nil) != (count == 4097) {
			t.Fatal("account bound", count, err)
		}
	}
	l := DefaultMetadataLimits()
	l.MaxResultBytes = 1024
	if _, err := metadataClient(t, s, tr, l).Query(t.Context(), q); err == nil {
		t.Fatal("selected result wire bound ignored")
	}
}

func TestMetadataResultFailuresAndNoData(t *testing.T) {
	for _, x := range []struct {
		method MetadataMethod
		raw    string
	}{
		{MetadataAccounts, `["not-address"]`}, {MetadataListening, `null`}, {MetadataListening, `{"value":true}`},
		{MetadataPeerCount, `"0x10000000000000000"`}, {MetadataGasPrice, `"0x01"`}, {MetadataGasPrice, `"0xA"`},
		{MetadataChainID, `"0x0"`},
		{MetadataSyncing, `true`}, {MetadataSyncing, `{"currentBlock":"0x0"}`},
		{MetadataSyncing, `{"startingBlock":"0x0","currentBlock":"0x0","highestBlock":"0x0","CurrentBlock":"0x1"}`},
		{MetadataNetworkVersion, `"0x1"`}, {MetadataClientVersion, `"bad\nversion"`},
		{MetadataFeeHistory, `{"oldestBlock":"0x0","gasUsedRatio":[2]}`},
		{MetadataFeeHistory, `{"oldestBlock":"0x0","gasUsedRatio":[0],"reward":[["0x1"]]}`},
		{MetadataFeeHistory, `{"oldestBlock":"0x0","gasUsedRatio":[],"unexpected":0}`},
	} {
		params := "[]"
		if x.method == MetadataFeeHistory {
			params = `[1,"latest",[0,100]]`
		}
		q := metadataQuery(t, x.method, params)
		if _, err := metadataResult(q, []byte(x.raw), DefaultMetadataLimits()); err == nil {
			t.Fatal("bad node shape accepted", x.method, x.raw)
		}
	}
	for _, x := range []struct{ params, result string }{
		{`[0,"latest"]`, `{"oldestBlock":"0x0","gasUsedRatio":null}`},
		{`[2,"latest"]`, `{"oldestBlock":"0x0","gasUsedRatio":[0],"reward":[]}`},
		{`[2,"latest",[0,100]]`, `{"oldestBlock":"0x0","gasUsedRatio":[0],"reward":[["0x1","0x2"]]}`},
	} {
		if _, err := metadataResult(metadataQuery(t, MetadataFeeHistory, x.params), []byte(x.result), DefaultMetadataLimits()); err != nil {
			t.Fatal("valid no-data/short/optional shape refused", err)
		}
	}
}

func TestMetadataNoReplayOnReusedTLS(t *testing.T) {
	for _, lost := range []bool{false, true} {
		t.Run(fmt.Sprint("lost=", lost), func(t *testing.T) {
			n, s, tr := metadataFixture(t)
			if lost {
				n.mu.Lock()
				n.change = func(w http.ResponseWriter, _ *http.Request, req metadataTestRPC) bool {
					if req.Method != "eth_gasPrice" {
						return false
					}
					conn, _, err := w.(http.Hijacker).Hijack()
					if err != nil {
						t.Error(err)
						return true
					}
					_ = conn.Close()
					return true
				}
				n.mu.Unlock()
			}
			obs, err := metadataClient(t, s, tr, DefaultMetadataLimits()).Query(t.Context(), metadataQuery(t, MetadataGasPrice, "[]"))
			n.mu.Lock()
			reused := n.peers["eth_gasPrice"] != "" && n.peers["eth_gasPrice"] == n.peers["eth_getHeaderByNumber"]
			calls := len(n.calls)
			n.mu.Unlock()
			if !reused || calls != 3 || (err != nil) != lost || (obs == nil) != lost {
				t.Fatal("lost response replayed/continued or success broke", reused, calls, err)
			}
		})
	}
}

func TestMetadataEarlierDeadlineStopsFollowingCalls(t *testing.T) {
	for _, body := range []bool{false, true} {
		t.Run(fmt.Sprint("body=", body), func(t *testing.T) {
			n, s, tr := metadataFixture(t)
			n.mu.Lock()
			n.change = func(w http.ResponseWriter, r *http.Request, req metadataTestRPC) bool {
				if req.Method != "eth_getHeaderByNumber" {
					return false
				}
				if body {
					_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":`)
					w.(http.Flusher).Flush()
				}
				<-r.Context().Done()
				return true
			}
			n.mu.Unlock()
			ctx, cancel := context.WithTimeout(t.Context(), 70*time.Millisecond)
			defer cancel()
			start := time.Now()
			if obs, err := metadataClient(t, s, tr, DefaultMetadataLimits()).Query(ctx, metadataQuery(t, MetadataAccounts, "[]")); err == nil || obs != nil || time.Since(start) > time.Second {
				t.Fatal("earlier deadline did not bound actual socket", err)
			}
			n.mu.Lock()
			count := len(n.calls)
			n.mu.Unlock()
			if count != 2 {
				t.Fatal("deadline continued into selected method", count)
			}
		})
	}
}
