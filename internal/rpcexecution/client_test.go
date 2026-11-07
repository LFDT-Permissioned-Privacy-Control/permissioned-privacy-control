package rpcexecution

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
)

const testOrg = "11111111-1111-1111-1111-111111111111"
const testTarget = "0x1111111111111111111111111111111111111111"
const testHash = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func testCall(t *testing.T) Call {
	t.Helper()
	c, e := NormalizeCall([]byte(`{"to":"` + testTarget + `"}`))
	if e != nil {
		t.Fatal(e)
	}
	return c
}
func testBinding(url string) NodeBinding {
	return NodeBinding{OrganizationID: testOrg, URL: url, ChainID: "1", Profile: NodeProfileID, PragueStartInclusive: 10, PragueEndExclusive: 20, AllowUnauthenticated: true}
}
func rootTrace() map[string]any {
	return map[string]any{"type": "CALL", "from": common.Address{}.Hex(), "to": testTarget, "input": "0x", "value": "0x0", "gas": "0x10000", "gasUsed": "0x123", "output": "0xcafe"}
}

type nodeFixture struct {
	mu        sync.Mutex
	trace     map[string]any
	pre       map[string]any
	timestamp string
	code      string
	methods   []string
	anchors   []string
	badCode   bool
}

func baseNode() *nodeFixture {
	return &nodeFixture{trace: rootTrace(), pre: map[string]any{testTarget: map[string]any{"code": "0x6000"}}, timestamp: "0xa", code: "0x"}
}
func (n *nodeFixture) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	n.mu.Lock()
	defer n.mu.Unlock()
	var req struct {
		ID     json.RawMessage   `json:"id"`
		Method string            `json:"method"`
		Params []json.RawMessage `json:"params"`
	}
	if json.NewDecoder(r.Body).Decode(&req) != nil {
		w.WriteHeader(400)
		return
	}
	n.methods = append(n.methods, req.Method)
	var result any
	switch req.Method {
	case "eth_chainId":
		result = "0x1"
	case "eth_getBlockByNumber", "eth_getBlockByHash":
		result = map[string]any{"hash": testHash, "number": "0x1", "timestamp": n.timestamp}
	case "debug_traceCall":
		var anchor string
		json.Unmarshal(req.Params[1], &anchor)
		n.anchors = append(n.anchors, anchor)
		result = map[string]any{"callTracer": n.trace, "prestateTracer": n.pre}
	case "eth_getCode":
		var block map[string]any
		json.Unmarshal(req.Params[1], &block)
		n.anchors = append(n.anchors, block["blockHash"].(string))
		if n.badCode {
			json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": req.ID, "error": map[string]any{"code": -1, "message": "secret-node-detail"}})
			return
		}
		result = n.code
	default:
		w.WriteHeader(400)
		return
	}
	json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": result})
}
func acquire(t *testing.T, n *nodeFixture, l Limits) (*CallExecution, error) {
	t.Helper()
	server := httptest.NewServer(n)
	defer server.Close()
	c, e := NewClient(http.DefaultTransport, testBinding(server.URL), l)
	if e != nil {
		t.Fatal(e)
	}
	c, e = c.WithCredential("")
	if e != nil {
		t.Fatal(e)
	}
	b, e := ParseBlockSelector(nil)
	if e != nil {
		t.Fatal(e)
	}
	return c.AcquireCall(t.Context(), testCall(t), b)
}

func TestAcquisitionOwnsSameTraceAndAnchoredPresenceAwareCode(t *testing.T) {
	for _, present := range []bool{false, true} {
		n := baseNode()
		if present {
			n.pre[testTarget] = map[string]any{}
		} else {
			delete(n.pre, testTarget)
		}
		e, err := acquire(t, n, DefaultLimits())
		if err != nil {
			t.Fatal(err)
		}
		want := []string{"eth_chainId", "eth_getBlockByNumber", "debug_traceCall"}
		if !present {
			want = append(want, "eth_getCode")
		}
		if !reflect.DeepEqual(n.methods, want) {
			t.Fatalf("present=%v: %v", present, n.methods)
		}
		for _, hash := range n.anchors {
			if hash != testHash {
				t.Fatalf("unanchored read %s", hash)
			}
		}
		out, _ := e.Tree().Outcome()
		if !bytes.Equal(out.Output, []byte{0xca, 0xfe}) {
			t.Fatal("different execution output")
		}
		code, ok := e.Code(common.HexToAddress(testTarget))
		if !ok || code.HasCode() {
			t.Fatal("present empty code not retained")
		}
		raw := e.RawEvidence()
		raw[0] = 'x'
		if e.RawEvidence()[0] != '{' {
			t.Fatal("raw evidence escaped")
		}
		object := e.Call().Object()
		object["value"] = "0xff"
		if e.Call().Value().Sign() != 0 {
			t.Fatal("normalized call escaped")
		}
	}
	n := baseNode()
	delete(n.pre, testTarget)
	n.badCode = true
	if _, err := acquire(t, n, DefaultLimits()); err == nil || strings.Contains(err.Error(), "secret-node-detail") {
		t.Fatal("missing evidence granted/leaked", err)
	}
}

func TestAcquisitionRejectsUnqualifiedEvidenceAndForkBoundaries(t *testing.T) {
	for name, edit := range map[string]func(*nodeFixture){
		"before Prague":      func(n *nodeFixture) { n.timestamp = "0x9" },
		"at end":             func(n *nodeFixture) { n.timestamp = "0x14" },
		"after end":          func(n *nodeFixture) { n.timestamp = "0x15" },
		"root mismatch":      func(n *nodeFixture) { n.trace["input"] = "0x01" },
		"missing CALL value": func(n *nodeFixture) { delete(n.trace, "value") },
		"delegated ordinary target": func(n *nodeFixture) {
			n.pre[testTarget] = map[string]any{"code": "0xef01000000000000000000000000000000000000000001"}
		},
		"storage unexpectedly returned": func(n *nodeFixture) { n.pre[testTarget] = map[string]any{"storage": map[string]any{}} },
		"nonce coercion":                func(n *nodeFixture) { n.pre[testTarget] = map[string]any{"nonce": 1.5} },
		"oversized decimal nonce": func(n *nodeFixture) {
			n.pre[testTarget] = map[string]any{"nonce": json.Number(strings.Repeat("9", 100000))}
		},
		"nonce uint64 overflow": func(n *nodeFixture) { n.pre[testTarget] = map[string]any{"nonce": json.Number("18446744073709551616")} },
		"bad code hash":         func(n *nodeFixture) { n.pre[testTarget] = map[string]any{"code": "0x6000", "codeHash": testHash} },
		"caught unknown CREATE": func(n *nodeFixture) {
			n.trace["calls"] = []any{map[string]any{"type": "CREATE", "from": testTarget, "input": "0x6000", "value": "0x0", "gas": "0x100", "gasUsed": "0x100", "error": "execution reverted"}}
		},
		"SELFDESTRUCT": func(n *nodeFixture) {
			n.trace["calls"] = []any{map[string]any{"type": "SELFDESTRUCT", "from": testTarget, "to": common.Address{}.Hex(), "input": "0x", "value": "0x0", "gas": "0x0", "gasUsed": "0x0"}}
		},
	} {
		t.Run(name, func(t *testing.T) {
			n := baseNode()
			edit(n)
			if _, err := acquire(t, n, DefaultLimits()); err == nil {
				t.Fatal("unqualified evidence accepted")
			}
		})
	}
	for name, edit := range map[string]func(*Limits){
		"raw":        func(l *Limits) { l.MaxMuxBytes = 16 },
		"accounts":   func(l *Limits) { l.MaxPrestateAccounts = 1 },
		"code":       func(l *Limits) { l.MaxCodeBytesPerAccount = 1 },
		"total code": func(l *Limits) { l.MaxTotalCodeBytes = 1 },
	} {
		t.Run(name, func(t *testing.T) {
			n := baseNode()
			n.pre[common.Address{}.Hex()] = map[string]any{}
			l := DefaultLimits()
			edit(&l)
			if _, err := acquire(t, n, l); err == nil {
				t.Fatal("budget bypass")
			}
		})
	}
}

type transportFunc func(*http.Request) (*http.Response, error)

func (f transportFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func TestAcquisitionUsesOneDeadlineAndDetachedSelectedCredential(t *testing.T) {
	var deadlines []time.Time
	credentials := map[string]Credential{"allowed": {Header: "X-Key", Value: "original-secret"}}
	b := testBinding("http://trusted.invalid")
	b.AllowUnauthenticated = false
	b.Credentials = credentials
	transport := transportFunc(func(r *http.Request) (*http.Response, error) {
		deadline, ok := r.Context().Deadline()
		if !ok {
			t.Fatal("no deadline")
		}
		deadlines = append(deadlines, deadline)
		if r.Header.Get("X-Key") != "original-secret" {
			t.Fatal("credential binding changed")
		}
		var req struct {
			ID     uint64 `json:"id"`
			Method string `json:"method"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		if req.Method == "eth_chainId" {
			body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": "0x1"})
			return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(body))}, nil
		}
		<-r.Context().Done()
		return nil, r.Context().Err()
	})
	l := DefaultLimits()
	l.AcquisitionTimeout = 20 * time.Millisecond
	c, e := NewClient(transport, b, l)
	if e != nil {
		t.Fatal(e)
	}
	credentials["allowed"] = Credential{Header: "X-Key", Value: "changed"}
	if _, e = c.WithCredential(""); e == nil {
		t.Fatal("unauthenticated fallback")
	}
	if _, e = c.WithCredential("other"); e == nil {
		t.Fatal("unknown credential")
	}
	c, e = c.WithCredential("allowed")
	if e != nil {
		t.Fatal(e)
	}
	block, _ := ParseBlockSelector(nil)
	if _, e = c.AcquireCall(t.Context(), testCall(t), block); e == nil {
		t.Fatal("deadline ignored")
	}
	if len(deadlines) != 2 || !deadlines[0].Equal(deadlines[1]) {
		t.Fatal("deadline restarted", deadlines)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	before := len(deadlines)
	if _, e = c.AcquireCall(ctx, testCall(t), block); e == nil || len(deadlines) != before {
		t.Fatal("canceled request made node calls")
	}
	var typed *Error
	if !errors.As(e, &typed) {
		t.Fatal("untyped node failure", e)
	}
}

func TestAcquisitionSharesDeadlineAndBudgetAcrossCodeLookups(t *testing.T) {
	for _, budgetOnly := range []bool{false, true} {
		var deadlines []time.Time
		lookups := 0
		transport := transportFunc(func(r *http.Request) (*http.Response, error) {
			deadline, ok := r.Context().Deadline()
			if !ok {
				t.Fatal("missing acquisition deadline")
			}
			deadlines = append(deadlines, deadline)
			var req struct {
				ID     uint64            `json:"id"`
				Method string            `json:"method"`
				Params []json.RawMessage `json:"params"`
			}
			json.NewDecoder(r.Body).Decode(&req)
			var result any
			switch req.Method {
			case "eth_chainId":
				result = "0x1"
			case "eth_getBlockByNumber":
				result = map[string]any{"hash": testHash, "number": "0x1", "timestamp": "0xa"}
			case "debug_traceCall":
				root := rootTrace()
				root["calls"] = []any{map[string]any{"type": "CALL", "from": testTarget, "to": "0x2222222222222222222222222222222222222222", "input": "0x", "value": "0x0", "gas": "0x100", "gasUsed": "0x10"}}
				result = map[string]any{"callTracer": root, "prestateTracer": map[string]any{}}
			case "eth_getCode":
				lookups++
				var block map[string]any
				json.Unmarshal(req.Params[1], &block)
				if block["blockHash"] != testHash {
					t.Fatal("lookup moved anchor")
				}
				if lookups == 2 {
					<-r.Context().Done()
					return nil, r.Context().Err()
				}
				result = "0x6000"
			default:
				t.Fatal("unexpected node method", req.Method)
			}
			body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": result})
			return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(body))}, nil
		})
		limits := DefaultLimits()
		limits.AcquisitionTimeout = 50 * time.Millisecond
		if budgetOnly {
			limits.MaxAnchoredCodeLookups = 1
		}
		client, err := NewClient(transport, testBinding("http://trusted.invalid"), limits)
		if err != nil {
			t.Fatal(err)
		}
		client, _ = client.WithCredential("")
		block, _ := ParseBlockSelector(nil)
		_, err = client.AcquireCall(t.Context(), testCall(t), block)
		var typed *Error
		if !errors.As(err, &typed) {
			t.Fatal("missing typed acquisition failure", err)
		}
		if budgetOnly {
			if typed.Code != EvidenceLimit || lookups != 1 {
				t.Fatal("lookup budget bypass", typed.Code, lookups)
			}
		} else {
			if typed.Code != NodeFailure || lookups != 2 {
				t.Fatal("deadline failure not reached", typed.Code, lookups)
			}
		}
		for _, deadline := range deadlines {
			if !deadline.Equal(deadlines[0]) {
				t.Fatal("lookup restarted acquisition deadline")
			}
		}
	}
}

func TestPrestateNonceAcceptsExactUint64Boundary(t *testing.T) {
	n := baseNode()
	n.pre[testTarget] = map[string]any{"code": "0x6000", "nonce": json.Number("18446744073709551615")}
	if _, err := acquire(t, n, DefaultLimits()); err != nil {
		t.Fatal("valid uint64 nonce rejected", err)
	}
}
