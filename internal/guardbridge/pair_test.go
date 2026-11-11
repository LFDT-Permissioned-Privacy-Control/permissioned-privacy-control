package guardbridge

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
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
	"privacy-proxy/internal/nodeapproval"
	"privacy-proxy/internal/rpcexecution"
	"privacy-proxy/internal/transactioninput"
)

const org = "11111111-1111-1111-1111-111111111111"
const target = "0x1111111111111111111111111111111111111111"
const anchor = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func verified(t *testing.T, input []byte) transactioninput.VerifiedTransaction {
	t.Helper()
	key, _ := crypto.HexToECDSA(strings.Repeat("0", 63) + "1")
	to := common.HexToAddress(target)
	tx, err := types.SignTx(types.NewTransaction(9, to, big.NewInt(0), 100000, big.NewInt(1), input), types.LatestSignerForChainID(big.NewInt(1)), key)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := tx.MarshalBinary()
	v, err := transactioninput.DecodeRaw("0x"+hex.EncodeToString(raw), "1", transactioninput.ProtectedEVMProfile(), transactioninput.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	return v
}

type node struct {
	mu           sync.Mutex
	t            *testing.T
	tx           transactioninput.VerifiedTransaction
	headerFields string
	fullHeader   *types.Header
	storage      string
	methods      []string
	calls, pre   string
	delay        time.Duration
}

func (n *node) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if r.Header.Get("X-Key") != "selected" {
		n.t.Error("wrong credential", r.Header)
	}
	var q struct {
		ID     json.RawMessage
		Method string
		Params []json.RawMessage
	}
	if json.NewDecoder(r.Body).Decode(&q) != nil {
		n.t.Error("request")
		return
	}
	n.methods = append(n.methods, q.Method)
	if n.delay > 0 {
		select {
		case <-time.After(n.delay):
		case <-r.Context().Done():
			return
		}
	}
	var result string
	headerHash := anchor
	if n.fullHeader != nil {
		headerHash = n.fullHeader.Hash().Hex()
	}
	switch q.Method {
	case "eth_chainId":
		result = `"0x1"`
	case "eth_getHeaderByNumber":
		result = `{"hash":"` + anchor + `"` + n.headerFields + `}`
		if n.fullHeader != nil {
			b, _ := json.Marshal(n.fullHeader)
			result = string(b)
		}
	case "debug_traceCall":
		var opts map[string]any
		json.Unmarshal(q.Params[2], &opts)
		var block string
		json.Unmarshal(q.Params[1], &block)
		if block != headerHash {
			n.t.Error("unanchored trace")
		}
		if opts["tracer"] == "muxTracer" {
			result = `{"callTracer":` + n.calls + `,"prestateTracer":` + n.pre + `}`
		} else {
			result = `{"pre":{},"post":{}}`
		}
	case "eth_getCode":
		var b map[string]any
		json.Unmarshal(q.Params[1], &b)
		if b["blockHash"] != headerHash {
			n.t.Error("unanchored supplement")
		}
		result = `"0x6000"`
	default:
		n.t.Error("unexpected node method", q.Method)
		w.WriteHeader(400)
		return
	}
	fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":%s}`, q.ID, result)
}
func newNode(t *testing.T, tx transactioninput.VerifiedTransaction) *node {
	t.Helper()
	n := &node{t: t, tx: tx, headerFields: `,"number":"0x0","timestamp":"0xa"`}
	n.calls = fmt.Sprintf(`{ "type":"CALL", "from":"%s","to":"%s","value":"0x0","input":"0x%s","gas":"0x10000","gasUsed":"0x1","output":"0xcafe" }`, tx.Signer().Hex(), target, hex.EncodeToString(tx.Input()))
	n.pre = `{ "` + target + `": {"code":"0x6000","nonce":9007199254740995,"storage":{"0x` + strings.Repeat("00", 32) + `":"0x` + strings.Repeat("01", 32) + `"}} }`
	return n
}
func pair(t *testing.T, n *node, limits rpcexecution.Limits) *Pair {
	t.Helper()
	s := httptest.NewServer(n)
	t.Cleanup(s.Close)
	b := rpcexecution.NodeBinding{OrganizationID: org, URL: s.URL, ChainID: "1", Profile: rpcexecution.GuardRetainedProfileID, PragueStartInclusive: 0, PragueEndExclusive: 20, Credentials: map[string]rpcexecution.Credential{"key": {Header: "X-Key", Value: "selected"}, "other": {Header: "X-Key", Value: "other"}}}
	p, err := NewPair(b, "key", s.Client().Transport, nodeapproval.HashCalls, limits)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	b.Credentials["key"] = rpcexecution.Credential{Header: "X-Key", Value: "mutated"}
	return p
}

func TestPairUsesOriginalGuardSnapshotAndSealedServiceBinding(t *testing.T) {
	t.Setenv("OPS_APPROVAL_NODE", "besu")
	t.Setenv("OPS_APPROVAL_HASH_MODE", "untrusted-environment-value")
	tx := verified(t, []byte{1, 2})
	n := newNode(t, tx)
	p := pair(t, n, rpcexecution.DefaultLimits())
	q, err := p.AcquireSigned(t.Context(), tx)
	if err != nil {
		t.Fatal(err)
	}
	e := q.Execution()
	if p.Ready() || p.EnqueueQualified(q) == nil {
		t.Fatal("preflight-only pair gained delivery authority")
	}
	signer, ok := e.VerifiedSigner()
	hash, known := e.TransactionHash()
	if !e.Signed() || !ok || !known || signer != tx.Signer() || hash != tx.Hash() || e.Anchor().Profile != rpcexecution.GuardRetainedProfileID || e.HashMode() != nodeapproval.HashCalls {
		t.Fatal("lost signed provenance")
	}
	retained, ok := p.service.EvidenceFor(q.prepared)
	if !ok || string(retained.Calls()) != n.calls || string(retained.Prestate()) != n.pre || retained.HeaderNumber() != 0 {
		t.Fatal("original subtree/presence changed")
	}
	retained.Calls()[0] = '['
	retained.Prestate()[0] = '['
	if string(retained.Calls()) != n.calls {
		t.Fatal("borrowed evidence")
	}
	if len(n.methods) != 4 || n.methods[0] != "eth_chainId" || n.methods[1] != "eth_getHeaderByNumber" {
		t.Fatal("unexpected extra acquisition", n.methods)
	}
	other := pair(t, newNode(t, tx), rpcexecution.DefaultLimits())
	if _, err := other.qualify(t.Context(), q.prepared, tx); err == nil {
		t.Fatal("same-chain different service accepted")
	}
	copyPrepared := *q.prepared
	if _, err := p.qualify(t.Context(), &copyPrepared, tx); err == nil {
		t.Fatal("copied public Prepared substituted original")
	}
	if _, err := p.qualify(t.Context(), q.prepared, verified(t, []byte{9})); err == nil {
		t.Fatal("another signed transaction paired with evidence")
	}
	q.prepared.Approval.Fingerprint = common.Hash{}
	if _, err := p.qualify(t.Context(), q.prepared, tx); err == nil {
		t.Fatal("exported approval substitution accepted")
	}
	if _, err := p.qualify(t.Context(), &nodeapproval.Prepared{}, tx); err == nil {
		t.Fatal("public literal created evidence")
	}
}

func TestOptionalHeaderCompatibilityAndTotalDeadline(t *testing.T) {
	for _, fields := range []string{"", `,"number":null,"timestamp":"0xa"`, `,"number":false,"timestamp":"0xa"`, `,"number":"0x0","timestamp":"bad"`, `,"number":"0x0","number":"0x0","timestamp":"0xa"`, `,"number":"` + strings.Repeat("1", 100000) + `","timestamp":"0xa"`} {
		tx := verified(t, nil)
		n := newNode(t, tx)
		n.headerFields = fields
		p := pair(t, n, rpcexecution.DefaultLimits())
		prepared, err := p.service.Prepare(t.Context(), tx.RawHex())
		if err != nil {
			t.Fatal("legacy prepare changed on optional header", err)
		}
		if _, ok := prepared.Evidence(); ok {
			t.Fatal("unqualified optional header retained")
		}
		if _, err := p.qualify(t.Context(), prepared, tx); err == nil {
			t.Fatal("missing header qualified")
		}
	}
	tx := verified(t, nil)
	n := newNode(t, tx)
	n.delay = 25 * time.Millisecond
	l := rpcexecution.DefaultLimits()
	l.AcquisitionTimeout = 65 * time.Millisecond
	p := pair(t, n, l)
	start := time.Now()
	if _, err := p.AcquireSigned(context.Background(), tx); err == nil {
		t.Fatal("per-query deadlines extended total")
	}
	if time.Since(start) > 300*time.Millisecond {
		t.Fatal("total deadline ignored")
	}
}

func TestBoundPreflightRejectsRedirectsAndInvalidProfiles(t *testing.T) {
	var reached atomic.Bool
	other := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached.Store(true) }))
	defer other.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL, http.StatusTemporaryRedirect)
	}))
	defer redirect.Close()
	binding := rpcexecution.NodeBinding{OrganizationID: org, URL: redirect.URL, ChainID: "1", Profile: rpcexecution.GuardRetainedProfileID, PragueStartInclusive: 0, PragueEndExclusive: 20, AllowUnauthenticated: true}
	p, err := NewPair(binding, "", redirect.Client().Transport, nodeapproval.HashStrict, rpcexecution.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	if _, err := p.AcquireSigned(t.Context(), verified(t, nil)); err == nil || reached.Load() {
		t.Fatal("redirect followed")
	}
	binding.Profile = rpcexecution.NodeProfileID
	if _, err := NewPair(binding, "", redirect.Client().Transport, nodeapproval.HashCalls, rpcexecution.DefaultLimits()); err == nil {
		t.Fatal("call binding relabeled as Guard")
	}
}
