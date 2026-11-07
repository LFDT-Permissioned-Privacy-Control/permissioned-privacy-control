package privado

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common/hexutil"
	stateabi "github.com/iden3/contracts-abi/state/go/abi"
)

type rpcFixture struct {
	server                     *httptest.Server
	hits, chains, calls, codes atomic.Int64
	mode                       atomic.Int64
	expectCredential           atomic.Bool
	credentialChecks           atomic.Int64
	emptyAt                    atomic.Int64
	started                    chan struct{}
}

func newRPCFixture(t *testing.T) *rpcFixture {
	t.Helper()
	f := &rpcFixture{started: make(chan struct{}, 8)}
	f.server = httptest.NewTLSServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.server.Close)
	return f
}
func (f *rpcFixture) serve(w http.ResponseWriter, r *http.Request) {
	f.hits.Add(1)
	if f.expectCredential.Load() {
		if r.Header.Get("Authorization") != "Bearer public-fixture-only" {
			w.WriteHeader(401)
			return
		}
		f.credentialChecks.Add(1)
	}
	w.Header().Set("Content-Type", "application/json")
	var req struct {
		ID     json.Number       `json:"id"`
		Method string            `json:"method"`
		Params []json.RawMessage `json:"params"`
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10))
	decoder.UseNumber()
	if decoder.Decode(&req) != nil {
		w.WriteHeader(400)
		return
	}
	if f.mode.Load() == 6 {
		_, _ = io.WriteString(w, strings.Repeat(" ", 64<<10)+"{}")
		return
	}
	if f.mode.Load() == 7 {
		w.Header().Set("Location", f.server.URL+"/must-not-follow")
		w.WriteHeader(302)
		return
	}
	if f.mode.Load() == 8 {
		select {
		case f.started <- struct{}{}:
		default:
		}
		<-r.Context().Done()
		return
	}
	var result string
	switch req.Method {
	case "eth_chainId":
		f.chains.Add(1)
		result = "0x13881"
		if f.mode.Load() == 4 {
			result = "0x1"
		}
	case "eth_getCode":
		f.codes.Add(1)
		result = "0x01"
	case "eth_call":
		callN := f.calls.Add(1)
		if mode := f.mode.Load(); mode >= 11 && mode <= 13 {
			message := map[int64]string{11: "owned fixture capacity failure", 12: "execution reverted: StateDoesNotExist", 13: "execution reverted: RootDoesNotExist"}[mode]
			_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": req.ID, "error": map[string]any{"code": -32005, "message": message}})
			return
		}
		if f.mode.Load() == 14 {
			result = "0x01" // well-formed hex, invalid generated ABI return data
			break
		}
		if f.mode.Load() == 5 || f.emptyAt.Load() > 0 && f.emptyAt.Load() == callN {
			result = "0x"
			break
		}
		var call struct {
			Input string `json:"input"`
		}
		if len(req.Params) != 2 || json.Unmarshal(req.Params[0], &call) != nil {
			w.WriteHeader(400)
			return
		}
		data, err := hex.DecodeString(strings.TrimPrefix(call.Input, "0x"))
		if err != nil {
			w.WriteHeader(400)
			return
		}
		abi, _ := stateabi.StateMetaData.GetAbi()
		method, err := abi.MethodById(data[:4])
		if err != nil {
			w.WriteHeader(400)
			return
		}
		args, err := method.Inputs.Unpack(data[4:])
		if err != nil {
			w.WriteHeader(400)
			return
		}
		var output []byte
		if method.Name == "getGISTRootInfo" {
			root := new(big.Int).Set(args[0].(*big.Int))
			if f.mode.Load() == 9 {
				root.Add(root, big.NewInt(1))
			}
			row := stateabi.IStateGistRootInfo{Root: root, ReplacedByRoot: big.NewInt(0), CreatedAtTimestamp: big.NewInt(1), ReplacedAtTimestamp: big.NewInt(0), CreatedAtBlock: big.NewInt(1), ReplacedAtBlock: big.NewInt(0)}
			if f.mode.Load() == 1 {
				row.ReplacedByRoot = big.NewInt(777)
				row.ReplacedAtTimestamp = big.NewInt(time.Now().Unix() + 100)
			}
			output, err = method.Outputs.Pack(row)
		} else {
			id, s := args[0].(*big.Int), args[1].(*big.Int)
			row := stateabi.IStateStateInfo{Id: id, State: s, ReplacedByState: big.NewInt(0), CreatedAtTimestamp: big.NewInt(1), ReplacedAtTimestamp: big.NewInt(0), CreatedAtBlock: big.NewInt(1), ReplacedAtBlock: big.NewInt(0)}
			if s.Int64() == 100 || f.mode.Load() == 2 {
				row.ReplacedByState = big.NewInt(999)
				row.ReplacedAtTimestamp = big.NewInt(time.Now().Unix() + 100)
			}
			if f.mode.Load() == 10 {
				row.Id = big.NewInt(0)
			}
			output, err = method.Outputs.Pack(row)
		}
		if err != nil {
			w.WriteHeader(500)
			return
		}
		result = hexutil.Encode(output)
	default:
		w.WriteHeader(400)
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": result})
}
func (f *rpcFixture) provider(t *testing.T) *Provider {
	t.Helper()
	return fixtureProvider(t, func(o *Options) { o.Networks[0].URL = f.server.URL; o.Transport = f.server.Client().Transport })
}

func (f *rpcFixture) logicalProvider(t *testing.T, clock func() time.Time) *Provider {
	t.Helper()
	destination, err := url.Parse(f.server.URL)
	if err != nil {
		t.Fatal(err)
	}
	return fixtureProvider(t, func(o *Options) {
		if clock != nil {
			o.Clock = clock
		}
		// Explicit owned-test mapping. Metadata keeps the same logical approved
		// endpoint across the native-proving and disabled-prover processes.
		o.Transport = roundTripper(func(request *http.Request) (*http.Response, error) {
			if request.URL.String() != "https://state.test/rpc" {
				return nil, ErrProvider
			}
			copy := request.Clone(request.Context())
			u := *request.URL
			copy.URL = &u
			copy.URL.Scheme = destination.Scheme
			copy.URL.Host = destination.Host
			copy.Host = request.URL.Host
			return f.server.Client().Transport.RoundTrip(copy)
		})
	})
}
func stateAttempt(ctx context.Context, p *Provider, network string, id *big.Int) *attempt {
	return newAttempt(ctx, p, parsed{holderNetwork: network, gist: "1234", roles: map[stateKey]bool{{network, id.String(), "100"}: false, {network, id.String(), "200"}: true}})
}

func TestCountedRPCPostIsNotTransparentlyReplayed(t *testing.T) {
	f := &rpcFixture{started: make(chan struct{}, 8)}
	var receivedCalls atomic.Int64
	f.server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 16<<10))
		if err != nil {
			w.WriteHeader(400)
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(raw))
		var request struct {
			Method string `json:"method"`
		}
		if json.Unmarshal(raw, &request) != nil {
			w.WriteHeader(400)
			return
		}
		if request.Method == "eth_call" {
			if r.Header.Get("Idempotency-Key") != "public-test-material" {
				t.Error("test credential did not reach the peer")
			}
			if receivedCalls.Add(1) == 1 {
				conn, _, err := w.(http.Hijacker).Hijack()
				if err != nil {
					t.Error(err)
					return
				}
				_ = conn.Close() // complete body received on the reused chain-ID connection
				return
			}
		}
		f.serve(w, r)
	}))
	t.Cleanup(f.server.Close)
	p := fixtureProvider(t, func(o *Options) {
		o.Networks[0].URL = f.server.URL
		o.Networks[0].Credential = &CredentialBinding{RefID: "PUBLIC_TEST_RPC_KEY", Header: "Idempotency-Key", Value: "public-test-material"}
		o.Transport = f.server.Client().Transport
	})
	id, _ := fixtureDID(t, "polygon:mumbai", 12)
	a := stateAttempt(t.Context(), p, "polygon:mumbai", id.BigInt())
	defer a.close()
	_, err := (&resolver{a, "polygon:mumbai"}).ResolveGlobalRoot(t.Context(), big.NewInt(1234))
	if !errors.Is(err, ErrProvider) || !a.unavailable.Load() || receivedCalls.Load() != 1 || a.wire.calls != 1 || a.wire.total != 2 || f.chains.Load() != 1 {
		t.Fatalf("failed POST replayed outside its physical budget: received=%d counted=%d total=%d error=%v", receivedCalls.Load(), a.wire.calls, a.wire.total, err)
	}
}

func TestTypedGetterPreservesFailureAndGenesisProvenance(t *testing.T) {
	for _, row := range []struct {
		name                                string
		mode                                int64
		root, genesis, unavailable, success bool
	}{
		{"capacity state", 11, false, false, true, false},
		{"capacity root", 11, true, false, true, false},
		{"invalid ABI state", 14, false, false, true, false},
		{"invalid ABI root", 14, true, false, true, false},
		{"missing state preserves genesis", 12, false, true, false, true},
		{"missing non-genesis state is evidence", 12, false, false, false, false},
		{"missing root is evidence", 13, true, false, false, false},
		{"wrong issuer is evidence", 10, false, false, false, false},
	} {
		t.Run(row.name, func(t *testing.T) {
			f := newRPCFixture(t)
			f.mode.Store(row.mode)
			id, _ := fixtureDID(t, "polygon:mumbai", 12)
			a := stateAttempt(t.Context(), f.provider(t), "polygon:mumbai", id.BigInt())
			defer a.close()
			r := &resolver{a, "polygon:mumbai"}
			var err error
			if row.root {
				_, err = r.ResolveGlobalRoot(t.Context(), big.NewInt(1234))
			} else {
				s := big.NewInt(200)
				if row.genesis {
					s = new(big.Int).Lsh(big.NewInt(12), 40)
					a.parsed.roles[stateKey{"polygon:mumbai", id.BigInt().String(), s.String()}] = true
				}
				resolved, resolveErr := r.Resolve(t.Context(), id.BigInt(), s)
				err = resolveErr
				if row.success && (resolved == nil || !resolved.Genesis || !resolved.Latest) {
					t.Fatal("standard missing-state genesis algorithm was replaced")
				}
			}
			if a.unavailable.Load() != row.unavailable || row.success && err != nil || !row.success && row.unavailable && !errors.Is(err, ErrProvider) || !row.success && !row.unavailable && !errors.Is(err, ErrEvidence) {
				t.Fatalf("wrong generated getter provenance: unavailable=%v error=%v", a.unavailable.Load(), err)
			}
			if f.chains.Load() != 1 || f.calls.Load() != 1 {
				t.Fatal("provenance check did not reach real typed RPC")
			}
		})
	}
}

// Invoked with the same actual freshly generated proof by both native and
// verification-only builds. No verifier success stub or old re-timestamped proof.
func checkFreshProofRPCFailures(t *testing.T, request Request, compact string) {
	t.Helper()
	for _, row := range []struct {
		name string
		mode int64
		want error
	}{{"capacity", 11, ErrProvider}, {"invalid ABI", 14, ErrProvider}, {"missing root", 13, ErrEvidence}} {
		t.Run(row.name, func(t *testing.T) {
			f := newRPCFixture(t)
			f.mode.Store(row.mode)
			p := f.logicalProvider(t, nil)
			proof, err := p.Verify(t.Context(), request, compact)
			if proof != nil || !errors.Is(err, row.want) || f.chains.Load() != 1 || f.calls.Load() != 1 {
				t.Fatalf("actual proof lost RPC error provenance: chains=%d calls=%d error=%v", f.chains.Load(), f.calls.Load(), err)
			}
		})
	}
}

func TestActualTypedStateDistinguishesHistoricalAuthFromCurrentNonrev(t *testing.T) {
	f := newRPCFixture(t)
	p := f.provider(t)
	issuer, _ := fixtureDID(t, "polygon:mumbai", 12)
	a := stateAttempt(t.Context(), p, "polygon:mumbai", issuer.BigInt())
	defer a.close()
	r := &resolver{a, "polygon:mumbai"}
	old, err := r.Resolve(context.Background(), issuer.BigInt(), big.NewInt(100))
	if err != nil || old == nil || old.Latest {
		t.Fatal("valid historical signing state rejected", err)
	}
	current, err := r.Resolve(context.Background(), issuer.BigInt(), big.NewInt(200))
	if err != nil || current == nil || !current.Latest {
		t.Fatal("current nonrev rejected", err)
	}
	if _, err := r.ResolveGlobalRoot(context.Background(), big.NewInt(1234)); err != nil {
		t.Fatal(err)
	}
	if f.chains.Load() != 1 || f.calls.Load() != 3 {
		t.Fatal("chain not reused ONLY within attempt")
	}
	a2 := stateAttempt(t.Context(), p, "polygon:mumbai", issuer.BigInt())
	defer a2.close()
	if _, err := (&resolver{a2, "polygon:mumbai"}).ResolveGlobalRoot(context.Background(), big.NewInt(1234)); err != nil {
		t.Fatal(err)
	}
	if f.chains.Load() != 2 || f.calls.Load() != 4 {
		t.Fatal("state or chain cached between proof attempts")
	}
	before := f.hits.Load()
	if _, err := r.Resolve(context.Background(), issuer.BigInt(), big.NewInt(201)); err == nil || f.hits.Load() != before {
		t.Fatal("unplanned state lookup reached node")
	}
	// One pair used in both roles must satisfy the stronger nonrev requirement.
	a.parsed.roles[stateKey{"polygon:mumbai", issuer.BigInt().String(), "100"}] = true
	if _, err := r.Resolve(context.Background(), issuer.BigInt(), big.NewInt(100)); err == nil {
		t.Fatal("historical signing state borrowed as current nonrev")
	}
}
func TestActualTypedStateRejectsReplacedFutureRootsAndWrongChain(t *testing.T) {
	for _, row := range []struct {
		name   string
		mode   int64
		nonrev bool
	}{{"future replaced GIST", 1, false}, {"future replaced nonrev", 2, true}, {"wrong chain", 4, false}, {"wrong root", 9, false}, {"wrong issuer", 10, true}} {
		t.Run(row.name, func(t *testing.T) {
			f := newRPCFixture(t)
			f.mode.Store(row.mode)
			p := f.provider(t)
			id, _ := fixtureDID(t, "polygon:mumbai", 12)
			a := stateAttempt(t.Context(), p, "polygon:mumbai", id.BigInt())
			defer a.close()
			r := &resolver{a, "polygon:mumbai"}
			var err error
			if row.nonrev {
				_, err = r.Resolve(t.Context(), id.BigInt(), big.NewInt(200))
			} else {
				_, err = r.ResolveGlobalRoot(t.Context(), big.NewInt(1234))
			}
			if err == nil {
				t.Fatal("invalid current state accepted")
			}
			if row.mode == 4 && f.calls.Load() != 0 {
				t.Fatal("wrong-chain node queried for state")
			}
		})
	}
}

func TestActualStateTransportEnvelopes(t *testing.T) {
	for _, mode := range []int64{5, 6, 7} {
		t.Run(strconv.FormatInt(mode, 10), func(t *testing.T) {
			f := newRPCFixture(t)
			f.mode.Store(mode)
			p := f.provider(t)
			id, _ := fixtureDID(t, "polygon:mumbai", 12)
			a := stateAttempt(t.Context(), p, "polygon:mumbai", id.BigInt())
			defer a.close()
			if _, err := (&resolver{a, "polygon:mumbai"}).ResolveGlobalRoot(t.Context(), big.NewInt(1234)); err == nil {
				t.Fatal("invalid HTTP/ABI result accepted")
			}
			if mode == 5 && (f.hits.Load() != 3 || f.codes.Load() != 1 || a.wire.total != 3) {
				t.Fatal("generated empty-call fallback hidden from budget", f.hits.Load(), a.wire.total)
			}
			if mode == 7 && f.hits.Load() != 1 {
				t.Fatal("redirect followed")
			}
		})
	}
	t.Run("original cancellation reaches SDK background-state path", func(t *testing.T) {
		f := newRPCFixture(t)
		f.mode.Store(8)
		p := f.provider(t)
		ctx, cancel := context.WithCancel(t.Context())
		id, _ := fixtureDID(t, "polygon:mumbai", 12)
		a := stateAttempt(ctx, p, "polygon:mumbai", id.BigInt())
		defer a.close()
		done := make(chan error, 1)
		go func() {
			_, err := (&resolver{a, "polygon:mumbai"}).ResolveGlobalRoot(context.Background(), big.NewInt(1234))
			done <- err
		}()
		select {
		case <-f.started:
		case <-time.After(time.Second):
			t.Fatal("actual TLS request not started")
		}
		cancel()
		select {
		case err := <-done:
			if err == nil {
				t.Fatal("canceled request accepted")
			}
		case <-time.After(time.Second):
			t.Fatal("background resolver detached from original context")
		}
	})
	t.Run("guarded production transport refuses loopback unless explicitly selected", func(t *testing.T) {
		f := newRPCFixture(t)
		o := fixtureOptions(t)
		o.Networks[0].URL = f.server.URL
		o.Transport = nil
		p, e := New(o)
		if e != nil {
			t.Fatal(e)
		}
		defer p.Close()
		id, _ := fixtureDID(t, "polygon:mumbai", 12)
		a := stateAttempt(t.Context(), p, "polygon:mumbai", id.BigInt())
		defer a.close()
		if _, e := (&resolver{a, "polygon:mumbai"}).ResolveGlobalRoot(t.Context(), big.NewInt(1234)); e == nil || f.hits.Load() != 0 {
			t.Fatal("strict egress reaches loopback")
		}
	})
}

func TestActualStateCredentialAndCallTimeout(t *testing.T) {
	f := newRPCFixture(t)
	f.expectCredential.Store(true)
	p := fixtureProvider(t, func(o *Options) {
		o.Networks[0].URL = f.server.URL
		o.Networks[0].Credential = &CredentialBinding{RefID: "PUBLIC_TEST_KEY", Header: "Authorization", Value: "Bearer public-fixture-only"}
		o.Transport = f.server.Client().Transport
	})
	id, _ := fixtureDID(t, "polygon:mumbai", 12)
	a := stateAttempt(t.Context(), p, "polygon:mumbai", id.BigInt())
	defer a.close()
	if _, e := (&resolver{a, "polygon:mumbai"}).ResolveGlobalRoot(t.Context(), big.NewInt(1234)); e != nil || f.credentialChecks.Load() != 2 {
		t.Fatal("approved credential not attached to exact owned target", e)
	}
	f.mode.Store(8)
	a2 := stateAttempt(t.Context(), p, "polygon:mumbai", id.BigInt())
	defer a2.close()
	started := time.Now()
	if _, e := (&resolver{a2, "polygon:mumbai"}).ResolveGlobalRoot(context.Background(), big.NewInt(1234)); e == nil {
		t.Fatal("per-call timeout absent")
	}
	if time.Since(started) > 6*time.Second {
		t.Fatal("owned HTTP deadline exceeded generous test allowance")
	}
}

func TestRPCAllowlistRejectsBeforeCallerTransport(t *testing.T) {
	var forwarded atomic.Int64
	p := fixtureProvider(t, func(o *Options) {
		o.Transport = roundTripper(func(*http.Request) (*http.Response, error) { forwarded.Add(1); return nil, ErrProvider })
	})
	id, _ := fixtureDID(t, "polygon:mumbai", 12)
	for _, method := range []string{"eth_sendTransaction", "debug_traceCall", "eth_getLogs", "eth_call"} {
		a := stateAttempt(t.Context(), p, "polygon:mumbai", id.BigInt())
		transport := &stateTransport{a, p.networks["polygon:mumbai"]}
		body := `{"jsonrpc":"2.0","id":1,"method":"` + method + `","params":[]}`
		r, _ := http.NewRequestWithContext(t.Context(), "POST", "https://state.test/rpc", strings.NewReader(body))
		if response, err := transport.RoundTrip(r); err == nil || response != nil || forwarded.Load() != 0 {
			t.Fatal("unapproved RPC forwarded")
		}
	}
}

func TestEightNetworkWireBudgetIncludesTerminalCodeFallback(t *testing.T) {
	for _, empty := range []bool{false, true} {
		t.Run(strconv.FormatBool(empty), func(t *testing.T) {
			f := newRPCFixture(t)
			p := f.provider(t)
			if empty {
				f.emptyAt.Store(33)
			}
			// The source constructor separately validates actual selected networks.
			// This owned TLS primitive drives the SAME real per-attempt wire budget
			// over eight endpoint bindings; it is not proof/identity evidence.
			p.networks = map[string]*network{}
			for i := 0; i < 8; i++ {
				key := "test:" + strconv.Itoa(i)
				p.networks[key] = &network{binding: NetworkBinding{Network: key, ChainID: "80001", StateContract: fixtureContract, URL: f.server.URL}, transport: f.server.Client().Transport}
			}
			id, _ := fixtureDID(t, "polygon:mumbai", 12)
			a := newAttempt(t.Context(), p, parsed{holderNetwork: "test:0", gist: "1234", roles: map[stateKey]bool{}})
			defer a.close()
			if _, err := (&resolver{a, "test:0"}).ResolveGlobalRoot(t.Context(), big.NewInt(1234)); err != nil {
				t.Fatal(err)
			}
			for i := 0; i < 32; i++ {
				network := "test:" + strconv.Itoa(i%8)
				stateValue := big.NewInt(int64(200 + i))
				a.parsed.roles[stateKey{network, id.BigInt().String(), stateValue.String()}] = true
				_, err := (&resolver{a, network}).Resolve(t.Context(), id.BigInt(), stateValue)
				if i == 31 && empty {
					if err == nil {
						t.Fatal("empty ABI output accepted")
					}
				} else if err != nil {
					t.Fatal(i, err)
				}
			}
			want := int64(41)
			if empty {
				want = 42
			}
			if f.hits.Load() != want || f.chains.Load() != 8 || f.calls.Load() != 33 || int64(a.wire.total) != want {
				t.Fatal("physical budget miscount", f.hits.Load(), a.wire.total)
			}
			// Attempt43 cannot reach the real HTTP transport or reset the budget.
			a.parsed.roles[stateKey{"test:0", id.BigInt().String(), "500"}] = true
			if _, err := (&resolver{a, "test:0"}).Resolve(t.Context(), id.BigInt(), big.NewInt(500)); err == nil || f.hits.Load() != want {
				t.Fatal("overbudget attempt reached node")
			}
		})
	}
}
