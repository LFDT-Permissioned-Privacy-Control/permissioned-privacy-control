package privado

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/rpc"
	stateabi "github.com/iden3/contracts-abi/state/go/abi"
	"github.com/iden3/go-iden3-auth/v2/pubsignals"
	"github.com/iden3/go-iden3-auth/v2/state"
)

type attempt struct {
	ctx         context.Context
	provider    *Provider
	parsed      parsed
	lookup      sync.Mutex
	clients     map[string]*ethclient.Client
	getters     map[string]*stateabi.StateCaller
	chainReady  map[string]bool
	wire        wireBudget
	unavailable atomic.Bool
}
type wireBudget struct {
	mu                  sync.Mutex
	total, calls, codes int
	chains              map[string]bool
	lastEmpty           string
	failed              bool
}
type resolver struct {
	attempt *attempt
	network string
}

func newAttempt(ctx context.Context, p *Provider, parsed parsed) *attempt {
	return &attempt{ctx: ctx, provider: p, parsed: parsed, clients: map[string]*ethclient.Client{}, getters: map[string]*stateabi.StateCaller{}, chainReady: map[string]bool{}, wire: wireBudget{chains: map[string]bool{}}}
}

func (a *attempt) close() {
	for _, client := range a.clients {
		client.Close()
	}
}
func (a *attempt) resolvers() map[string]pubsignals.StateResolver {
	result := map[string]pubsignals.StateResolver{}
	for network := range a.provider.networks {
		result[network] = &resolver{a, network}
	}
	return result
}
func (a *attempt) getter(networkID string) (*stateabi.StateCaller, error) {
	if a.ctx.Err() != nil {
		return nil, ErrProvider
	}
	if existing := a.getters[networkID]; existing != nil {
		return existing, nil
	}
	n := a.provider.networks[networkID]
	if n == nil {
		return nil, ErrEvidence
	}
	client := &http.Client{Transport: &stateTransport{a, n}, Timeout: RPCTimeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	rpcClient, err := rpc.DialOptions(a.ctx, n.binding.URL, rpc.WithHTTPClient(client))
	if err != nil {
		return nil, ErrProvider
	}
	eth := ethclient.NewClient(rpcClient)
	a.clients[networkID] = eth
	chain, err := eth.ChainID(a.ctx)
	if err != nil || chain == nil || chain.String() != n.binding.ChainID {
		a.unavailable.Store(true)
		return nil, ErrProvider
	}
	a.chainReady[networkID] = true
	getter, err := stateabi.NewStateCaller(common.HexToAddress(n.binding.StateContract), eth)
	if err != nil {
		return nil, ErrProvider
	}
	a.getters[networkID] = getter
	return getter, nil
}

// The SDK packer currently uses Background for holder state. This wrapper
// always owns the ORIGINAL operation context; it never detaches an RPC.
func (r *resolver) Resolve(_ context.Context, id, s *big.Int) (*state.ResolvedState, error) {
	a := r.attempt
	a.lookup.Lock()
	defer a.lookup.Unlock()
	if id == nil || s == nil || a.ctx.Err() != nil {
		return nil, ErrProvider
	}
	current, planned := a.parsed.roles[stateKey{r.network, id.String(), s.String()}]
	if !planned {
		return nil, ErrEvidence
	}
	getter, err := a.getter(r.network)
	if err != nil {
		return nil, err
	}
	resolved, err := state.Resolve(a.ctx, observedGetter{a, getter}, id, s)
	if a.ctx.Err() != nil || a.unavailable.Load() {
		return nil, ErrProvider
	}
	if err != nil {
		return nil, ErrEvidence
	}
	if resolved == nil || resolved.State != s.String() || current && !resolved.Latest {
		return nil, ErrEvidence
	}
	return resolved, nil
}
func (r *resolver) ResolveGlobalRoot(_ context.Context, s *big.Int) (*state.ResolvedState, error) {
	a := r.attempt
	a.lookup.Lock()
	defer a.lookup.Unlock()
	if s == nil || a.ctx.Err() != nil {
		return nil, ErrProvider
	}
	if r.network != a.parsed.holderNetwork || s.String() != a.parsed.gist {
		return nil, ErrEvidence
	}
	getter, err := a.getter(r.network)
	if err != nil {
		return nil, err
	}
	resolved, err := state.ResolveGlobalRoot(a.ctx, observedGetter{a, getter}, s)
	if a.ctx.Err() != nil || a.unavailable.Load() {
		return nil, ErrProvider
	}
	if err != nil {
		return nil, ErrEvidence
	}
	if resolved == nil || resolved.State != s.String() || !resolved.Latest {
		return nil, ErrEvidence
	}
	return resolved, nil
}

// Observe the generated getter's errors before SDK wrapping loses their
// provenance. The SDK's known missing-state errors are part of its genesis and
// invalid-evidence algorithm; unrelated RPC/ABI failures mean unavailability.
// These methods do not replace or duplicate either SDK resolution algorithm.
type observedGetter struct {
	attempt *attempt
	caller  *stateabi.StateCaller
}

func (g observedGetter) GetStateInfoByIdAndState(opts *bind.CallOpts, id, s *big.Int) (stateabi.IStateStateInfo, error) {
	row, err := g.caller.GetStateInfoByIdAndState(opts, id, s)
	if err != nil && !stateabi.IsErrStateDoesNotExist(err) {
		g.attempt.unavailable.Store(true)
	}
	return row, err
}

func (g observedGetter) GetGISTRootInfo(opts *bind.CallOpts, root *big.Int) (stateabi.IStateGistRootInfo, error) {
	row, err := g.caller.GetGISTRootInfo(opts, root)
	if err != nil && !stateabi.IsErrRootDoesNotExist(err) {
		g.attempt.unavailable.Store(true)
	}
	return row, err
}

type stateTransport struct {
	attempt *attempt
	network *network
}

func (t *stateTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	a, n := t.attempt, t.network
	a.wire.mu.Lock()
	defer a.wire.mu.Unlock()
	fail := func() (*http.Response, error) {
		a.wire.failed = true
		a.unavailable.Store(true)
		return nil, ErrProvider
	}
	if a.wire.failed || a.ctx.Err() != nil || request.Context().Err() != nil || request.Method != http.MethodPost || request.URL.String() != n.binding.URL || request.Body == nil || request.ContentLength > 16<<10 {
		return fail()
	}
	defer request.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(request.Body, (16<<10)+1))
	if err != nil || len(raw) > 16<<10 {
		return fail()
	}
	nodes := 0
	value, err := readJSON(raw, 16<<10, &nodes)
	if err != nil {
		return fail()
	}
	message, ok := value.(map[string]any)
	if !ok || !keys(message, []string{"jsonrpc", "id", "method"}, []string{"params"}) || message["jsonrpc"] != "2.0" {
		return fail()
	}
	if _, ok := integer(message["id"], 1<<63-1); !ok {
		return fail()
	}
	method, ok := message["method"].(string)
	if !ok {
		return fail()
	}
	params, hasParams := message["params"].([]any)
	if _, present := message["params"]; present && !hasParams {
		return fail()
	}
	a.wire.total++
	if a.wire.total > MaxRPCRequests {
		return fail()
	}
	switch method {
	case "eth_chainId":
		if len(params) != 0 || a.wire.chains[n.binding.Network] || len(a.wire.chains) >= MaxNetworks {
			return fail()
		}
		a.wire.chains[n.binding.Network] = true
		a.wire.lastEmpty = ""
	case "eth_call":
		if !a.chainReady[n.binding.Network] || len(params) != 2 || params[1] != "latest" || a.wire.calls >= 33 {
			return fail()
		}
		call, ok := params[0].(map[string]any)
		if !ok || !keys(call, []string{"from", "to", "input"}, nil) || call["from"] != (common.Address{}).Hex() || !target(call["to"], n.binding.StateContract) {
			return fail()
		}
		input, ok := call["input"].(string)
		if !ok || !stateInput(input) {
			return fail()
		}
		a.wire.calls++
		a.wire.lastEmpty = ""
	case "eth_getCode":
		if !a.chainReady[n.binding.Network] || len(params) != 2 || params[1] != "latest" || !target(params[0], n.binding.StateContract) || a.wire.lastEmpty != n.binding.Network || a.wire.codes != 0 {
			return fail()
		}
		a.wire.codes++
		a.wire.lastEmpty = ""
	default:
		return fail()
	}
	copy := request.Clone(request.Context())
	copy.Header = request.Header.Clone()
	copy.Body = io.NopCloser(bytes.NewReader(raw))
	// A permitted credential may be an Idempotency-Key. Do not let the
	// underlying Go transport replay this counted POST after its body was sent.
	copy.GetBody = nil
	copy.ContentLength = int64(len(raw))
	copy.Header.Set("Accept-Encoding", "identity")
	if n.binding.Credential != nil {
		copy.Header.Set(n.binding.Credential.Header, n.binding.Credential.Value)
	}
	response, err := n.transport.RoundTrip(copy)
	if err != nil {
		return fail()
	}
	if response == nil || response.Body == nil {
		return fail()
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || response.ContentLength > 64<<10 || response.Header.Get("Content-Encoding") != "" {
		return fail()
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, (64<<10)+1))
	if err != nil || len(data) > 64<<10 || a.ctx.Err() != nil || request.Context().Err() != nil {
		return fail()
	}
	nodes = 0
	value, err = readJSON(data, 64<<10, &nodes)
	if err != nil {
		return fail()
	}
	output, ok := value.(map[string]any)
	if !ok || !keys(output, []string{"jsonrpc", "id"}, []string{"result", "error"}) || output["jsonrpc"] != "2.0" || output["id"] != message["id"] {
		return fail()
	}
	_, hasResult := output["result"]
	_, hasError := output["error"]
	if hasResult == hasError {
		return fail()
	}
	if hasResult {
		result, ok := output["result"].(string)
		if !ok || !hexResult(result) {
			return fail()
		}
		if method == "eth_call" && result == "0x" {
			a.wire.lastEmpty = n.binding.Network
		}
	} else {
		errorObject, ok := output["error"].(map[string]any)
		if !ok || !keys(errorObject, []string{"code", "message"}, []string{"data"}) {
			return fail()
		}
		if _, ok := errorObject["code"].(json.Number); !ok {
			return fail()
		}
		if _, ok := errorObject["message"].(string); !ok {
			return fail()
		}
	}
	out := new(http.Response)
	*out = *response
	out.Header = response.Header.Clone()
	out.Body = io.NopCloser(bytes.NewReader(data))
	out.ContentLength = int64(len(data))
	return out, nil
}
func target(v any, address string) bool {
	s, ok := v.(string)
	return ok && len(s) == 42 && common.IsHexAddress(s) && common.HexToAddress(s) == common.HexToAddress(address)
}
func hexResult(s string) bool {
	if !strings.HasPrefix(s, "0x") {
		return false
	}
	for _, c := range s[2:] {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
func stateInput(input string) bool {
	if !strings.HasPrefix(input, "0x") || (len(input) != 2+68*2 && len(input) != 2+36*2) {
		return false
	}
	data, err := hex.DecodeString(input[2:])
	if err != nil {
		return false
	}
	abi, err := stateabi.StateMetaData.GetAbi()
	if err != nil {
		return false
	}
	if len(data) == 68 && bytes.Equal(data[:4], abi.Methods["getStateInfoByIdAndState"].ID) {
		return true
	}
	return len(data) == 36 && bytes.Equal(data[:4], abi.Methods["getGISTRootInfo"].ID)
}
