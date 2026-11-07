package rpcexecution

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/google/uuid"

	"privacy-proxy/internal/executionfacts"
	"privacy-proxy/internal/policycore"
)

type Transport interface {
	RoundTrip(*http.Request) (*http.Response, error)
}
type Credential struct{ Header, Value string }
type NodeBinding struct {
	OrganizationID                           string
	URL                                      string
	ChainID                                  string
	Profile                                  string
	PragueStartInclusive, PragueEndExclusive uint64
	AllowUnauthenticated                     bool
	Credentials                              map[string]Credential
}
type BindingMetadata struct {
	OrganizationID, ChainID, Profile         string
	PragueStartInclusive, PragueEndExclusive uint64
}
type Client struct {
	transport  Transport
	binding    NodeBinding
	limits     Limits
	credential Credential
	selected   bool
	ids        *atomic.Uint64
}

func NewClient(transport Transport, binding NodeBinding, limits Limits) (*Client, error) {
	if binding.ChainID == "" || len(binding.ChainID) > 78 {
		return nil, failure(InvalidBinding)
	}
	u, e := url.Parse(binding.URL)
	id, uuidErr := uuid.Parse(binding.OrganizationID)
	chain, ok := new(big.Int).SetString(binding.ChainID, 10)
	if transport == nil || !limits.valid() || e != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.Fragment != "" || uuidErr != nil || id.String() != binding.OrganizationID || !ok || chain.Sign() < 0 || chain.BitLen() > 256 || chain.String() != binding.ChainID || (binding.Profile != NodeProfileID && binding.Profile != GuardRetainedProfileID && binding.Profile != SignedCallProfileID) || binding.PragueEndExclusive <= binding.PragueStartInclusive {
		return nil, failure(InvalidBinding)
	}
	owned := make(map[string]Credential, len(binding.Credentials))
	for ref, credential := range binding.Credentials {
		if ref == "" || len(ref) > 256 || !headerName(credential.Header) || credential.Value == "" || len(credential.Value) > 8192 || strings.ContainsAny(credential.Value, "\r\n\x00") {
			return nil, failure(InvalidBinding)
		}
		owned[ref] = credential
	}
	if !binding.AllowUnauthenticated && len(owned) == 0 {
		return nil, failure(InvalidBinding)
	}
	binding.Credentials = owned
	return &Client{transport: transport, binding: binding, limits: limits, ids: &atomic.Uint64{}}, nil
}

func (c *Client) Metadata() BindingMetadata {
	b := c.binding
	return BindingMetadata{b.OrganizationID, b.ChainID, b.Profile, b.PragueStartInclusive, b.PragueEndExclusive}
}

// WithCredential returns an immutable selected view. The engine supplies only
// the reference chosen by the selected request org, never an HTTP input.
func (c *Client) WithCredential(ref string) (*Client, error) {
	if c == nil {
		return nil, failure(InvalidBinding)
	}
	selected := *c
	if ref == "" {
		if !c.binding.AllowUnauthenticated {
			return nil, failure(InvalidBinding)
		}
		selected.credential = Credential{}
	} else {
		credential, ok := c.binding.Credentials[ref]
		if !ok {
			return nil, failure(InvalidBinding)
		}
		selected.credential = credential
	}
	selected.selected = true
	return &selected, nil
}

type CallExecution struct {
	signed      bool
	signer      common.Address
	txHash      common.Hash
	hashMode    uint8
	recordCount int
	call        Call
	anchor      Anchor
	tree        *executionfacts.Tree
	codes       map[common.Address]CodeInfo
	raw         []byte
}

func (e *CallExecution) Call() Call                             { return e.call }
func (e *CallExecution) Anchor() Anchor                         { return e.anchor }
func (e *CallExecution) Tree() *executionfacts.Tree             { return e.tree }
func (e *CallExecution) Code(a common.Address) (CodeInfo, bool) { c, ok := e.codes[a]; return c, ok }
func (e *CallExecution) RawEvidence() []byte                    { return bytes.Clone(e.raw) }
func (e *CallExecution) RecordCount() int                       { return e.recordCount }
func (e *CallExecution) Signed() bool                           { return e != nil && e.signed }
func (e *CallExecution) VerifiedSigner() (common.Address, bool) {
	if e == nil || !e.signed {
		return common.Address{}, false
	}
	return e.signer, true
}
func (e *CallExecution) TransactionHash() (common.Hash, bool) {
	if e == nil || !e.signed {
		return common.Hash{}, false
	}
	return e.txHash, true
}
func (e *CallExecution) HashMode() uint8 {
	if e == nil {
		return 0
	}
	return e.hashMode
}

func (c *Client) rpc(ctx context.Context, method string, params []any) (json.RawMessage, error) {
	return c.rpcBounded(ctx, method, params, c.limits.MaxMuxBytes)
}

func (c *Client) rpcBounded(ctx context.Context, method string, params []any, maxBytes int64) (json.RawMessage, error) {
	id := c.ids.Add(1)
	request, _ := json.Marshal(struct {
		JSONRPC string `json:"jsonrpc"`
		ID      uint64 `json:"id"`
		Method  string `json:"method"`
		Params  []any  `json:"params"`
	}{"2.0", id, method, params})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.binding.URL, bytes.NewReader(request))
	if err != nil {
		return nil, failure(NodeFailure)
	}
	req.Header.Set("Content-Type", "application/json")
	if c.credential.Header != "" {
		req.Header.Set(c.credential.Header, c.credential.Value)
	}
	resp, err := c.transport.RoundTrip(req)
	if err != nil {
		return nil, failure(NodeFailure)
	}
	if resp == nil || resp.Body == nil {
		return nil, failure(NodeFailure)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, failure(NodeFailure)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes+1))
	if err != nil {
		return nil, failure(NodeFailure)
	}
	if int64(len(raw)) > maxBytes {
		return nil, failure(EvidenceLimit)
	}
	fields, err := closedRawObject(raw, 4)
	if err != nil {
		return nil, err
	}
	for name := range fields {
		if name != "jsonrpc" && name != "id" && name != "result" && name != "error" {
			return nil, failure(InvalidEvidence)
		}
	}
	if string(fields["jsonrpc"]) != `"2.0"` || string(fields["id"]) != strconv.FormatUint(id, 10) {
		return nil, failure(InvalidEvidence)
	}
	if _, hasError := fields["error"]; hasError {
		return nil, failure(NodeFailure)
	}
	result, ok := fields["result"]
	if !ok {
		return nil, failure(InvalidEvidence)
	}
	return result, nil
}

func (c *Client) AcquireCall(ctx context.Context, call Call, block BlockSelector) (*CallExecution, error) {
	if c == nil || !c.selected || c.binding.Profile != NodeProfileID || call.wire == nil || call.value == nil || block.selector == "" {
		return nil, failure(InvalidBinding)
	}
	return c.acquire(ctx, call, block, nil)
}

func (c *Client) acquire(ctx context.Context, call Call, block BlockSelector, overrides map[string]any) (*CallExecution, error) {
	if call.chainID != nil && call.chainID.String() != c.binding.ChainID {
		return nil, failure(InvalidCall)
	}
	ctx, cancel := context.WithTimeout(ctx, c.limits.AcquisitionTimeout)
	defer cancel()
	if ctx.Err() != nil {
		return nil, failure(NodeFailure)
	}
	chainRaw, err := c.rpc(ctx, "eth_chainId", []any{})
	if err != nil {
		return nil, err
	}
	var chainText string
	if json.Unmarshal(chainRaw, &chainText) != nil {
		return nil, failure(InvalidEvidence)
	}
	chain, ok := quantity(chainText, 256)
	if !ok || chain.String() != c.binding.ChainID || (call.chainID != nil && call.chainID.Cmp(chain) != 0) {
		return nil, failure(InvalidEvidence)
	}
	headerMethod := "eth_getBlockByNumber"
	if block.hash {
		headerMethod = "eth_getBlockByHash"
	}
	headerRaw, err := c.rpc(ctx, headerMethod, []any{block.selector, false})
	if err != nil {
		return nil, err
	}
	anchor, err := decodeHeader(headerRaw)
	if err != nil {
		return nil, err
	}
	if block.hash && anchor.Hash.Hex() != block.selector {
		return nil, failure(InvalidEvidence)
	}
	if block.historical && !block.hash {
		number, _ := quantity(block.selector, 64)
		if anchor.Number != number.Uint64() {
			return nil, failure(InvalidEvidence)
		}
	}
	if anchor.Timestamp < c.binding.PragueStartInclusive || anchor.Timestamp >= c.binding.PragueEndExclusive {
		return nil, failure(UnsupportedEvidence)
	}
	if block.canonical {
		raw, e := c.rpc(ctx, "eth_getBlockByNumber", []any{"0x" + strconv.FormatUint(anchor.Number, 16), false})
		if e != nil {
			return nil, e
		}
		canonical, e := decodeHeader(raw)
		if e != nil || canonical.Hash != anchor.Hash {
			return nil, failure(InvalidEvidence)
		}
	}
	anchor.ChainID, anchor.Profile, anchor.OrganizationID = c.binding.ChainID, c.binding.Profile, c.binding.OrganizationID
	config := map[string]any{"tracer": "muxTracer", "tracerConfig": map[string]any{"callTracer": map[string]any{"onlyTopCall": false, "withLog": true}, "prestateTracer": map[string]any{"diffMode": false, "disableCode": false, "disableStorage": true, "includeEmpty": true}}}
	if overrides != nil {
		config["stateOverrides"] = overrides
	}
	mux, err := c.rpc(ctx, "debug_traceCall", []any{call.Object(), anchor.Hash.Hex(), config})
	if err != nil {
		return nil, err
	}
	parts, err := closedRawObject(mux, 2)
	if err != nil {
		return nil, err
	}
	if len(parts) != 2 || parts["callTracer"] == nil || parts["prestateTracer"] == nil {
		return nil, failure(InvalidEvidence)
	}
	expected := executionfacts.ExpectedRoot{Kind: executionfacts.Call, From: call.from, To: executionfacts.Address{Value: call.to, Known: true}, Input: call.input, Value: call.value}
	tree, err := executionfacts.Parse(parts["callTracer"], expected, executionfacts.GethCallTracerWithLogsProfile(), c.limits.Trace)
	if err != nil {
		return nil, failure(InvalidEvidence)
	}
	codes, total, err := decodePrestate(parts["prestateTracer"], c.limits)
	if err != nil {
		return nil, err
	}
	return c.finishEvidence(ctx, call, anchor, tree, codes, total, mux)
}

func (c *Client) finishEvidence(ctx context.Context, call Call, anchor Anchor, tree *executionfacts.Tree, codes map[common.Address]CodeInfo, total int, raw []byte) (*CallExecution, error) {
	lookups := 0
	ensureCode := func(a common.Address) error {
		code, present := codes[a]
		if !present && !precompile(a) {
			if lookups >= c.limits.MaxAnchoredCodeLookups {
				return failure(EvidenceLimit)
			}
			lookups++
			raw, e := c.rpc(ctx, "eth_getCode", []any{a.Hex(), map[string]any{"blockHash": anchor.Hash.Hex(), "requireCanonical": false}})
			if e != nil {
				return e
			}
			b, e := decodeCode(raw, min(c.limits.MaxCodeBytesPerAccount, c.limits.MaxTotalCodeBytes-total))
			if e != nil {
				return e
			}
			total += len(b)
			code = CodeInfo{code: b, hash: crypto.Keccak256Hash(b)}
		}
		if delegation(code.code) {
			return failure(UnsupportedEvidence)
		}
		if precompile(a) {
			code.precompile = true
			code.hash = crypto.Keccak256Hash(nil)
		}
		codes[a] = code
		return nil
	}
	records := tree.Records()
	for _, record := range records {
		if ctx.Err() != nil {
			return nil, failure(NodeFailure)
		}
		if record.Kind == executionfacts.Create || record.Kind == executionfacts.Create2 || record.Kind == executionfacts.SelfDestruct {
			return nil, failure(UnsupportedEvidence)
		}
		if !record.NominalCodeAddress.Known || !record.StorageAddress.Known {
			return nil, failure(InvalidEvidence)
		}
		for _, a := range []common.Address{record.NominalCodeAddress.Value, record.StorageAddress.Value} {
			if err := ensureCode(a); err != nil {
				return nil, err
			}
		}
		if target, recognized, e := policycore.InspectUpgradeTarget(record.Input); recognized {
			if e != nil {
				return nil, failure(InvalidEvidence)
			}
			if e = ensureCode(target); e != nil {
				return nil, e
			}
		}
	}
	if ctx.Err() != nil {
		return nil, failure(NodeFailure)
	}
	return &CallExecution{call: call, anchor: anchor, tree: tree, codes: codes, raw: bytes.Clone(raw), recordCount: len(records)}, nil
}
