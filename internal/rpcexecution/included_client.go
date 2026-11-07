package rpcexecution

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"strconv"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"privacy-proxy/internal/creationfacts"
	"privacy-proxy/internal/executionfacts"
	"privacy-proxy/internal/policycore"
)

type IncludedClient struct {
	header *HeaderClient
	source creationfacts.Source
	limits IncludedLimits
}

func NewIncludedClient(transport Transport, source creationfacts.Source, credential Credential, limits IncludedLimits) (*IncludedClient, error) {
	if !limits.valid() || source.Profile != IncludedProfileID {
		return nil, failure(InvalidBinding)
	}
	header, err := NewHeaderClient(transport, source, credential, DefaultHeaderLimits())
	if err != nil {
		return nil, err
	}
	return &IncludedClient{header: header, source: source, limits: limits}, nil
}
func (c *IncludedClient) Source() creationfacts.Source {
	if c == nil {
		return creationfacts.Source{}
	}
	return c.source
}

func (c *IncludedClient) AcquireIncluded(ctx context.Context, wanted common.Hash) (*IncludedCreationProof, error) {
	if c == nil || c.header == nil || ctx == nil || wanted == (common.Hash{}) || !c.limits.valid() {
		return nil, failure(InvalidBinding)
	}
	ctx, cancel := context.WithTimeout(ctx, c.limits.Timeout)
	defer cancel()
	requests := 0
	rpc := func(method string, params []any, limit int64, nullable bool) (json.RawMessage, error) {
		if requests >= c.limits.MaxRequests {
			return nil, failure(EvidenceLimit)
		}
		requests++
		return c.header.wire.rpcResultBounded(ctx, method, params, limit, nullable)
	}
	raw, err := rpc("eth_chainId", []any{}, 4096, false)
	if err != nil {
		return nil, err
	}
	chain, err := includedString(raw, 18)
	if err != nil {
		return nil, err
	}
	n, valid := quantity(chain, 64)
	if !valid || n.String() != c.source.Network.ChainID {
		return nil, failure(InvalidEvidence)
	}
	raw, err = rpc("eth_getHeaderByNumber", []any{"0x0"}, 16<<10, false)
	if err != nil {
		return nil, err
	}
	genesis, err := decodeQualifiedHeader(raw)
	if err != nil || genesis.Number != 0 || genesis.Hash != c.source.Network.Genesis {
		return nil, failure(InvalidEvidence)
	}
	raw, err = rpc("eth_getTransactionByHash", []any{wanted.Hex()}, c.limits.MaxTransactionBytes, true)
	if err != nil {
		return nil, err
	}
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return nil, ErrNotIncluded
	}
	tx, pos, err := decodeIncludedTransaction(raw, wanted, c.source.Network.ChainID)
	if err != nil {
		return nil, err
	}
	raw, err = rpc("eth_getTransactionReceipt", []any{wanted.Hex()}, c.limits.MaxReceiptBytes, true)
	if err != nil {
		return nil, err
	}
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return nil, ErrNotIncluded
	}
	success, err := decodeIncludedReceipt(raw, tx, pos)
	if err != nil {
		return nil, err
	}
	raw, err = rpc("eth_getBlockByHash", []any{pos.Hash.Hex(), false}, c.limits.MaxBlockBytes, false)
	if err != nil {
		return nil, err
	}
	header, err := decodeIncludedBlock(raw, pos, wanted)
	if err != nil || header.Timestamp < c.source.PragueStart || header.Timestamp >= c.source.PragueEnd {
		return nil, failure(InvalidEvidence)
	}
	canonical := func() error {
		b, err := rpc("eth_getBlockByNumber", []any{"0x" + strconv.FormatUint(pos.Number, 16), false}, c.limits.MaxBlockBytes, false)
		if err != nil {
			return err
		}
		h, err := decodeIncludedBlock(b, pos, wanted)
		if err != nil || h != header {
			return failure(InvalidEvidence)
		}
		return nil
	}
	if err := canonical(); err != nil {
		return nil, err
	}
	config := map[string]any{"tracer": "muxTracer", "tracerConfig": map[string]any{"callTracer": map[string]any{"onlyTopCall": false, "withLog": true}, "prestateTracer": map[string]any{"diffMode": false, "disableCode": false, "disableStorage": true, "includeEmpty": true}}}
	raw, err = rpc("debug_traceTransaction", []any{wanted.Hex(), config}, c.limits.MaxMuxBytes, false)
	if err != nil {
		return nil, err
	}
	mux, err := closedRawObject(raw, 2)
	if err != nil || len(mux) != 2 || mux["callTracer"] == nil || mux["prestateTracer"] == nil {
		return nil, failure(InvalidEvidence)
	}
	// Bound and parse full prestate, then discard it. Parent/post-block state
	// is never substituted for actual transaction-index account authority.
	preLimits := DefaultLimits()
	preLimits.MaxCodeBytesPerAccount = c.limits.MaxCodeBytes
	preLimits.MaxTotalCodeBytes = c.limits.MaxTotalCodeBytes
	if _, _, err := decodePrestate(mux["prestateTracer"], preLimits); err != nil {
		return nil, err
	}
	expected := executionfacts.ExpectedRoot{Kind: executionfacts.Call, From: tx.Signer(), Input: tx.Input(), Value: tx.Value()}
	if to, call := tx.Destination(); call {
		expected.To = executionfacts.Address{Value: to, Known: true}
	} else {
		expected.Kind = executionfacts.Create
		expected.CreatedAddress = executionfacts.Address{Value: crypto.CreateAddress(tx.Signer(), tx.Nonce()), Known: true}
	}
	tree, err := executionfacts.Parse(mux["callTracer"], expected, executionfacts.GethLifecycleWithLogsProfile(), c.limits.Trace)
	if err != nil {
		return nil, failure(InvalidEvidence)
	}
	records := tree.Records()
	if len(records) == 0 || (!records[0].Failed()) != success {
		return nil, failure(InvalidEvidence)
	}
	proof := &IncludedCreationProof{source: c.source, transaction: tx, header: header, index: pos.Index, success: success, creations: []IncludedCreationRecord{}, self: []IncludedSelfRecord{}}
	nearest := make([]int, len(records))
	committedSelf := map[common.Address]bool{}
	work := len(records)
	outputBytes := 0
	for i, r := range records {
		if ctx.Err() != nil {
			return nil, failure(NodeFailure)
		}
		parent := -1
		if r.ParentIndex >= 0 {
			parent = nearest[r.ParentIndex]
		}
		nearest[i] = parent
		work += 1 + (len(r.Input)+31)/32 + (len(r.Output)+31)/32
		if work > c.limits.MaxWork {
			return nil, failure(EvidenceLimit)
		}
		if r.Kind == executionfacts.SelfDestruct {
			if !r.StorageAddress.Known {
				return nil, failure(UnsupportedEvidence)
			}
			if !r.Failed() && !r.AncestorFailed {
				committedSelf[r.StorageAddress.Value] = true
			}
			proof.self = append(proof.self, IncludedSelfRecord{Record: i, Parent: parent, Depth: r.Depth, Source: r.StorageAddress.Value, Beneficiary: r.To.Value, BeneficiaryKnown: r.To.Known, Value: "0x" + r.Value.Text(16), Failed: r.Failed(), AncestorFailed: r.AncestorFailed})
			continue
		}
		if r.Kind != executionfacts.Create && r.Kind != executionfacts.Create2 {
			continue
		}
		nearest[i] = i
		if !r.Failed() && !r.AncestorFailed {
			if len(r.Output) > c.limits.MaxTotalCodeBytes-outputBytes {
				return nil, failure(EvidenceLimit)
			}
			outputBytes += len(r.Output)
		}
		proof.creations = append(proof.creations, IncludedCreationRecord{Record: i, Parent: parent, Depth: r.Depth, Kind: string(r.Kind), Address: r.StorageAddress.Value, AddressKnown: r.StorageAddress.Known, Creator: r.From, Caller: r.CallerAddress.Value, CallerKnown: r.CallerAddress.Known, InputHash: crypto.Keccak256Hash(r.Input), Value: "0x" + r.Value.Text(16), OutputHash: crypto.Keccak256Hash(r.Output), OutputLength: len(r.Output), Failed: r.Failed(), AncestorFailed: r.AncestorFailed})
	}
	seen := map[common.Address]bool{}
	totalCode := 0
	survivors := 0
	for i := range proof.creations {
		entry := &proof.creations[i]
		r := records[entry.Record]
		if entry.Failed || entry.AncestorFailed || !entry.AddressKnown {
			continue
		}
		if seen[entry.Address] {
			return nil, failure(UnsupportedEvidence)
		}
		seen[entry.Address] = true
		if !entry.CallerKnown || entry.OutputLength == 0 || r.Output[0] == 0xef || policycore.IsPraguePrecompile(entry.Address) || committedSelf[entry.Address] {
			continue
		}
		survivors++
		if survivors > c.limits.MaxSurvivors {
			return nil, failure(EvidenceLimit)
		}
		if entry.OutputLength > c.limits.MaxCodeBytes || entry.OutputLength > c.limits.MaxTotalCodeBytes-totalCode {
			return nil, failure(EvidenceLimit)
		}
		limit := min(c.limits.MaxCodeBytes, c.limits.MaxTotalCodeBytes-totalCode)
		raw, err := rpc("eth_getCode", []any{entry.Address.Hex(), map[string]any{"blockHash": header.Hash.Hex(), "requireCanonical": false}}, int64(2*limit+1024), false)
		if err != nil {
			return nil, err
		}
		code, err := decodeCode(raw, limit)
		if err != nil {
			return nil, err
		}
		if !bytes.Equal(code, r.Output) {
			return nil, failure(UnsupportedEvidence)
		}
		totalCode += len(code)
		work += (len(code) + 31) / 32
		if work > c.limits.MaxWork {
			return nil, failure(EvidenceLimit)
		}
		entry.Survives = true
	}
	if err := canonical(); err != nil {
		return nil, err
	}
	if ctx.Err() != nil {
		return nil, failure(NodeFailure)
	}
	semantic := struct {
		Profile   string
		Hash      common.Hash
		Header    creationfacts.Header
		Index     uint32
		Success   bool
		Creations []IncludedCreationRecord
		Self      []IncludedSelfRecord
	}{IncludedProfileID, wanted, header, pos.Index, success, proof.creations, proof.self}
	encoded, err := json.Marshal(semantic)
	if err != nil {
		return nil, failure(InvalidEvidence)
	}
	h := sha256.New()
	_, _ = h.Write([]byte("ops-included-creation-proof/v1\x00"))
	_, _ = h.Write(encoded)
	proof.digest = common.BytesToHash(h.Sum(nil))
	return proof, nil
}
