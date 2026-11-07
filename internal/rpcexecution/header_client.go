package rpcexecution

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"math"
	"strings"
	"sync/atomic"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"privacy-proxy/internal/creationfacts"
)

// HeaderLimits bound one Read, including its network and synchronization checks.
// An earlier caller deadline still applies. Limits can only lower these ceilings.
type HeaderLimits struct {
	Timeout        time.Duration
	MaxQueries     int
	MaxHeaderBytes int64
}

func DefaultHeaderLimits() HeaderLimits { return HeaderLimits{15 * time.Second, 128, 16 << 10} }

func (l HeaderLimits) valid() bool {
	m := DefaultHeaderLimits()
	return l.Timeout > 0 && l.Timeout <= m.Timeout && l.MaxQueries > 0 && l.MaxQueries <= m.MaxQueries && l.MaxHeaderBytes > 0 && l.MaxHeaderBytes <= m.MaxHeaderBytes
}

// HeaderQuery is a closed selector union: latest or a canonical nonnegative
// numeric selector, OR one nonzero hash. A hash lookup does not prove canonicality.
type HeaderQuery struct {
	NumberOrTag string
	Hash        common.Hash
}

func (q HeaderQuery) valid() bool {
	if q.Hash != (common.Hash{}) {
		return q.NumberOrTag == ""
	}
	if q.NumberOrTag == "latest" {
		return true
	}
	n, ok := quantity(q.NumberOrTag, 64)
	return ok && n.IsInt64() && q.NumberOrTag == strings.ToLower(q.NumberOrTag)
}

// HeaderClient owns an explicitly selected network reference. It has no org
// selection, execution acquisition or mutable readiness API.
type HeaderClient struct {
	wire   *Client
	source creationfacts.Source
	limits HeaderLimits
}

func NewHeaderClient(transport Transport, source creationfacts.Source, credential Credential, limits HeaderLimits) (*HeaderClient, error) {
	if transport == nil || !source.Valid() || source.Profile != "reth-prague-included-creations/v1" || !limits.valid() || credential.Header != source.CredentialHeader {
		return nil, failure(InvalidBinding)
	}
	if source.CredentialRef == "" {
		if credential != (Credential{}) {
			return nil, failure(InvalidBinding)
		}
	} else if !headerName(credential.Header) || credential.Value == "" || len(credential.Value) > 8192 || strings.ContainsAny(credential.Value, "\r\n\x00") {
		return nil, failure(InvalidBinding)
	}
	// Reuse only the bounded RPC transport, whose POST GetBody is nil. This
	// private wire client is never exposed as an org execution client: the
	// included-reference profile cannot activate any legacy acquisition path.
	wire := &Client{
		transport:  transport,
		binding:    NodeBinding{URL: source.URL, ChainID: source.Network.ChainID, Profile: source.Profile},
		credential: credential,
		ids:        &atomic.Uint64{},
	}
	return &HeaderClient{wire: wire, source: source, limits: limits}, nil
}

// Source returns the immutable, nonsecret startup descriptor for cold pairing.
func (c *HeaderClient) Source() creationfacts.Source {
	if c == nil {
		return creationfacts.Source{}
	}
	return c.source
}

// HeaderBatch contains bounded observations, not a readiness or ownership
// verdict. Callers still verify their canonical branch, prefix and fork window.
type HeaderBatch struct {
	source  creationfacts.Source
	headers []creationfacts.Header
	synced  bool
}

func (b *HeaderBatch) Source() creationfacts.Source {
	if b == nil {
		return creationfacts.Source{}
	}
	return b.source // values and strings only; never the credential value
}

func (b *HeaderBatch) Headers() []creationfacts.Header {
	if b == nil {
		return nil
	}
	return append([]creationfacts.Header{}, b.headers...)
}

func (b *HeaderBatch) Synced() bool { return b != nil && b.synced }

// Read makes at most len(queries)+3 physical RPC attempts under ONE deadline.
// The worst response envelope total is (128+1)*16KiB+2*4KiB, below 3MiB.
// No retries, redirects, full-block fallback or deadline reset occur here.
// An empty query list performs only the three network/sync checks.
func (c *HeaderClient) Read(ctx context.Context, queries []HeaderQuery) (*HeaderBatch, error) {
	if c == nil || c.wire == nil || ctx == nil || !c.limits.valid() {
		return nil, failure(InvalidBinding)
	}
	if len(queries) > c.limits.MaxQueries {
		return nil, failure(EvidenceLimit)
	}
	queries = append([]HeaderQuery(nil), queries...)
	for _, query := range queries {
		if !query.valid() {
			return nil, failure(InvalidCall)
		}
	}
	ctx, cancel := context.WithTimeout(ctx, c.limits.Timeout)
	defer cancel()
	if ctx.Err() != nil {
		return nil, failure(NodeFailure)
	}
	chain, err := c.wire.rpcBounded(ctx, "eth_chainId", []any{}, 4<<10)
	if err != nil {
		return nil, err
	}
	var chainID string
	if json.Unmarshal(chain, &chainID) != nil {
		return nil, failure(InvalidEvidence)
	}
	n, ok := quantity(chainID, 64)
	if !ok || n.String() != c.source.Network.ChainID || chainID != strings.ToLower(chainID) {
		return nil, failure(InvalidEvidence)
	}
	genesis, err := c.readHeader(ctx, HeaderQuery{NumberOrTag: "0x0"})
	if err != nil {
		return nil, err
	}
	if genesis.Number != 0 || genesis.Hash != c.source.Network.Genesis {
		return nil, failure(InvalidEvidence)
	}
	progress, err := c.wire.rpcBounded(ctx, "eth_syncing", []any{}, 4<<10)
	if err != nil {
		return nil, err
	}
	synced, err := decodeHeaderSync(progress)
	if err != nil {
		return nil, err
	}
	out := &HeaderBatch{source: c.source, headers: make([]creationfacts.Header, 0, len(queries)), synced: synced}
	for _, query := range queries {
		header, err := c.readHeader(ctx, query)
		if err != nil {
			return nil, err
		}
		out.headers = append(out.headers, header)
	}
	if ctx.Err() != nil {
		return nil, failure(NodeFailure)
	}
	return out, nil
}

func (c *HeaderClient) readHeader(ctx context.Context, query HeaderQuery) (creationfacts.Header, error) {
	method, selector := "eth_getHeaderByNumber", query.NumberOrTag
	if query.Hash != (common.Hash{}) {
		method, selector = "eth_getHeaderByHash", query.Hash.Hex()
	}
	raw, err := c.wire.rpcBounded(ctx, method, []any{selector}, c.limits.MaxHeaderBytes)
	if err != nil {
		return creationfacts.Header{}, err
	}
	header, err := decodeQualifiedHeader(raw)
	if err != nil {
		return creationfacts.Header{}, err
	}
	if query.Hash != (common.Hash{}) {
		if header.Hash != query.Hash {
			return creationfacts.Header{}, failure(InvalidEvidence)
		}
	} else if query.NumberOrTag != "latest" {
		number, _ := quantity(query.NumberOrTag, 64) // validated before any RPC
		if number == nil || header.Number != number.Uint64() {
			return creationfacts.Header{}, failure(InvalidEvidence)
		}
	}
	return header, nil
}

// decodeQualifiedHeader validates every declared field before invoking geth's
// generated decoder and recomputes the complete RLP header hash. It deliberately
// supplies no consensus validation, Prague-time or canonicality verdict.
func decodeQualifiedHeader(raw []byte) (creationfacts.Header, error) {
	if len(raw) > 16<<10 {
		return creationfacts.Header{}, failure(EvidenceLimit)
	}
	nullable := map[string]bool{
		"baseFeePerGas": true, "withdrawalsRoot": true, "blobGasUsed": true,
		"excessBlobGas": true, "parentBeaconBlockRoot": true, "requestsHash": true,
		"totalDifficulty": true, "size": true,
		// Newer geth encoders emit these as null even for older headers. A
		// nonnull value activates an unqualified later header format.
		"blockAccessListHash": true, "slotNumber": true,
	}
	fields, err := nullableRawObject(raw, 32, nullable)
	if err != nil {
		return creationfacts.Header{}, err
	}
	dataFields := map[string]int{
		"hash": 32, "parentHash": 32, "sha3Uncles": 32, "miner": 20,
		"stateRoot": 32, "transactionsRoot": 32, "receiptsRoot": 32,
		"logsBloom": 256, "extraData": -1, "mixHash": 32, "nonce": 8,
		"withdrawalsRoot": 32, "parentBeaconBlockRoot": 32, "requestsHash": 32,
	}
	quantityFields := map[string]int{
		"difficulty": 256, "number": 64, "gasLimit": 64, "gasUsed": 64,
		"timestamp": 64, "baseFeePerGas": 256, "blobGasUsed": 64,
		"excessBlobGas": 64, "totalDifficulty": 256, "size": 64,
	}
	for _, name := range []string{"hash", "parentHash", "sha3Uncles", "miner", "stateRoot", "transactionsRoot", "receiptsRoot", "logsBloom", "difficulty", "number", "gasLimit", "gasUsed", "timestamp", "extraData", "mixHash", "nonce"} {
		if fields[name] == nil {
			return creationfacts.Header{}, failure(InvalidEvidence)
		}
	}
	for name, value := range fields {
		if bytes.Equal(bytes.TrimSpace(value), []byte("null")) && nullable[name] {
			continue
		}
		if name == "blockAccessListHash" || name == "slotNumber" {
			return creationfacts.Header{}, failure(UnsupportedEvidence)
		}
		var text string
		if json.Unmarshal(value, &text) != nil || text != strings.ToLower(text) {
			return creationfacts.Header{}, failure(InvalidEvidence)
		}
		if size, declared := dataFields[name]; declared {
			if !strings.HasPrefix(text, "0x") || len(text)%2 != 0 || (size >= 0 && len(text) != 2+size*2) {
				return creationfacts.Header{}, failure(InvalidEvidence)
			}
			if _, err := hex.DecodeString(text[2:]); err != nil {
				return creationfacts.Header{}, failure(InvalidEvidence)
			}
		} else if bits, declared := quantityFields[name]; declared {
			n, valid := quantity(text, bits)
			if !valid || (name == "number" && !n.IsInt64()) {
				return creationfacts.Header{}, failure(InvalidEvidence)
			}
		} else {
			return creationfacts.Header{}, failure(InvalidEvidence)
		}
	}
	var header types.Header
	if json.Unmarshal(raw, &header) != nil || header.Number == nil || header.Difficulty == nil || !header.Number.IsInt64() || header.Number.Sign() < 0 || header.GasUsed > header.GasLimit {
		return creationfacts.Header{}, failure(InvalidEvidence)
	}
	var claimed string
	if json.Unmarshal(fields["hash"], &claimed) != nil || header.Hash().Hex() != claimed {
		return creationfacts.Header{}, failure(InvalidEvidence)
	}
	out := creationfacts.Header{Number: header.Number.Uint64(), Hash: header.Hash(), Parent: header.ParentHash, Timestamp: header.Time}
	if out.Number > math.MaxInt64 || !out.Valid() {
		return creationfacts.Header{}, failure(InvalidEvidence)
	}
	return out, nil
}

func decodeHeaderSync(raw []byte) (bool, error) {
	if bytes.Equal(bytes.TrimSpace(raw), []byte("false")) {
		return true, nil
	}
	fields, err := closedRawObject(raw, 32)
	if err != nil {
		return false, err
	}
	for _, name := range []string{"startingBlock", "currentBlock", "highestBlock"} {
		if fields[name] == nil {
			return false, failure(InvalidEvidence)
		}
	}
	// Progress telemetry is not authority. The three standard fields and any
	// bounded extension must be canonical hex quantities; any valid object
	// still means syncing, never readiness.
	for _, value := range fields {
		var text string
		if json.Unmarshal(value, &text) != nil || text != strings.ToLower(text) {
			return false, failure(InvalidEvidence)
		}
		if _, ok := quantity(text, 256); !ok {
			return false, failure(InvalidEvidence)
		}
	}
	return false, nil
}
