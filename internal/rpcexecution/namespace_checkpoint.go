package rpcexecution

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"math"
	"net/http"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"privacy-proxy/internal/creationfacts"
	"privacy-proxy/internal/historynamespace"
	"privacy-proxy/internal/networkidentity"
	"privacy-proxy/internal/policycore"
)

type NamespaceCheckpointLimits struct {
	Timeout           time.Duration
	MaxAddresses      int
	MaxCodeBytes      int
	MaxTotalCodeBytes int
	MaxWireBytes      int64
}

func DefaultNamespaceCheckpointLimits() NamespaceCheckpointLimits {
	return NamespaceCheckpointLimits{15 * time.Second, 128, 1 << 20, 8 << 20, 18 << 20}
}
func (l NamespaceCheckpointLimits) valid() bool {
	m := DefaultNamespaceCheckpointLimits()
	return l.Timeout > 0 && l.Timeout <= m.Timeout && l.MaxAddresses > 0 && l.MaxAddresses <= m.MaxAddresses &&
		l.MaxCodeBytes > 0 && l.MaxCodeBytes <= m.MaxCodeBytes && l.MaxTotalCodeBytes > 0 && l.MaxTotalCodeBytes <= m.MaxTotalCodeBytes &&
		l.MaxWireBytes > 0 && l.MaxWireBytes <= m.MaxWireBytes
}

// NamespaceCheckpointClient is an import-only owned node client. It creates no
// execution, approval, initial namespace or complete historical source.
type NamespaceCheckpointClient struct {
	transport  Transport
	source     creationfacts.Source
	credential Credential
	era        historynamespace.ModelEra
	limits     NamespaceCheckpointLimits
}

func NewNamespaceCheckpointClient(transport Transport, source creationfacts.Source, credential Credential, era historynamespace.ModelEra, limits NamespaceCheckpointLimits) (*NamespaceCheckpointClient, error) {
	if !era.Valid() || !limits.valid() || source.PragueStart >= era.EndTimestampExclusive || source.PragueEnd <= era.EntryTimestamp {
		return nil, failure(InvalidBinding)
	}
	key, err := (networkidentity.Binding{Environment: source.Network.Environment, ChainID: source.Network.ChainID, GenesisHash: source.Network.Genesis.Hex(), DeploymentID: source.Network.Deployment}).Key()
	if err != nil || creationfacts.Digest(key) != source.Network.Key {
		return nil, failure(InvalidBinding)
	}
	if _, err := NewHeaderClient(transport, source, credential, HeaderLimits{limits.Timeout, 1, 16 << 10}); err != nil {
		return nil, err
	}
	return &NamespaceCheckpointClient{transport, source, credential, era, limits}, nil
}

func (c *NamespaceCheckpointClient) Source() creationfacts.Source {
	if c == nil {
		return creationfacts.Source{}
	}
	return c.source
}

type NamespaceCheckpointProof struct {
	source creationfacts.Source
	facts  historynamespace.CheckpointFacts
	digest historynamespace.Digest
	valid  bool
}

func (p *NamespaceCheckpointProof) Facts() historynamespace.CheckpointFacts {
	if p == nil || !p.valid {
		return historynamespace.CheckpointFacts{}
	}
	f := p.facts
	f.Codes = append([]historynamespace.QualifiedCode(nil), f.Codes...)
	return f
}
func (p *NamespaceCheckpointProof) Source() creationfacts.Source {
	if p == nil || !p.valid {
		return creationfacts.Source{}
	}
	return p.source
}
func (p *NamespaceCheckpointProof) Digest() historynamespace.Digest {
	if p == nil || !p.valid {
		return historynamespace.Digest{}
	}
	return p.digest
}

// Qualify observes END-of-block runtime at one canonical number. Exactly two
// HeaderClient.Read operations cost four calls each; at most128 code calls make
// the physical ceiling136. One operation-local budget counts ALL raw envelope
// bytes, including hostile JSON whitespace, under the one earlier-parent deadline.
func (c *NamespaceCheckpointClient) Qualify(ctx context.Context, number uint64, addresses []historynamespace.Address) (*NamespaceCheckpointProof, error) {
	if c == nil || ctx == nil || !c.limits.valid() || number < c.era.EntryNumber || number > math.MaxInt64 || len(addresses) == 0 || len(addresses) > c.limits.MaxAddresses {
		return nil, failure(InvalidCall)
	}
	addresses = append([]historynamespace.Address(nil), addresses...)
	for i, address := range addresses {
		if policycore.IsPraguePrecompile(common.Address(address)) || i > 0 && bytes.Compare(addresses[i-1][:], address[:]) >= 0 {
			return nil, failure(InvalidCall)
		}
	}
	ctx, cancel := context.WithTimeout(ctx, c.limits.Timeout)
	defer cancel()
	budget := &namespaceWireBudget{base: c.transport, remaining: c.limits.MaxWireBytes, maxCalls: 8 + len(addresses)}
	headers, err := NewHeaderClient(budget, c.source, c.credential, HeaderLimits{c.limits.Timeout, 1, 16 << 10})
	if err != nil {
		return nil, err
	}
	query := []HeaderQuery{{NumberOrTag: fmt.Sprintf("0x%x", number)}}
	before, err := headers.Read(ctx, query)
	if err != nil {
		return nil, namespaceBudgetError(budget, err)
	}
	if !before.Synced() || len(before.headers) != 1 {
		return nil, failure(InvalidEvidence)
	}
	header := before.headers[0]
	if header.Timestamp < c.era.EntryTimestamp || header.Timestamp >= c.era.EndTimestampExclusive || header.Timestamp < c.source.PragueStart || header.Timestamp >= c.source.PragueEnd || number == c.era.EntryNumber && (historynamespace.Hash(header.Hash) != c.era.EntryHash || header.Timestamp != c.era.EntryTimestamp) {
		return nil, failure(InvalidEvidence)
	}
	facts := historynamespace.CheckpointFacts{Network: historynamespace.Digest(c.source.Network.Key), Source: historynamespace.Digest(c.source.Digest()), Era: c.era, Number: number, Hash: historynamespace.Hash(header.Hash), Timestamp: header.Timestamp, Codes: make([]historynamespace.QualifiedCode, 0, len(addresses))}
	total := 0
	for _, address := range addresses {
		raw, err := headers.wire.rpcBounded(ctx, "eth_getCode", []any{common.Address(address).Hex(), map[string]any{"blockHash": header.Hash.Hex(), "requireCanonical": true}}, int64(2*c.limits.MaxCodeBytes+4096))
		if err != nil {
			return nil, namespaceBudgetError(budget, err)
		}
		code, err := decodeCode(raw, c.limits.MaxCodeBytes)
		if err != nil {
			return nil, err
		}
		if len(code) == 0 || code[0] == 0xef || delegation(code) {
			return nil, failure(InvalidEvidence)
		}
		total += len(code)
		if total > c.limits.MaxTotalCodeBytes {
			return nil, failure(EvidenceLimit)
		}
		facts.Codes = append(facts.Codes, historynamespace.QualifiedCode{Address: address, RuntimeHash: historynamespace.Hash(crypto.Keccak256Hash(code)), RuntimeLength: uint32(len(code))})
	}
	after, err := headers.Read(ctx, query)
	if err != nil {
		return nil, namespaceBudgetError(budget, err)
	}
	if !after.Synced() || len(after.headers) != 1 || after.headers[0] != header || ctx.Err() != nil {
		return nil, failure(InvalidEvidence)
	}
	digest, err := historynamespace.CheckpointFactsDigest(facts)
	if err != nil {
		return nil, failure(InvalidEvidence)
	}
	return &NamespaceCheckpointProof{source: c.source, facts: facts, digest: digest, valid: true}, nil
}

type namespaceWireBudget struct {
	base      Transport
	remaining int64
	calls     int
	maxCalls  int
	exceeded  bool
}

func (b *namespaceWireBudget) RoundTrip(request *http.Request) (*http.Response, error) {
	if b.calls >= b.maxCalls || b.remaining <= 0 {
		b.exceeded = true
		return nil, failure(EvidenceLimit)
	}
	b.calls++
	response, err := b.base.RoundTrip(request)
	if err != nil || response == nil || response.Body == nil {
		return response, err
	}
	detached := *response
	detached.Body = &namespaceCountedBody{body: response.Body, budget: b}
	return &detached, nil
}

type namespaceCountedBody struct {
	body   io.ReadCloser
	budget *namespaceWireBudget
}

func (r *namespaceCountedBody) Read(p []byte) (int, error) {
	if r.budget.remaining < 0 {
		return 0, failure(EvidenceLimit)
	}
	if int64(len(p)) > r.budget.remaining+1 {
		p = p[:r.budget.remaining+1]
	}
	n, err := r.body.Read(p)
	r.budget.remaining -= int64(n)
	if r.budget.remaining < 0 {
		r.budget.exceeded = true
		return n, failure(EvidenceLimit)
	}
	return n, err
}
func (r *namespaceCountedBody) Close() error { return r.body.Close() }
func namespaceBudgetError(b *namespaceWireBudget, err error) error {
	if b.exceeded {
		return failure(EvidenceLimit)
	}
	return err
}
