package rpcexecution

import (
	"bytes"
	"context"
	"encoding/json"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

type MetadataClient struct {
	wire   *Client
	source MetadataSourceMetadata
	limits MetadataLimits
}

func NewMetadataClient(transport Transport, source MetadataSource, credential Credential, limits MetadataLimits) (*MetadataClient, error) {
	if !limits.valid() {
		return nil, failure(InvalidBinding)
	}
	wire, meta, err := newReadWire(transport, source, credential, metadataReadSource)
	if err != nil {
		return nil, err
	}
	return &MetadataClient{wire: wire, source: meta, limits: limits}, nil
}

func (c *MetadataClient) Source() MetadataSourceMetadata {
	if c == nil {
		return MetadataSourceMetadata{}
	}
	return c.source
}

// MetadataObservation is a validated result, not forwarding permission. Source
// is configured metadata; a local Keccak result observes no live node at all.
type MetadataObservation struct {
	source MetadataSourceMetadata
	method MetadataMethod
	result []byte
}

func (o *MetadataObservation) Source() MetadataSourceMetadata {
	if o == nil {
		return MetadataSourceMetadata{}
	}
	return o.source
}
func (o *MetadataObservation) Method() MetadataMethod {
	if o == nil {
		return InvalidMetadataMethod
	}
	return o.method
}
func (o *MetadataObservation) ResultJSON() []byte {
	if o == nil {
		return nil
	}
	return bytes.Clone(o.result)
}

// Query performs zero I/O for Keccak, two RPCs for chain ID and at most three
// for other methods. The same earlier deadline covers the whole operation.
func (c *MetadataClient) Query(ctx context.Context, q MetadataQuery) (*MetadataObservation, error) {
	if c == nil || c.wire == nil || ctx == nil || !q.validFor(c.limits) {
		return nil, failure(InvalidCall)
	}
	ctx, cancel := context.WithTimeout(ctx, c.limits.Timeout)
	defer cancel()
	if ctx.Err() != nil {
		return nil, failure(NodeFailure)
	}
	if q.method == MetadataKeccak {
		// The encoded 32-byte digest has exactly68 bytes, known before hashing.
		if c.limits.MaxResultBytes < 68 {
			return nil, failure(EvidenceLimit)
		}
		raw, _ := json.Marshal("0x" + common.Bytes2Hex(crypto.Keccak256(q.hashInput)))
		if ctx.Err() != nil {
			return nil, failure(NodeFailure)
		}
		return &MetadataObservation{c.source, q.method, raw}, nil
	}
	chain, err := verifyReadNetwork(ctx, c.wire, c.source)
	if err != nil {
		return nil, err
	}
	raw := chain
	if q.method != MetadataChainID {
		raw, err = c.wire.rpcBounded(ctx, q.method.String(), q.params, c.limits.MaxResultBytes)
		if err != nil {
			return nil, err
		}
	}
	raw, err = metadataResult(q, raw, c.limits)
	if err != nil {
		return nil, err
	}
	if ctx.Err() != nil {
		return nil, failure(NodeFailure)
	}
	return &MetadataObservation{c.source, q.method, raw}, nil
}
