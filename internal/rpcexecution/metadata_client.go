package rpcexecution

import (
	"bytes"
	"context"
	"encoding/json"
	"net/url"
	"strings"
	"sync/atomic"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

type MetadataClient struct {
	wire   *Client
	source MetadataSourceMetadata
	limits MetadataLimits
}

func NewMetadataClient(transport Transport, source MetadataSource, credential Credential, limits MetadataLimits) (*MetadataClient, error) {
	key, err := source.Network.Key()
	u, parseErr := url.Parse(source.URL)
	if transport == nil || !limits.valid() || err != nil || common.HexToHash(source.Network.GenesisHash) == (common.Hash{}) || parseErr != nil || len(source.URL) > 2048 || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.Fragment != "" || credential.Header != source.CredentialHeader {
		return nil, failure(InvalidBinding)
	}
	if source.CredentialRef == "" {
		if !source.AllowUnauthenticated || credential != (Credential{}) || source.CredentialHeader != "" {
			return nil, failure(InvalidBinding)
		}
	} else if len(source.CredentialRef) > 256 || !headerName(credential.Header) || credential.Value == "" || len(credential.Value) > 8192 || strings.ContainsAny(credential.Value, "\r\n\x00") {
		return nil, failure(InvalidBinding)
	}
	meta := MetadataSourceMetadata{source.Network, key, source.URL, source.CredentialRef, source.CredentialHeader, "rpc-metadata/v1"}
	// This private client reuses only the bounded no-replay wire operation.
	// Its metadata profile cannot activate any existing execution acquisition.
	wire := &Client{transport: transport, binding: NodeBinding{URL: source.URL, ChainID: source.Network.ChainID, Profile: meta.Profile}, credential: credential, ids: &atomic.Uint64{}}
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
	chain, err := c.wire.rpcBounded(ctx, "eth_chainId", []any{}, 4<<10)
	if err != nil {
		return nil, err
	}
	v, err := metadataJSON(chain)
	s, stringOK := v.(string)
	n, valid := quantity(s, 64)
	if err != nil || !stringOK || !valid || n.Sign() <= 0 || s != strings.ToLower(s) || n.String() != c.source.Network.ChainID {
		return nil, failure(InvalidEvidence)
	}
	genesis, err := c.wire.rpcBounded(ctx, "eth_getHeaderByNumber", []any{"0x0"}, 16<<10)
	if err != nil {
		return nil, err
	}
	header, err := decodeQualifiedHeader(genesis)
	if err != nil || header.Number != 0 || header.Hash.Hex() != c.source.Network.GenesisHash {
		return nil, failure(InvalidEvidence)
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
