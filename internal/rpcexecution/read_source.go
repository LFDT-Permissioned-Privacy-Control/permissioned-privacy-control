package rpcexecution

import (
	"context"
	"encoding/json"
	"net/url"
	"strings"
	"sync/atomic"

	"github.com/ethereum/go-ethereum/common"
)

type readSourceKind uint8

const (
	metadataReadSource readSourceKind = iota + 1
	stateReadSource
)

// newReadWire is private and closed to two non-executing read source tags.
// Neither tag is an execution acquisition or policy profile.
func newReadWire(transport Transport, source MetadataSource, credential Credential, kind readSourceKind) (*Client, MetadataSourceMetadata, error) {
	profile := ""
	switch kind {
	case metadataReadSource:
		profile = "rpc-metadata/v1"
	case stateReadSource:
		profile = "rpc-state/v1"
	default:
		return nil, MetadataSourceMetadata{}, failure(InvalidBinding)
	}
	key, err := source.Network.Key()
	u, parseErr := url.Parse(source.URL)
	if transport == nil || err != nil || common.HexToHash(source.Network.GenesisHash) == (common.Hash{}) || parseErr != nil || len(source.URL) > 2048 || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.Fragment != "" || credential.Header != source.CredentialHeader {
		return nil, MetadataSourceMetadata{}, failure(InvalidBinding)
	}
	if source.CredentialRef == "" {
		if !source.AllowUnauthenticated || credential != (Credential{}) || source.CredentialHeader != "" {
			return nil, MetadataSourceMetadata{}, failure(InvalidBinding)
		}
	} else if len(source.CredentialRef) > 256 || !headerName(credential.Header) || credential.Value == "" || len(credential.Value) > 8192 || strings.ContainsAny(credential.Value, "\r\n\x00") {
		return nil, MetadataSourceMetadata{}, failure(InvalidBinding)
	}
	meta := MetadataSourceMetadata{source.Network, key, source.URL, source.CredentialRef, source.CredentialHeader, profile}
	wire := &Client{transport: transport, binding: NodeBinding{URL: source.URL, ChainID: source.Network.ChainID, Profile: profile}, credential: credential, ids: &atomic.Uint64{}}
	return wire, meta, nil
}

// verifyReadNetwork observes only chain ID and genesis, not the selected state
// point, canonical head, readiness, or deployment/environment authority.
func verifyReadNetwork(ctx context.Context, wire *Client, source MetadataSourceMetadata) (json.RawMessage, error) {
	chain, err := wire.rpcBounded(ctx, "eth_chainId", []any{}, 4<<10)
	if err != nil {
		return nil, err
	}
	v, err := metadataJSON(chain)
	s, stringOK := v.(string)
	n, valid := quantity(s, 64)
	if err != nil || !stringOK || !valid || n.Sign() <= 0 || s != strings.ToLower(s) || n.String() != source.Network.ChainID {
		return nil, failure(InvalidEvidence)
	}
	genesis, err := wire.rpcBounded(ctx, "eth_getHeaderByNumber", []any{"0x0"}, 16<<10)
	if err != nil {
		return nil, err
	}
	header, err := decodeQualifiedHeader(genesis)
	if err != nil || header.Number != 0 || header.Hash.Hex() != source.Network.GenesisHash {
		return nil, failure(InvalidEvidence)
	}
	return chain, nil
}
