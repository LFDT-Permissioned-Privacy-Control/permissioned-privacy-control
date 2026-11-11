package rpcexecution

import (
	"bytes"
	"context"
	"strconv"

	"github.com/ethereum/go-ethereum/common"
	"privacy-proxy/internal/creationfacts"
)

// StateSource shares the immutable network/credential binding used by metadata
// reads. A source's configured environment and deployment are operational inputs.
type StateSource = MetadataSource
type StateSourceMetadata = MetadataSourceMetadata

type StateClient struct {
	wire   *Client
	source StateSourceMetadata
	limits StateLimits
}

// RequireCanonicalHeader checks one original observed ancestor by NUMBER on
// this exact concrete source. It makes one bounded call, with no retry or
// network/source fallback. The complete returned header is hash-recomputed;
// this is sampled canonicality under the trusted-node boundary, not consensus
// verification, an atomic statepoint or a future-reorg guarantee.
func (c *StateClient) RequireCanonicalHeader(ctx context.Context, head creationfacts.Header) error {
	if c == nil || c.wire == nil || ctx == nil || !head.Valid() || head.Parent != (common.Hash{}) || head.Timestamp != 0 {
		return failure(InvalidCall)
	}
	ctx, cancel := context.WithTimeout(ctx, c.limits.Timeout)
	defer cancel()
	if ctx.Err() != nil {
		return failure(NodeFailure)
	}
	raw, err := c.wire.rpcBounded(ctx, "eth_getHeaderByNumber", []any{"0x" + strconv.FormatUint(head.Number, 16)}, 16<<10)
	if err != nil {
		return err
	}
	actual, err := decodeQualifiedHeader(raw)
	if err != nil || actual.Number != head.Number || actual.Hash != head.Hash {
		return failure(InvalidEvidence)
	}
	if ctx.Err() != nil {
		return failure(NodeFailure)
	}
	return nil
}

func NewStateClient(transport Transport, source StateSource, credential Credential, limits StateLimits) (*StateClient, error) {
	if !limits.valid() {
		return nil, failure(InvalidBinding)
	}
	wire, meta, err := newReadWire(transport, source, credential, stateReadSource)
	if err != nil {
		return nil, err
	}
	return &StateClient{wire, meta, limits}, nil
}

func (c *StateClient) Source() StateSourceMetadata {
	if c == nil {
		return StateSourceMetadata{}
	}
	return c.source
}

func (c *StateClient) Bounds() StateLimits {
	if c == nil {
		return StateLimits{}
	}
	return c.limits
}

// ProofAccountPresence is a small typed observation under the existing trusted
// backend boundary. It is not Merkle verification or a permission capability.
type ProofAccountPresence struct {
	AccountProofNodes            int
	NonceNonzero, BalanceNonzero bool
	CodeHash, StorageHash        common.Hash
}

// StateObservation pairs the exact owned query and validated result. It makes
// no statepoint, privacy, authorization or proof-node confidentiality assertion.
type StateObservation struct {
	source      StateSourceMetadata
	query       StateQuery
	result      []byte
	presence    ProofAccountPresence
	hasPresence bool
}

func (o *StateObservation) Source() StateSourceMetadata {
	if o == nil {
		return StateSourceMetadata{}
	}
	return o.source
}
func (o *StateObservation) Query() StateQuery {
	if o == nil {
		return StateQuery{}
	}
	return o.query // Its mutable storage is private; every slice getter copies.
}
func (o *StateObservation) Method() StateMethod {
	if o == nil {
		return InvalidStateMethod
	}
	return o.query.Method()
}
func (o *StateObservation) ResultJSON() []byte {
	if o == nil {
		return nil
	}
	return bytes.Clone(o.result)
}
func (o *StateObservation) ResultSize() int64 {
	if o == nil {
		return 0
	}
	return int64(len(o.result))
}
func (o *StateObservation) ProofAccountPresence() (ProofAccountPresence, bool) {
	if o == nil {
		return ProofAccountPresence{}, false
	}
	return o.presence, o.hasPresence
}

// Query performs at most three physical calls with one earlier-parent deadline.
// The returned scalar or proof remains bound to this original parsed request.
func (c *StateClient) Query(ctx context.Context, q StateQuery) (*StateObservation, error) {
	if c == nil || c.wire == nil || ctx == nil || !q.validFor(c.limits) {
		return nil, failure(InvalidCall)
	}
	ctx, cancel := context.WithTimeout(ctx, c.limits.Timeout)
	defer cancel()
	if ctx.Err() != nil {
		return nil, failure(NodeFailure)
	}
	if _, err := verifyReadNetwork(ctx, c.wire, c.source); err != nil {
		return nil, err
	}
	raw, err := c.wire.rpcBounded(ctx, q.method.String(), q.params, c.limits.MaxResultBytes)
	if err != nil {
		return nil, err
	}
	result, presence, hasPresence, err := stateResultWithPresence(q, raw, c.limits)
	if err != nil {
		return nil, err
	}
	if ctx.Err() != nil {
		return nil, failure(NodeFailure)
	}
	return &StateObservation{source: c.source, query: q, result: result, presence: presence, hasPresence: hasPresence}, nil
}
