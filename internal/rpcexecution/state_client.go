package rpcexecution

import (
	"bytes"
	"context"
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

// StateObservation pairs the exact owned query and validated result. It makes
// no statepoint, privacy, authorization or proof-node confidentiality assertion.
type StateObservation struct {
	source StateSourceMetadata
	query  StateQuery
	result []byte
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
	result, err := stateResult(q, raw, c.limits)
	if err != nil {
		return nil, err
	}
	if ctx.Err() != nil {
		return nil, failure(NodeFailure)
	}
	return &StateObservation{c.source, q, result}, nil
}
