package rpcexecution

import (
	"context"
	"encoding/json"

	"github.com/ethereum/go-ethereum/common"
	"privacy-proxy/internal/networkidentity"
)

// WithNetwork returns an immutable source clone. The expected tuple comes from
// trusted assembly; deriving its key does not verify the connected backend.
func (c *Client) WithNetwork(expected networkidentity.Binding) (*Client, error) {
	_, err := expected.Key()
	if c == nil || c.transport == nil || !c.limits.valid() || err != nil || common.HexToHash(expected.GenesisHash) == (common.Hash{}) || c.binding.ChainID != expected.ChainID || c.networkBound && c.network != expected {
		return nil, failure(InvalidBinding)
	}
	bound := *c
	bound.network, bound.networkBound = expected, true
	return &bound, nil
}

func (c *Client) BoundNetwork() (networkidentity.Binding, bool) {
	if c == nil || !c.networkBound {
		return networkidentity.Binding{}, false
	}
	return c.network, true
}

// requireGenesis uses the acquisition's existing deadline, or the final probe's
// earlier-parent deadline. Only this same selected credential/source is used.
func (c *Client) requireGenesis(ctx context.Context) error {
	if ctx.Err() != nil {
		return failure(NodeFailure)
	}
	raw, err := c.rpcBounded(ctx, "eth_getHeaderByNumber", []any{"0x0"}, 16<<10)
	if err != nil {
		return err
	}
	header, err := decodeQualifiedHeader(raw)
	if err != nil || header.Number != 0 || header.Hash != common.HexToHash(c.network.GenesisHash) {
		return failure(InvalidEvidence)
	}
	if ctx.Err() != nil {
		return failure(NodeFailure)
	}
	return nil
}

// RequireBoundNetwork samples actual chain configuration and genesis again.
// Chain ID is not committed into the genesis header, so both must match. This
// checks one logically consistent trusted endpoint, not consensus or an atomic
// source-to-socket fence. Unbound clients cannot supply a successful probe.
func (c *Client) RequireBoundNetwork(ctx context.Context) error {
	if c == nil || !c.selected || !c.networkBound || ctx == nil {
		return failure(InvalidBinding)
	}
	ctx, cancel := context.WithTimeout(ctx, c.limits.AcquisitionTimeout)
	defer cancel()
	if ctx.Err() != nil {
		return failure(NodeFailure)
	}
	raw, err := c.rpcBounded(ctx, "eth_chainId", []any{}, 1024)
	if err != nil {
		return err
	}
	var text string
	if json.Unmarshal(raw, &text) != nil {
		return failure(InvalidEvidence)
	}
	chain, valid := quantity(text, 64)
	if !valid || chain.String() != c.network.ChainID {
		return failure(InvalidEvidence)
	}
	return c.requireGenesis(ctx)
}
