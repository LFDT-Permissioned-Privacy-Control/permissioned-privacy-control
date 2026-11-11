package rpcexecution

import (
	"context"
	"fmt"

	"privacy-proxy/internal/creationfacts"
)

// RequireCanonicalAncestor samples one original observer head by NUMBER on the
// same selected, network-bound endpoint. A by-hash lookup cannot prove that the
// retained header is still canonical. The endpoint is trusted and logically
// consistent; this is not an atomic check against a later socket/mining event.
func (c *Client) RequireCanonicalAncestor(ctx context.Context, head creationfacts.Header) error {
	if c == nil || !c.selected || !c.networkBound || ctx == nil || !head.Valid() || head.Parent != ([32]byte{}) || head.Timestamp != 0 {
		return failure(InvalidBinding)
	}
	ctx, cancel := context.WithTimeout(ctx, c.limits.AcquisitionTimeout)
	defer cancel()
	raw, err := c.rpcBounded(ctx, "eth_getHeaderByNumber", []any{fmt.Sprintf("0x%x", head.Number)}, 16<<10)
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
