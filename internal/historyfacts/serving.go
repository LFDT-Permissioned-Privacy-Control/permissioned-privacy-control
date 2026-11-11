package historyfacts

import (
	"context"
	"time"

	"github.com/ethereum/go-ethereum/common"
)

// OriginalFence returns only the owning operation values, never an acquisition
// child or the original context (which can retain authentication/body values).
func (c *Current) OriginalFence() (time.Time, <-chan struct{}) {
	if c == nil {
		return time.Time{}, nil
	}
	return c.fence.deadline, c.fence.done
}

// RequireLive is the final no-I/O check after the LAST actual source probe.
// It never builds, renews or replaces the original verified View.
func (c *Current) RequireLive(ctx context.Context) error {
	if c == nil || c.owner == nil || c.view == nil || ctx == nil || ctx.Err() != nil || c.fence.Check() != nil || c.view.RequireLive() != nil {
		return ErrUnavailable
	}
	return nil
}

// EmitterMetadataCharge allows the serving owner to reserve metadata BEFORE
// Emitter makes ABI/grant copies. It is conservative payload accounting, not a
// heap estimate. The original immutable catalog itself is not copied here.
func (c *Current) EmitterMetadataCharge(address common.Address) int {
	if c == nil || c.view == nil {
		return 0
	}
	return c.view.ReadMetadataCharge(address)
}
