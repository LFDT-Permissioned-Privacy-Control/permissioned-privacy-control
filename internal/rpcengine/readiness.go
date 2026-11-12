package rpcengine

import (
	"context"
	"errors"
)

var errOperationalReadiness = errors.New("execution dependency unavailable")

// CheckOperationalReadiness uses the same live Guard producer gate as raw
// admission. A node identity/sync observation alone does not establish it.
func (e *Engine) CheckOperationalReadiness(ctx context.Context) error {
	if e == nil || ctx == nil || ctx.Err() != nil {
		return errOperationalReadiness
	}
	if e.raw == nil {
		return nil
	}
	if e.raw.closed.Load() {
		return errOperationalReadiness
	}
	for _, refs := range e.raw.bindings {
		for _, binding := range refs {
			if binding.pair != nil && !binding.pair.Ready() {
				return errOperationalReadiness
			}
		}
	}
	if ctx.Err() != nil {
		return errOperationalReadiness
	}
	return nil
}
