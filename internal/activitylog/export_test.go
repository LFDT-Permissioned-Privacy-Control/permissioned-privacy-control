package activitylog

import (
	"context"
	"privacy-proxy/internal/audit/buffer"
)

// NewRecorderForTest uses the real private constructor and buffer. This symbol
// exists only in the activitylog test binary, never in the production package.
func NewRecorderForTest(ctx context.Context, c Config, store Store, options ...buffer.Option) (*Recorder, error) {
	return newRecorder(ctx, c, store, options)
}
