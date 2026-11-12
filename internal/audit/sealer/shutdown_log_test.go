package sealer

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"testing"
)

type observedLogs struct {
	mu       sync.Mutex
	messages []string
}

func (*observedLogs) Enabled(context.Context, slog.Level) bool { return true }
func (h *observedLogs) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.messages = append(h.messages, r.Message)
	return nil
}
func (h *observedLogs) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *observedLogs) WithGroup(string) slog.Handler      { return h }
func (h *observedLogs) retries() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	n := 0
	for _, s := range h.messages {
		if s == "audit sealer tick failed (will retry next tick)" {
			n++
		}
	}
	return n
}

func TestRunDoesNotReportNormalCancellationAsRetryableFailure(t *testing.T) {
	logs := &observedLogs{}
	previous := slog.Default()
	slog.SetDefault(slog.New(logs))
	defer slog.SetDefault(previous)
	b := newBuf(t, 0)
	defer b.Close()
	entered := make(chan struct{})
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	s := New(b, func(context.Context, uint64, []byte) error { return nil }, func(ctx context.Context) (uint64, error) { close(entered); <-ctx.Done(); return 0, ctx.Err() }, Config{})
	done := make(chan struct{})
	go func() { s.Run(ctx); close(done) }()
	<-entered
	cancel()
	<-done
	if logs.retries() != 0 {
		t.Fatal("normal shutdown reported a future retry")
	}
}

func TestRunKeepsActualDependencyFailureLog(t *testing.T) {
	logs := &observedLogs{}
	previous := slog.Default()
	slog.SetDefault(slog.New(logs))
	defer slog.SetDefault(previous)
	b := newBuf(t, 0)
	defer b.Close()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	// The second attempt ends the finite loop only after the first genuine
	// failure had its normal retry log; the error is never reclassified as close.
	n := 0
	s := New(b, func(context.Context, uint64, []byte) error { return nil }, func(context.Context) (uint64, error) {
		n++
		if n == 2 {
			cancel()
		}
		return 0, errors.New("owned unavailable database")
	}, Config{Interval: 1})
	s.Run(ctx)
	if logs.retries() != 1 {
		t.Fatal("genuine dependency failure was hidden", logs.retries())
	}
}
