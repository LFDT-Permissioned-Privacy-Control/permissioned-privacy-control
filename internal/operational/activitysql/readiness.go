package activitysql

import (
	"context"
	a "privacy-proxy/internal/activitylog"
	"time"
)

// Promoted to Reader and Writer; observes state without allocating a run/sequence.
func (s *store) CheckReady(ctx context.Context) error {
	if s == nil || s.pool == nil || ctx == nil {
		return a.ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	tx, err := begin(ctx, s.pool, true)
	if err != nil {
		return err
	}
	defer rollback(tx)
	state, err := selected(ctx, tx, s.scope, false, true)
	if err != nil || state.metadata != s.state.metadata || state.roles != s.state.roles || checkSchema(ctx, tx) != nil || checkRole(ctx, tx, state.roles, s.mode) != nil || checkHead(ctx, tx, state, s.mode) != nil {
		return a.ErrUnavailable
	}
	if tx.Commit(ctx) != nil || ctx.Err() != nil {
		return a.ErrUnavailable
	}
	return nil
}
