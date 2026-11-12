package identitysql

import (
	"context"
	b "privacy-proxy/internal/identitybroker"
	"time"
)

// CheckReady observes the actual selected role, schema and recovery epoch.
// It neither creates a family nor treats a reachable database as ready.
func (s *Store) CheckReady(ctx context.Context) error {
	if s == nil || s.pool == nil || ctx == nil {
		return b.ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if checkSchema(ctx, s.pool) != nil || checkV2Privileges(ctx, s.pool, "", s.mode) != nil || checkState(ctx, s.pool, s.scope) != nil || ctx.Err() != nil {
		return b.ErrUnavailable
	}
	return nil
}
func (s *ProofStore) CheckReady(ctx context.Context) error {
	if s == nil {
		return b.ErrUnavailable
	}
	return s.store.CheckReady(ctx)
}
