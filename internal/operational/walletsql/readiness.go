package walletsql

import (
	"context"
	w "privacy-proxy/internal/walletops"
)

func (s *Store) CheckReady(ctx context.Context, namespace w.Namespace, expected w.ExpectedState) error {
	if s == nil || s.pool == nil || ctx == nil || !expected.Valid() {
		return w.ErrUnavailable
	}
	ctx, cancel := bounded(ctx)
	defer cancel()
	if s.CheckSchema(ctx) != nil || s.checkPrivileges(ctx) != nil || checkState(ctx, s.pool, namespace, expected) != nil || ctx.Err() != nil {
		return w.ErrUnavailable
	}
	return nil
}
