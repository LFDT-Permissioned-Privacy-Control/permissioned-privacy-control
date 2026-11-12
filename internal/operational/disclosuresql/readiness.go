package disclosuresql

import (
	"context"
	c "privacy-proxy/internal/disclosurecase"
)

func (s *Store) CheckReady(ctx context.Context) error {
	if s == nil || s.pool == nil || ctx == nil {
		return c.ErrUnavailable
	}
	ctx, cancel := bounded(ctx)
	defer cancel()
	if s.CheckSchema(ctx) != nil || s.checkAppPrivileges(ctx) != nil || ctx.Err() != nil {
		return c.ErrUnavailable
	}
	return nil
}
