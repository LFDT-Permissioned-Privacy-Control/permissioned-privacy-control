package ssosql

import (
	"context"
	"time"
)

func (s *Store) CheckReady(ctx context.Context) error {
	if s == nil || s.pool == nil || ctx == nil {
		return ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	tx, err := begin(ctx, s.pool)
	if err != nil {
		return err
	}
	defer rollback(tx)
	if err = s.check(ctx, tx, false); err != nil {
		return err
	}
	if tx.Commit(ctx) != nil || ctx.Err() != nil {
		return ErrUnavailable
	}
	return nil
}
