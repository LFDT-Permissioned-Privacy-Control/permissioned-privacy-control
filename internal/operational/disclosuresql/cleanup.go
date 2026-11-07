package disclosuresql

import (
	"context"
	"time"
)

// Failure cleanup gets its own short deadline at defer execution, even when
// the operation context has expired. pgx discards connections on rollback
// failure; no background cleanup may wait indefinitely on a stalled peer.
func rollback(tx interface{ Rollback(context.Context) error }) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_ = tx.Rollback(ctx)
}
func closeConnection(conn interface{ Close(context.Context) error }) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_ = conn.Close(ctx)
}
