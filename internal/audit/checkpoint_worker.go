package audit

import (
	"context"
	"log/slog"
	"time"
)

// CheckpointStore is the persistence the checkpoint worker needs. A server-side
// adapter implements it over *db.DB (the audit package must not import db).
type CheckpointStore interface {
	// ChainStats returns the chain's current row count and head (id, entry_hash).
	ChainStats(ctx context.Context, chainName string) (rowCount, headID int64, headHash string, err error)
	// WriteCheckpoint persists a signed checkpoint (append-only).
	WriteCheckpoint(ctx context.Context, c Checkpoint) error
}

// CheckpointReader returns the latest signed checkpoint for a chain (nil if
// none). Used by the Verifier's truncation guard.
type CheckpointReader interface {
	LatestCheckpoint(ctx context.Context, chainName string) (*Checkpoint, error)
}

// CheckpointWorker periodically signs a roll-up of each chain's head + row
// count, so the verifier can detect tail truncation (RD-1112 #8). It is the
// single signer of checkpoints; the signing key lives behind the Signer
// interface (HMAC for MVP, KMS in production).
type CheckpointWorker struct {
	store    CheckpointStore
	signer   Signer
	chains   []ChainName
	interval time.Duration
	done     chan struct{}
}

// NewCheckpointWorker constructs a worker. interval defaults to 1m.
func NewCheckpointWorker(store CheckpointStore, signer Signer, chains []ChainName, interval time.Duration) *CheckpointWorker {
	if interval <= 0 {
		interval = time.Minute
	}
	return &CheckpointWorker{store: store, signer: signer, chains: chains, interval: interval, done: make(chan struct{})}
}

// Wait blocks until Run has returned.
func (w *CheckpointWorker) Wait() { <-w.done }

// Run signs checkpoints for all chains every interval until ctx is cancelled
// (once immediately on start).
func (w *CheckpointWorker) Run(ctx context.Context) {
	defer close(w.done)
	t := time.NewTicker(w.interval)
	defer t.Stop()
	for {
		for _, chain := range w.chains {
			if err := w.Checkpoint(ctx, chain); err != nil {
				slog.Error("audit checkpoint failed (will retry next interval)", "chain", chain, "error", err)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// Checkpoint signs and writes one checkpoint for chain. Empty chains are
// skipped (nothing to anchor yet).
func (w *CheckpointWorker) Checkpoint(ctx context.Context, chain ChainName) error {
	rowCount, headID, headHash, err := w.store.ChainStats(ctx, string(chain))
	if err != nil {
		return err
	}
	if rowCount == 0 {
		return nil
	}
	c := Checkpoint{
		ChainName: string(chain),
		HeadID:    headID,
		HeadHash:  headHash,
		RowCount:  rowCount,
		CreatedAt: time.Now().UTC(),
	}
	if err := SignCheckpoint(w.signer, &c); err != nil {
		return err
	}
	return w.store.WriteCheckpoint(ctx, c)
}

// checkpointTruncated reports whether the chain has been tail-truncated since
// the given signed checkpoint: the current head id must not have regressed
// below the checkpointed head. (Middle-row deletion / modification is caught by
// the hash walk; this guard covers tail truncation, which the walk cannot see.)
// Pure decision so it is unit-testable without a database.
func checkpointTruncated(c *Checkpoint, curHeadValid bool, curHeadID int64) bool {
	if c == nil {
		return false // no checkpoint to enforce yet
	}
	if !curHeadValid {
		// Checkpoint says there were rows up to c.HeadID, but the chain is now
		// empty → truncated.
		return c.HeadID > 0
	}
	return curHeadID < c.HeadID
}
