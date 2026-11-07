package walletsql

import (
	"context"
	"strconv"
	"time"

	w "privacy-proxy/internal/walletops"
)

type Retention struct {
	Interval time.Duration
	Batch    int
}

func RetentionFromEnv(getenv func(string) string) (Retention, error) {
	r := Retention{time.Minute, 1000}
	if getenv == nil {
		return r, w.ErrInvalid
	}
	if raw := getenv("RETENTION_WALLET_CHALLENGES_CLEANUP_INTERVAL"); raw != "" {
		d, err := time.ParseDuration(raw)
		if err != nil || d <= 0 {
			return r, w.ErrInvalid
		}
		r.Interval = d
	}
	if raw := getenv("RETENTION_WALLET_CHALLENGES_CLEANUP_BATCH"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 || n > 1000 || strconv.Itoa(n) != raw {
			return r, w.ErrInvalid
		}
		r.Batch = n
	}
	return r, nil
}

// CleanupOnce can delete expired challenges only. Ownership and revocation
// history have no automatic age-based deletion or resurrection mechanism.
func (s *Store) CleanupOnce(ctx context.Context, at time.Time, batch int) (int64, error) {
	if s.mode != "retention" || batch < 1 || batch > 1000 {
		return 0, w.ErrInvalid
	}
	ctx, cancel := bounded(ctx)
	defer cancel()
	tx, err := begin(ctx, s.pool)
	if err != nil {
		return 0, err
	}
	defer rollback(tx)
	tag, err := tx.Exec(ctx, `DELETE FROM ops_wallet_v2.wallet_challenges WHERE(namespace,generation,nonce)IN(SELECT namespace,generation,nonce FROM ops_wallet_v2.wallet_challenges WHERE expires_at<=$1 ORDER BY expires_at LIMIT $2)`, at, batch)
	if err != nil {
		return 0, w.ErrUnavailable
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, w.ErrUnavailable
	}
	return tag.RowsAffected(), nil
}
