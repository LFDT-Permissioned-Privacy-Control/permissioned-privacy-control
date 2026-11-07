package admissionsql

import (
	"context"
	"strconv"
	"time"

	a "privacy-proxy/internal/admission"
)

type Retention struct {
	Logs, Records, Interval time.Duration
	Batch                   int
}

func RetentionFromEnv(getenv func(string) string) (Retention, error) {
	r := Retention{Logs: 7 * 365 * 24 * time.Hour, Records: 7 * 365 * 24 * time.Hour, Interval: time.Hour, Batch: 1000}
	if getenv == nil {
		return r, a.ErrInvalid
	}
	for _, x := range []struct {
		key    string
		target *time.Duration
		zero   bool
	}{{"RETENTION_COMPLIANCE_LOGS", &r.Logs, true}, {"RETENTION_TRAVEL_RECORDS", &r.Records, true}, {"RETENTION_CLEANUP_INTERVAL", &r.Interval, false}} {
		if raw := getenv(x.key); raw != "" {
			d, err := time.ParseDuration(raw)
			if err != nil || d < 0 || d == 0 && !x.zero {
				return r, a.ErrInvalid
			}
			*x.target = d
		}
	}
	if raw := getenv("RETENTION_COMPLIANCE_CLEANUP_BATCH"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 || n > 1000 || strconv.Itoa(n) != raw {
			return r, a.ErrInvalid
		}
		r.Batch = n
	}
	return r, nil
}

// CleanupOnce retains every used record and its events, and every qualified
// origin/share/witness. Automatic retirement needs a separate qualified archive
// and finality protocol. A zero horizon means keep forever.
func (s *Store) CleanupOnce(ctx context.Context, network a.Digest, expected a.ExpectedState, at time.Time, r Retention) (int64, error) {
	if s.mode != "retention" || r.Batch < 1 || r.Batch > 1000 || r.Logs < 0 || r.Records < 0 || at.IsZero() {
		return 0, a.ErrInvalid
	}
	ctx, cancel := bounded(ctx)
	defer cancel()
	tx, err := begin(ctx, s.pool, false)
	if err != nil {
		return 0, err
	}
	defer rollback(tx)
	if err := state(ctx, tx, network, expected); err != nil {
		return 0, err
	}
	var total int64
	if r.Logs > 0 {
		tag, err := tx.Exec(ctx, `DELETE FROM ops_admission_v2.compliance_events WHERE id IN(SELECT id FROM ops_admission_v2.compliance_events WHERE network_key=$1 AND decision_at<$2 AND record_id IS NULL ORDER BY decision_at,id LIMIT $3)`, network[:], at.Add(-r.Logs), r.Batch)
		if err != nil {
			return 0, a.ErrUnavailable
		}
		total = tag.RowsAffected()
	}
	if r.Records > 0 && total < int64(r.Batch) {
		tag, err := tx.Exec(ctx, `DELETE FROM ops_admission_v2.travel_records WHERE id IN(SELECT id FROM ops_admission_v2.travel_records WHERE network_key=$1 AND used_at IS NULL AND expires_at<=$2 AND created_at<$3 ORDER BY created_at,id LIMIT $4)`, network[:], at, at.Add(-r.Records), r.Batch-int(total))
		if err != nil {
			return 0, a.ErrUnavailable
		}
		total += tag.RowsAffected()
	}
	if err := state(ctx, tx, network, expected); err != nil {
		return 0, err
	}
	if tx.Commit(ctx) != nil {
		return 0, a.ErrUnavailable
	}
	return total, nil
}
