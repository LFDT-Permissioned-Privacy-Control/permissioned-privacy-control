package disclosuresql

import (
	"context"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	c "privacy-proxy/internal/disclosurecase"
)

type Retention struct {
	Events, Cases, CleanupInterval time.Duration
	Batch                          int
}

func DefaultRetention() Retention {
	return Retention{Events: 7 * 365 * 24 * time.Hour, Cases: 7 * 365 * 24 * time.Hour, CleanupInterval: time.Hour, Batch: 1000}
}
func (r Retention) Valid() bool {
	return r.Events > 0 && r.Cases >= 30*24*time.Hour && r.CleanupInterval > 0 && r.Batch > 0 && r.Batch <= 1000
}

// RetentionFromEnv follows the deployment RETENTION_* duration pattern without
// coupling this adapter to legacy configuration or policy projections.
func RetentionFromEnv(getenv func(string) string) (Retention, error) {
	r := DefaultRetention()
	if getenv == nil {
		return r, c.ErrInvalid
	}
	for _, entry := range []struct {
		name   string
		target *time.Duration
	}{{"RETENTION_DISCLOSURE_EVENTS", &r.Events}, {"RETENTION_DISCLOSURE_CASES", &r.Cases}, {"RETENTION_CLEANUP_INTERVAL", &r.CleanupInterval}} {
		if raw := getenv(entry.name); raw != "" {
			value, err := time.ParseDuration(raw)
			if err != nil {
				return Retention{}, c.ErrInvalid
			}
			*entry.target = value
		}
	}
	if raw := getenv("RETENTION_DISCLOSURE_CLEANUP_BATCH"); raw != "" {
		value, err := strconv.Atoi(raw)
		if err != nil {
			return Retention{}, c.ErrInvalid
		}
		r.Batch = value
	}
	if !r.Valid() {
		return Retention{}, c.ErrInvalid
	}
	return r, nil
}

// CleanupOnce runs under separate retention credentials. It removes one bounded
// batch from each table, never cascades into audit and never touches live cases.
func CleanupOnce(ctx context.Context, dsn string, now time.Time, r Retention) (events, cases int64, err error) {
	if strings.TrimSpace(dsn) == "" || !r.Valid() {
		return 0, 0, c.ErrInvalid
	}
	ctx, cancel := bounded(ctx)
	defer cancel()
	config, err := pgx.ParseConfig(dsn)
	if err != nil {
		return 0, 0, c.ErrUnavailable
	}
	config.ConnectTimeout = 3 * time.Second
	conn, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		return 0, 0, c.ErrUnavailable
	}
	defer closeConnection(conn)
	if err := checkSchema(ctx, conn); err != nil {
		return 0, 0, err
	}
	tx, err := conn.Begin(ctx)
	if err != nil {
		return 0, 0, c.ErrUnavailable
	}
	defer rollback(tx)
	if _, err := tx.Exec(ctx, `SELECT set_config('lock_timeout','1s',true),set_config('statement_timeout','3s',true)`); err != nil {
		return 0, 0, c.ErrUnavailable
	}
	tag, err := tx.Exec(ctx, `DELETE FROM ops_v2.disclosure_events WHERE event_id IN(SELECT event_id FROM ops_v2.disclosure_events WHERE prepared_at<$1 ORDER BY prepared_at,event_id LIMIT $2)`, now.Add(-r.Events), r.Batch)
	if err != nil {
		return 0, 0, c.ErrUnavailable
	}
	events = tag.RowsAffected()
	tag, err = tx.Exec(ctx, `DELETE FROM ops_v2.disclosure_cases WHERE case_id IN(SELECT c.case_id FROM ops_v2.disclosure_cases c WHERE c.expires_at<$1 AND c.expires_at<$2 AND NOT EXISTS(SELECT 1 FROM ops_v2.disclosure_events e WHERE e.case_id=c.case_id) ORDER BY c.expires_at,c.case_id LIMIT $3)`, now.Add(-r.Cases), now, r.Batch)
	if err != nil {
		return 0, 0, c.ErrUnavailable
	}
	cases = tag.RowsAffected()
	if tx.Commit(ctx) != nil {
		return 0, 0, c.ErrUnavailable
	}
	return events, cases, nil
}
