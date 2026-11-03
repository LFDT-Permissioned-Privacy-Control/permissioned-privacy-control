package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// trackingMaintenanceLock is the advisory lock key serializing partition
// maintenance across OPS instances sharing a tracking database.
const trackingMaintenanceLock = 0x4f50535f45584543 // "OPS_EXEC"

// trackingPartitioned are the daily-partitioned tracking tables and their
// partition key.
var trackingPartitioned = []struct{ table, column string }{
	{"node_tx_status", "final_at"},
	{"node_tx_identities", "created_at"},
}

// TrackingMaintenance is the result of one maintenance run.
type TrackingMaintenance struct {
	Created, Dropped, Truncated []string
	Skipped                     bool // another instance held the maintenance lock
}

// MaintainTracking runs one maintenance pass as the owner, serialized across
// instances by an advisory lock (a concurrent pass is skipped, not queued):
//
//   - daily partitions of node_tx_status and node_tx_identities exist for
//     yesterday through today + ahead (K25), created stand-alone and then
//     attached, so the parent is locked only briefly;
//   - with retention > 0, day partitions whose day ended at least retention
//     ago are detached (CONCURRENTLY, no exclusive lock on the parent) and
//     dropped (G41); nothing inside the retention window is touched;
//   - payload buckets whose most recent use ended at least payloadKeep ago
//     are truncated: no identity created in them can still be valid.
//
// Every DDL statement runs with a lock timeout, so maintenance never queues
// request-path work behind it for long; a timed-out step is retried next run.
func (e *ExecAdminDB) MaintainTracking(ctx context.Context, ahead int, retention, payloadKeep time.Duration) (TrackingMaintenance, error) {
	var out TrackingMaintenance
	conn, err := e.pool.conn.Conn(ctx)
	if err != nil {
		return out, err
	}
	defer conn.Close()
	var locked bool
	if err := conn.QueryRowContext(ctx, `SELECT pg_try_advisory_lock($1)`, int64(trackingMaintenanceLock)).Scan(&locked); err != nil {
		return out, err
	}
	if !locked {
		out.Skipped = true
		return out, nil
	}
	defer conn.ExecContext(context.WithoutCancel(ctx), `SELECT pg_advisory_unlock($1)`, int64(trackingMaintenanceLock))
	if _, err := conn.ExecContext(ctx, `SET lock_timeout = '2s'`); err != nil {
		return out, err
	}
	defer conn.ExecContext(context.WithoutCancel(ctx), `RESET lock_timeout`)
	var now time.Time
	if err := conn.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return out, err
	}
	now = now.UTC()
	today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	var errs []error
	for _, p := range trackingPartitioned {
		for d := -1; d <= ahead; d++ {
			day := today.AddDate(0, 0, d)
			created, err := ensureDayPartition(ctx, conn, p.table, p.column, day)
			if err != nil {
				errs = append(errs, err)
				continue
			}
			if created {
				out.Created = append(out.Created, partitionName(p.table, day))
			}
		}
		if retention <= 0 {
			continue
		}
		dropped, err := dropExpiredPartitions(ctx, conn, p.table, now.Add(-retention))
		out.Dropped = append(out.Dropped, dropped...)
		if err != nil {
			errs = append(errs, err)
		}
	}
	truncated, err := truncateExpiredBuckets(ctx, conn, payloadKeep)
	out.Truncated = truncated
	if err != nil {
		errs = append(errs, err)
	}
	return out, errors.Join(errs...)
}

func partitionName(table string, day time.Time) string {
	return table + "_" + day.Format("20060102")
}

// ensureDayPartition creates and attaches the [day, day+1) partition of table
// if it is missing. A table left unattached by an interrupted run is attached.
func ensureDayPartition(ctx context.Context, conn *sql.Conn, table, column string, day time.Time) (bool, error) {
	name := partitionName(table, day)
	from, to := day.Format(time.RFC3339), day.AddDate(0, 0, 1).Format(time.RFC3339)
	var exists, attached bool
	if err := conn.QueryRowContext(ctx, `SELECT to_regclass($1) IS NOT NULL, EXISTS (SELECT 1 FROM pg_inherits WHERE inhrelid = to_regclass($1) AND inhparent = to_regclass($2))`, name, table).Scan(&exists, &attached); err != nil {
		return false, err
	}
	if attached {
		return false, nil
	}
	if !exists {
		// The range CHECK lets ATTACH skip its validation scan.
		if _, err := conn.ExecContext(ctx, fmt.Sprintf(`CREATE TABLE %[1]s (LIKE %[2]s INCLUDING DEFAULTS INCLUDING CONSTRAINTS);
ALTER TABLE %[1]s ADD CONSTRAINT %[1]s_range CHECK (%[3]s >= '%[4]s' AND %[3]s < '%[5]s')`, name, table, column, from, to)); err != nil {
			return false, fmt.Errorf("create partition %s: %w", name, err)
		}
	}
	if _, err := conn.ExecContext(ctx, fmt.Sprintf(`ALTER TABLE %s ATTACH PARTITION %s FOR VALUES FROM ('%s') TO ('%s')`, table, name, from, to)); err != nil {
		return false, fmt.Errorf("attach partition %s: %w", name, err)
	}
	return true, nil
}

// dropExpiredPartitions detaches and drops the day partitions of table whose
// upper bound is at or before cutoff.
func dropExpiredPartitions(ctx context.Context, conn *sql.Conn, table string, cutoff time.Time) ([]string, error) {
	rows, err := conn.QueryContext(ctx, `SELECT c.relname, i.inhdetachpending FROM pg_inherits i JOIN pg_class c ON c.oid = i.inhrelid WHERE i.inhparent = to_regclass($1) ORDER BY c.relname`, table)
	if err != nil {
		return nil, err
	}
	type part struct {
		name    string
		pending bool
	}
	var parts []part
	for rows.Next() {
		var p part
		if err := rows.Scan(&p.name, &p.pending); err != nil {
			rows.Close()
			return nil, err
		}
		parts = append(parts, p)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	var dropped []string
	for _, p := range parts {
		if len(p.name) != len(table)+9 || !strings.HasPrefix(p.name, table+"_") {
			continue // not one of ours
		}
		day, err := time.Parse("20060102", p.name[len(table)+1:])
		if err != nil {
			continue
		}
		if day.AddDate(0, 0, 1).After(cutoff) {
			continue
		}
		name := pgx.Identifier{p.name}.Sanitize()
		detach := `ALTER TABLE %s DETACH PARTITION %s CONCURRENTLY`
		if p.pending {
			detach = `ALTER TABLE %s DETACH PARTITION %s FINALIZE`
		}
		if _, err := conn.ExecContext(ctx, fmt.Sprintf(detach, pgx.Identifier{table}.Sanitize(), name)); err != nil {
			return dropped, fmt.Errorf("detach partition %s: %w", p.name, err)
		}
		if _, err := conn.ExecContext(ctx, `DROP TABLE `+name); err != nil {
			return dropped, fmt.Errorf("drop partition %s: %w", p.name, err)
		}
		dropped = append(dropped, p.name)
	}
	// Detached by an interrupted earlier run (detach done, drop not).
	orphans, err := conn.QueryContext(ctx, `SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
 WHERE n.nspname = current_schema() AND c.relkind = 'r' AND c.relname LIKE $1 || '\_%' AND NOT c.relispartition`, table)
	if err != nil {
		return dropped, err
	}
	var names []string
	for orphans.Next() {
		var name string
		if err := orphans.Scan(&name); err != nil {
			orphans.Close()
			return dropped, err
		}
		names = append(names, name)
	}
	orphans.Close()
	for _, name := range names {
		if len(name) != len(table)+9 {
			continue
		}
		day, err := time.Parse("20060102", name[len(table)+1:])
		if err != nil || day.AddDate(0, 0, 1).After(cutoff) {
			continue
		}
		if _, err := conn.ExecContext(ctx, `DROP TABLE `+pgx.Identifier{name}.Sanitize()); err != nil {
			return dropped, fmt.Errorf("drop detached partition %s: %w", name, err)
		}
		dropped = append(dropped, name)
	}
	return dropped, nil
}

// TrackingPartitionsReady reports whether today's and tomorrow's partitions
// of every partitioned tracking table exist (finalization depends on them).
func (e *ExecAdminDB) TrackingPartitionsReady(ctx context.Context) (bool, error) {
	var now time.Time
	if err := e.pool.conn.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return false, err
	}
	now = now.UTC()
	today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	for _, p := range trackingPartitioned {
		for d := 0; d <= 1; d++ {
			var ok bool
			if err := e.pool.conn.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM pg_inherits WHERE inhrelid = to_regclass($1) AND inhparent = to_regclass($2))`, partitionName(p.table, today.AddDate(0, 0, d)), p.table).Scan(&ok); err != nil || !ok {
				return false, err
			}
		}
	}
	return true, nil
}

// truncateExpiredBuckets truncates payload buckets whose most recent fifteen
// minutes ended at least keep ago, on the database clock that assigned them.
// The current and the previous bucket are never truncated.
func truncateExpiredBuckets(ctx context.Context, conn *sql.Conn, keep time.Duration) ([]string, error) {
	if keep < 15*time.Minute {
		keep = 15 * time.Minute
	}
	var nowSec float64
	if err := conn.QueryRowContext(ctx, `SELECT extract(epoch FROM clock_timestamp())::float8`).Scan(&nowSec); err != nil {
		return nil, err
	}
	current := int64(nowSec) / 900
	var truncated []string
	var errs []error
	for b := int64(0); b < 16; b++ {
		// The most recent absolute bucket index mapped to b.
		last := current - ((current-b)%16+16)%16
		// Never the current, the previous or the next bucket (the next one
		// becomes current within fifteen minutes, possibly during this pass).
		if last >= current-1 || last <= current-15 || float64((last+1)*900) > nowSec-keep.Seconds() {
			continue
		}
		name := fmt.Sprintf("node_tx_payload_%d", b)
		var any bool
		if err := conn.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM `+name+`)`).Scan(&any); err != nil {
			errs = append(errs, err)
			continue
		}
		if !any {
			continue
		}
		if _, err := conn.ExecContext(ctx, `TRUNCATE `+name); err != nil {
			errs = append(errs, fmt.Errorf("truncate %s: %w", name, err))
			continue
		}
		truncated = append(truncated, name)
	}
	return truncated, errors.Join(errs...)
}
