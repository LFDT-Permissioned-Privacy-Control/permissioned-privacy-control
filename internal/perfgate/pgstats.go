package perfgate

import (
	"context"
	"database/sql"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib" // database/sql driver "pgx"
)

// DBCounters is one database's cumulative pg_stat_database counters.
type DBCounters struct {
	Commits   int64 `json:"commits"`
	Rollbacks int64 `json:"rollbacks"`
	Inserted  int64 `json:"tup_inserted"`
	Updated   int64 `json:"tup_updated"`
	Deleted   int64 `json:"tup_deleted"`
}

// WALCounters is pg_stat_wal plus checkpoint activity.
type WALCounters struct {
	Records           int64   `json:"wal_records"`
	FPI               int64   `json:"wal_fpi"`
	Bytes             int64   `json:"wal_bytes"`
	BuffersFull       int64   `json:"wal_buffers_full"`
	Writes            int64   `json:"wal_write"`
	Syncs             int64   `json:"wal_sync"`
	WriteMS           float64 `json:"wal_write_time_ms"`
	SyncMS            float64 `json:"wal_sync_time_ms"`
	CheckpointsTimed  int64   `json:"checkpoints_timed"`
	CheckpointsReq    int64   `json:"checkpoints_req"`
	BuffersCheckpoint int64   `json:"buffers_checkpoint"`
	BuffersBackend    int64   `json:"buffers_backend"`
}

// ClusterSnapshot is everything sampled from one Postgres instance at one instant.
type ClusterSnapshot struct {
	At        time.Time             `json:"at"`
	Databases map[string]DBCounters `json:"databases"`
	WALBytes  int64                 `json:"wal_bytes"`
	CPUMicros uint64                `json:"cpu_us"`
	// NextXID advances only for transactions that wrote (xids are assigned on
	// first write), so its delta counts write transactions cluster-wide,
	// unlike xact_commit, which also counts read-only autocommit SELECTs.
	NextXID int64       `json:"next_xid"`
	WAL     WALCounters `json:"wal"`
}

// OpenDB opens a pooled database/sql handle with the pgx driver.
func OpenDB(dsn string) (*sql.DB, error) {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(8)
	db.SetMaxIdleConns(8) // keep them: the runner must not churn host ports itself
	return db, nil
}

// SnapshotCluster reads per-database counters, the WAL position and the
// container's CPU time. stats_fetch_consistency=none keeps counters fresh.
func SnapshotCluster(ctx context.Context, admin *sql.DB, container *Container) (ClusterSnapshot, error) {
	out := ClusterSnapshot{At: time.Now(), Databases: map[string]DBCounters{}}
	if _, err := admin.ExecContext(ctx, `SELECT pg_stat_clear_snapshot()`); err != nil {
		return out, err
	}
	rows, err := admin.QueryContext(ctx, `SELECT datname, xact_commit, xact_rollback, tup_inserted, tup_updated, tup_deleted FROM pg_stat_database WHERE datname IS NOT NULL`)
	if err != nil {
		return out, err
	}
	defer rows.Close()
	for rows.Next() {
		var name string
		var c DBCounters
		if err := rows.Scan(&name, &c.Commits, &c.Rollbacks, &c.Inserted, &c.Updated, &c.Deleted); err != nil {
			return out, err
		}
		out.Databases[name] = c
	}
	if err := rows.Err(); err != nil {
		return out, err
	}
	if err := admin.QueryRowContext(ctx, `SELECT pg_wal_lsn_diff(pg_current_wal_lsn(), '0/0')::bigint, pg_snapshot_xmax(pg_current_snapshot())::text::bigint`).Scan(&out.WALBytes, &out.NextXID); err != nil {
		return out, err
	}
	w := &out.WAL
	if err := admin.QueryRowContext(ctx, `SELECT w.wal_records, w.wal_fpi, w.wal_bytes::bigint, w.wal_buffers_full, w.wal_write, w.wal_sync, w.wal_write_time, w.wal_sync_time,
 b.checkpoints_timed, b.checkpoints_req, b.buffers_checkpoint, b.buffers_backend FROM pg_stat_wal w, pg_stat_bgwriter b`).Scan(&w.Records, &w.FPI, &w.Bytes, &w.BuffersFull, &w.Writes, &w.Syncs, &w.WriteMS, &w.SyncMS, &w.CheckpointsTimed, &w.CheckpointsReq, &w.BuffersCheckpoint, &w.BuffersBackend); err != nil {
		return out, err
	}
	if container != nil {
		cpu, err := container.CPUMicros(ctx)
		if err != nil {
			return out, err
		}
		out.CPUMicros = cpu
	}
	return out, nil
}

// ClusterDelta is the difference between two snapshots.
type ClusterDelta struct {
	WriteTransactions int64                 `json:"write_transactions"`
	WAL               WALCounters           `json:"wal"`
	Seconds           float64               `json:"seconds"`
	Databases         map[string]DBCounters `json:"databases"`
	CommitsPerSec     map[string]float64    `json:"commits_per_second"`
	WALBytes          int64                 `json:"wal_bytes"`
	CPUSeconds        float64               `json:"cpu_seconds"`
	CPUUtilisation    float64               `json:"cpu_cores_busy"`
}

// Delta subtracts a from b (b later).
func Delta(a, b ClusterSnapshot) ClusterDelta {
	out := ClusterDelta{Seconds: b.At.Sub(a.At).Seconds(), Databases: map[string]DBCounters{}, CommitsPerSec: map[string]float64{}, WALBytes: b.WALBytes - a.WALBytes}
	for name, after := range b.Databases {
		before := a.Databases[name]
		d := DBCounters{Commits: after.Commits - before.Commits, Rollbacks: after.Rollbacks - before.Rollbacks, Inserted: after.Inserted - before.Inserted, Updated: after.Updated - before.Updated, Deleted: after.Deleted - before.Deleted}
		out.Databases[name] = d
		if out.Seconds > 0 {
			out.CommitsPerSec[name] = float64(d.Commits) / out.Seconds
		}
	}
	out.WriteTransactions = b.NextXID - a.NextXID
	out.WAL = WALCounters{Records: b.WAL.Records - a.WAL.Records, FPI: b.WAL.FPI - a.WAL.FPI, Bytes: b.WAL.Bytes - a.WAL.Bytes, BuffersFull: b.WAL.BuffersFull - a.WAL.BuffersFull,
		Writes: b.WAL.Writes - a.WAL.Writes, Syncs: b.WAL.Syncs - a.WAL.Syncs, WriteMS: b.WAL.WriteMS - a.WAL.WriteMS, SyncMS: b.WAL.SyncMS - a.WAL.SyncMS,
		CheckpointsTimed: b.WAL.CheckpointsTimed - a.WAL.CheckpointsTimed, CheckpointsReq: b.WAL.CheckpointsReq - a.WAL.CheckpointsReq,
		BuffersCheckpoint: b.WAL.BuffersCheckpoint - a.WAL.BuffersCheckpoint, BuffersBackend: b.WAL.BuffersBackend - a.WAL.BuffersBackend}
	if b.CPUMicros >= a.CPUMicros {
		out.CPUSeconds = float64(b.CPUMicros-a.CPUMicros) / 1e6
	}
	if out.Seconds > 0 {
		out.CPUUtilisation = out.CPUSeconds / out.Seconds
	}
	return out
}

// Statement is one pg_stat_statements row.
type Statement struct {
	Database string  `json:"database"`
	Query    string  `json:"query"`
	Calls    int64   `json:"calls"`
	TotalMS  float64 `json:"total_ms"`
	MeanMS   float64 `json:"mean_ms"`
	Rows     int64   `json:"rows"`
}

// ResetStatements clears pg_stat_statements cluster-wide.
func ResetStatements(ctx context.Context, admin *sql.DB) error {
	_, err := admin.ExecContext(ctx, `SELECT pg_stat_statements_reset()`)
	return err
}

// TopStatements returns the n statements with the highest total execution time.
func TopStatements(ctx context.Context, admin *sql.DB, n int) ([]Statement, error) {
	rows, err := admin.QueryContext(ctx, `SELECT d.datname, left(regexp_replace(s.query, '\s+', ' ', 'g'), 240), s.calls, s.total_exec_time, s.mean_exec_time, s.rows
 FROM pg_stat_statements s JOIN pg_database d ON d.oid = s.dbid ORDER BY s.total_exec_time DESC LIMIT $1`, n)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Statement
	for rows.Next() {
		var s Statement
		if err := rows.Scan(&s.Database, &s.Query, &s.Calls, &s.TotalMS, &s.MeanMS, &s.Rows); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// WriteStatements sums INSERT/UPDATE/DELETE statement calls and rows per database.
func WriteStatements(ctx context.Context, admin *sql.DB) (map[string]map[string]int64, error) {
	rows, err := admin.QueryContext(ctx, `SELECT d.datname, lower(substring(s.query from '^\s*(\w+)')) AS verb, sum(s.calls)::bigint, sum(s.rows)::bigint
 FROM pg_stat_statements s JOIN pg_database d ON d.oid = s.dbid
 WHERE lower(substring(s.query from '^\s*(\w+)')) IN ('insert','update','delete','with') GROUP BY 1, 2`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]map[string]int64{}
	for rows.Next() {
		var database, verb string
		var calls, affected int64
		if err := rows.Scan(&database, &verb, &calls, &affected); err != nil {
			return nil, err
		}
		if out[database] == nil {
			out[database] = map[string]int64{}
		}
		out[database][verb+"_calls"] += calls
		out[database][verb+"_rows"] += affected
	}
	return out, rows.Err()
}

// WaitEvents counts active client backends by wait event (CPU = not waiting).
func WaitEvents(ctx context.Context, admin *sql.DB) (map[string]int, error) {
	rows, err := admin.QueryContext(ctx, `SELECT coalesce(wait_event_type, 'CPU') || ':' || coalesce(wait_event, 'running'), count(*)
 FROM pg_stat_activity WHERE state = 'active' AND backend_type = 'client backend' AND pid <> pg_backend_pid() GROUP BY 1`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var name string
		var n int
		if err := rows.Scan(&name, &n); err != nil {
			return nil, err
		}
		out[name] = n
	}
	return out, rows.Err()
}

// TableStats is one table's size and tuple counters.
type TableStats struct {
	Database   string `json:"database"`
	Table      string `json:"table"`
	Rows       int64  `json:"live_tuples"`
	Dead       int64  `json:"dead_tuples"`
	Inserted   int64  `json:"n_tup_ins"`
	Updated    int64  `json:"n_tup_upd"`
	HotUpdated int64  `json:"n_tup_hot_upd"`
	Deleted    int64  `json:"n_tup_del"`
	TotalBytes int64  `json:"total_bytes"`
	HeapBytes  int64  `json:"heap_bytes"`
	Autovac    int64  `json:"autovacuum_count"`
}

// LargestTables lists the n largest user tables of one database.
func LargestTables(ctx context.Context, db *sql.DB, database string, n int) ([]TableStats, error) {
	rows, err := db.QueryContext(ctx, `SELECT relname, n_live_tup, n_dead_tup, n_tup_ins, n_tup_upd, n_tup_hot_upd, n_tup_del, pg_total_relation_size(relid), pg_relation_size(relid), autovacuum_count
 FROM pg_stat_user_tables ORDER BY pg_total_relation_size(relid) DESC LIMIT $1`, n)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []TableStats
	for rows.Next() {
		t := TableStats{Database: database}
		if err := rows.Scan(&t.Table, &t.Rows, &t.Dead, &t.Inserted, &t.Updated, &t.HotUpdated, &t.Deleted, &t.TotalBytes, &t.HeapBytes, &t.Autovac); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// ProcessCPUSeconds reads a child process's cumulative CPU time via ps(1).
func ProcessCPUSeconds(pid int) (float64, error) {
	out, err := exec.Command("ps", "-o", "time=", "-p", strconv.Itoa(pid)).Output()
	if err != nil {
		return 0, err
	}
	return parsePSTime(strings.TrimSpace(string(out)))
}

// parsePSTime parses ps "time" values: [[dd-]hh:]mm:ss[.ss].
func parsePSTime(value string) (float64, error) {
	days := 0.0
	if d, rest, ok := strings.Cut(value, "-"); ok {
		n, err := strconv.ParseFloat(d, 64)
		if err != nil {
			return 0, err
		}
		days, value = n, rest
	}
	parts := strings.Split(value, ":")
	if len(parts) < 2 || len(parts) > 3 {
		return 0, fmt.Errorf("unexpected ps time %q", value)
	}
	total := 0.0
	for _, p := range parts {
		n, err := strconv.ParseFloat(p, 64)
		if err != nil {
			return 0, err
		}
		total = total*60 + n
	}
	return days*86400 + total, nil
}

// SelfCPUSeconds is this process's user+system CPU time.
func SelfCPUSeconds() float64 {
	var usage syscall.Rusage
	if syscall.Getrusage(syscall.RUSAGE_SELF, &usage) != nil {
		return 0
	}
	return time.Duration(usage.Utime.Nano() + usage.Stime.Nano()).Seconds()
}
