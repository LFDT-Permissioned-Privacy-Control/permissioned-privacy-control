package activitysql

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"time"

	"github.com/jackc/pgx/v5"
	a "privacy-proxy/internal/activitylog"
	"privacy-proxy/internal/audit"
)

// FinalizeRecovery performs the expensive exact retained-chain recount only
// while drained and unready. Acknowledgement is an operator assertion about the
// restored SQL/range set, not evidence that every producer's spool was supplied.
// Recorder startup separately checks its exclusive original local spool.
func FinalizeRecovery(ctx context.Context, dsn string, scope Scope, acknowledge bool, timeout time.Duration) error {
	if !acknowledge || !scope.Valid() || timeout < 0 || timeout > 30*time.Minute {
		return a.ErrInvalid
	}
	if timeout == 0 {
		timeout = 10 * time.Minute
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return ownerTx(ctx, dsn, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT set_config('statement_timeout','30s',true),set_config('work_mem','4MB',true),set_config('max_parallel_workers_per_gather','0',true)`); err != nil {
			return a.ErrUnavailable
		}
		s, err := ownerSelected(ctx, tx, scope)
		if err != nil {
			return err
		}
		if s.ready || s.pruneThrough != nil {
			return a.ErrConflict
		}
		if err := validateRuns(ctx, tx, s); err != nil {
			return err
		}
		last, prev, err := anchor(ctx, tx, s.chain)
		if err != nil {
			return err
		}
		if last > s.headID {
			return a.ErrUnavailable
		}
		var count, bytes int64
		for {
			rows, err := tx.Query(ctx, `SELECT `+logColumns+` FROM public.access_logs WHERE chain_name=$1 AND id>$2 ORDER BY id LIMIT 1024`, s.chain, last)
			if err != nil {
				return a.ErrUnavailable
			}
			page := make([]logRow, 0, 1024)
			ids := make([]string, 0, 1024)
			for rows.Next() {
				l, err := scanLog(rows)
				if err != nil {
					rows.Close()
					return err
				}
				page = append(page, l)
				ids = append(ids, l.run)
			}
			err = rows.Err()
			rows.Close()
			if err != nil {
				return a.ErrUnavailable
			}
			if len(page) == 0 {
				break
			}
			runs, err := loadRuns(ctx, tx, ids)
			if err != nil {
				return err
			}
			for _, l := range page {
				if l.id <= last || !registered(runs[l.run], l.envelope, uint64(l.seq), s) {
					return a.ErrUnavailable
				}
				content := audit.AccessLogChainContentV2(l.id, l.actor, l.method, l.ip, l.status, l.http, l.at, l.correlation, l.params)
				h := sha256.Sum256([]byte(prev + content))
				if hex.EncodeToString(h[:]) != l.hash {
					return a.ErrUnavailable
				}
				if count >= s.limits.Rows || int64(len(l.params)) > s.limits.Bytes-bytes {
					return a.ErrTooBroad
				}
				count++
				bytes += int64(len(l.params))
				last = l.id
				prev = l.hash
			}
		}
		if count != s.rows || bytes != s.bytes || last != s.headID || prev != s.headHash {
			return a.ErrUnavailable
		}
		if err := checkIDAllocator(ctx, tx); err != nil {
			return err
		}
		// A restored allocator must already be strictly beyond every registered
		// range and stored sequence. Recovery never silently calls setval.
		var next, registeredMax, storedMax int64
		if tx.QueryRow(ctx, `SELECT last_value+CASE WHEN is_called THEN 1 ELSE 0 END FROM public.access_logs_buffer_range_seq`).Scan(&next) != nil || tx.QueryRow(ctx, `SELECT COALESCE(max(range_index),0) FROM ops_activity_v1.runs`).Scan(&registeredMax) != nil || tx.QueryRow(ctx, `SELECT COALESCE(max(buffer_seq),0)>>40 FROM public.access_logs`).Scan(&storedMax) != nil || next <= max(registeredMax, storedMax) || next < 1 || next > 8388607 {
			return a.ErrUnavailable
		}
		tag, err := tx.Exec(ctx, `UPDATE ops_activity_v1.sources SET ready=true WHERE network_key=$1 AND source_id=$2::uuid AND generation=$3::uuid AND NOT ready AND prune_through_id IS NULL`, scope.NetworkKey[:], scope.SourceID, scope.ExpectedGeneration)
		if err != nil || tag.RowsAffected() != 1 {
			return a.ErrUnavailable
		}
		return nil
	})
}

// A table-only restore must not mark ready with an ID sequence behind retained
// or anchored heads. Owner-only qualification never silently calls setval.
// One statement uses the same MVCC snapshot for all global committed heads.
func checkIDAllocator(ctx context.Context, q queryer) error {
	var last, head int64
	var called bool
	if q.QueryRow(ctx, `SELECT last_value,is_called,GREATEST(COALESCE((SELECT max(id)FROM public.access_logs),0),COALESCE((SELECT max(head_id)FROM ops_activity_v1.sources),0),COALESCE((SELECT max(last_pruned_id)FROM public.audit_chain_anchor),0))FROM public.access_logs_id_seq`).Scan(&last, &called, &head) != nil || last < 1 || last == 1<<63-1 && called {
		return a.ErrUnavailable
	}
	next := last
	if called {
		next++
	}
	if next <= head {
		return a.ErrUnavailable
	}
	return nil
}
func validateRuns(ctx context.Context, q queryer, s sourceState) error {
	var after string
	var count int64
	for {
		rows, err := q.Query(ctx, `SELECT run_id::text,producer_id::text,chain_name,generation::text,network_key,configuration,range_index,registered_at FROM ops_activity_v1.runs WHERE network_key=$1 AND ($2='' OR run_id>NULLIF($2,'')::uuid) ORDER BY run_id LIMIT 1024`, s.metadata.NetworkKey[:], after)
		if err != nil {
			return a.ErrUnavailable
		}
		n := 0
		for rows.Next() {
			var id, producer, chain, generation string
			var net, config []byte
			var index int64
			var at time.Time
			if rows.Scan(&id, &producer, &chain, &generation, &net, &config, &index, &at) != nil || !a.CanonicalUUID(id) || !a.CanonicalUUID(producer) || !a.CanonicalUUID(generation) || len(net) != 32 || len(config) != 32 || hex.EncodeToString(net) != hex.EncodeToString(s.metadata.NetworkKey[:]) || chain != s.chain || index < 1 || index > 8388607 || at.UnixMicro() < 0 || at.UnixMicro() > a.MaxObservedMicros || at.Nanosecond()%1000 != 0 {
				rows.Close()
				return a.ErrUnavailable
			}
			count++
			if count > s.limits.Runs {
				rows.Close()
				return a.ErrTooBroad
			}
			after = id
			n++
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return a.ErrUnavailable
		}
		if n < 1024 {
			return nil
		}
	}
}
