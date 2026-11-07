package activitysql

import (
	"context"
	"time"

	a "privacy-proxy/internal/activitylog"
)

// Prune removes only an eligible chain PREFIX. An older observation appearing
// after a newer row is retained until that newer prefix also becomes eligible.
// No run registration is removed: even an unsealed run may own durable spool.
func (r *Retention) Prune(ctx context.Context, requestedFloor int64, batch int) (int, error) {
	if r == nil || r.store == nil || requestedFloor < 0 || requestedFloor > a.MaxObservedMicros || batch < 1 || batch > 5000 {
		return 0, a.ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	tx, err := begin(ctx, r.pool, false)
	if err != nil {
		return 0, err
	}
	defer rollback(tx)
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1::bigint)`, r.state.lock); err != nil {
		return 0, a.ErrUnavailable
	}
	s, err := selected(ctx, tx, r.scope, true, true)
	if err != nil {
		return 0, err
	}
	if s.metadata != r.state.metadata || s.roles != r.state.roles {
		return 0, a.ErrUnavailable
	}
	if err := checkSchema(ctx, tx); err != nil {
		return 0, err
	}
	if err := checkRole(ctx, tx, s.roles, "retention"); err != nil {
		return 0, err
	}
	if err := checkHead(ctx, tx, s, "retention"); err != nil {
		return 0, err
	}
	floor := max(requestedFloor, s.floor)
	rows, err := tx.Query(ctx, `SELECT id,activity_observed_us,encoded_bytes,entry_hash FROM ops_activity_v1.prunable_logs WHERE chain_name=$1 ORDER BY id LIMIT $2`, s.chain, batch)
	if err != nil {
		return 0, a.ErrUnavailable
	}
	var through, size int64
	hash := ""
	count := 0
	for rows.Next() {
		var id, observed, bytes int64
		var h string
		if rows.Scan(&id, &observed, &bytes, &h) != nil || id <= through || observed < 0 || observed > a.MaxObservedMicros || bytes < 1 || bytes > a.MaxEncodedBytes {
			rows.Close()
			return 0, a.ErrUnavailable
		}
		if _, err := a.ParseDigestHex(h); err != nil {
			rows.Close()
			return 0, a.ErrUnavailable
		}
		if observed >= floor {
			break
		}
		through = id
		hash = h
		size += bytes
		count++
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return 0, a.ErrUnavailable
	}
	if count == 0 {
		tag, err := tx.Exec(ctx, `UPDATE ops_activity_v1.sources SET retained_from_us=$2 WHERE network_key=$1 AND generation=$3::uuid AND ready AND prune_through_id IS NULL`, r.scope.NetworkKey[:], floor, r.scope.ExpectedGeneration)
		if err != nil || tag.RowsAffected() != 1 {
			return 0, a.ErrUnavailable
		}
		if tx.Commit(ctx) != nil {
			return 0, a.ErrUnavailable
		}
		return 0, nil
	}
	if int64(count) > s.rows || size > s.bytes || through > s.headID {
		return 0, a.ErrUnavailable
	}
	tag, err := tx.Exec(ctx, `UPDATE ops_activity_v1.sources SET retained_from_us=$2,prune_through_id=$3 WHERE network_key=$1 AND generation=$4::uuid AND ready AND prune_through_id IS NULL`, r.scope.NetworkKey[:], floor, through, r.scope.ExpectedGeneration)
	if err != nil || tag.RowsAffected() != 1 {
		return 0, a.ErrUnavailable
	}
	tag, err = tx.Exec(ctx, `DELETE FROM ops_activity_v1.prunable_logs WHERE chain_name=$1 AND id<=$2`, s.chain, through)
	if err != nil || tag.RowsAffected() != int64(count) {
		return 0, a.ErrUnavailable
	}
	previous, _, err := anchor(ctx, tx, s.chain)
	if err != nil {
		return 0, err
	}
	if previous >= through {
		return 0, a.ErrUnavailable
	}
	if previous == 0 {
		tag, err = tx.Exec(ctx, `INSERT INTO ops_activity_v1.anchors(chain_name,last_pruned_id,last_pruned_entry_hash,last_pruned_at)VALUES($1,$2,$3,clock_timestamp())`, s.chain, through, hash)
	} else {
		tag, err = tx.Exec(ctx, `UPDATE ops_activity_v1.anchors SET last_pruned_id=$2,last_pruned_entry_hash=$3,last_pruned_at=clock_timestamp() WHERE chain_name=$1 AND last_pruned_id=$4`, s.chain, through, hash, previous)
		if err == nil && tag.RowsAffected() != 1 {
			return 0, a.ErrUnavailable
		}
	}
	if err != nil || tag.RowsAffected() != 1 {
		return 0, a.ErrUnavailable
	}
	tag, err = tx.Exec(ctx, `UPDATE ops_activity_v1.sources SET row_count=row_count-$2,byte_count=byte_count-$3,prune_through_id=NULL WHERE network_key=$1 AND generation=$4::uuid AND prune_through_id=$5`, r.scope.NetworkKey[:], count, size, r.scope.ExpectedGeneration, through)
	if err != nil || tag.RowsAffected() != 1 {
		return 0, a.ErrUnavailable
	}
	if tx.Commit(ctx) != nil {
		return 0, a.ErrUnavailable
	}
	return count, nil
}
