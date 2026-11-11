package ssosql

import (
	"context"
	"github.com/jackc/pgx/v5"
	m "privacy-proxy/internal/ssotransaction"
)

type cleanupRow struct {
	id             string
	phase          m.Phase
	context, grant int64
}

func selectCleanup(ctx context.Context, tx pgx.Tx, namespace m.Digest, now m.Micros, budget int, recovery bool) ([]cleanupRow, error) {
	result := []cleanupRow{}
	if recovery {
		rows, e := tx.Query(ctx, `SELECT id::text,phase,octet_length(context_ciphertext)::bigint,coalesce(octet_length(grant_ciphertext),0)::bigint FROM ops_sso_v1.transactions WHERE namespace=$1 AND (phase=1 OR phase=2) ORDER BY id LIMIT $2 FOR UPDATE`, namespace[:], budget)
		if e != nil {
			return nil, ErrUnavailable
		}
		defer rows.Close()
		for rows.Next() {
			var r cleanupRow
			if rows.Scan(&r.id, &r.phase, &r.context, &r.grant) != nil || !validCleanup(r) {
				return nil, ErrUnavailable
			}
			result = append(result, r)
		}
		if rows.Err() != nil {
			return nil, ErrUnavailable
		}
		return result, nil
	}
	for _, phase := range []m.Phase{m.Pending, m.Ready, m.Consumed} {
		query := `SELECT id::text,phase,coalesce(octet_length(context_ciphertext),0)::bigint,coalesce(octet_length(grant_ciphertext),0)::bigint FROM ops_sso_v1.transactions WHERE namespace=$1 AND `
		switch phase {
		case m.Pending:
			query += `phase=1 AND expires_us<=$2 ORDER BY expires_us,id`
		case m.Ready:
			query += `phase=2 AND code_expires_us<=$2 ORDER BY code_expires_us,id`
		case m.Consumed:
			query += `phase IN(3,4) AND retain_until_us<=$2 ORDER BY retain_until_us,id`
		}
		query += ` LIMIT $3 FOR UPDATE`
		rows, e := tx.Query(ctx, query, namespace[:], int64(now), budget/3)
		if e != nil {
			return nil, ErrUnavailable
		}
		for rows.Next() {
			var r cleanupRow
			if rows.Scan(&r.id, &r.phase, &r.context, &r.grant) != nil || !validCleanup(r) {
				rows.Close()
				return nil, ErrUnavailable
			}
			result = append(result, r)
		}
		e = rows.Err()
		rows.Close()
		if e != nil {
			return nil, ErrUnavailable
		}
	}
	return result, nil
}
func validCleanup(r cleanupRow) bool {
	if !m.ValidUUID(r.id) || r.context < 0 || r.context > m.MaxContextCipherBytes || r.grant < 0 || r.grant > m.MaxGrantCipherBytes {
		return false
	}
	switch r.phase {
	case m.Pending:
		return r.context >= 28 && r.grant == 0
	case m.Ready:
		return r.context >= 28 && r.grant >= 28
	case m.Consumed, m.Expired:
		return r.context == 0 && r.grant == 0
	}
	return false
}
func cleanupRows(ctx context.Context, tx pgx.Tx, ns m.Digest, rows []cleanupRow) (CleanupCounts, int64, error) {
	var counts CleanupCounts
	var bytes int64
	pending, ready, terminal := []string{}, []string{}, []string{}
	for _, r := range rows {
		bytes += r.context + r.grant
		switch r.phase {
		case m.Pending:
			pending = append(pending, r.id)
		case m.Ready:
			ready = append(ready, r.id)
		case m.Consumed, m.Expired:
			terminal = append(terminal, r.id)
		default:
			return counts, 0, ErrUnavailable
		}
	}
	for i, ids := range [][]string{pending, ready, terminal} {
		if len(ids) == 0 {
			continue
		}
		query := []string{`DELETE FROM ops_sso_v1.transactions WHERE namespace=$1 AND phase=1 AND id=ANY($2::uuid[])`, `UPDATE ops_sso_v1.transactions SET phase=4,context_ciphertext=NULL,grant_ciphertext=NULL WHERE namespace=$1 AND phase=2 AND id=ANY($2::uuid[])`, `DELETE FROM ops_sso_v1.transactions WHERE namespace=$1 AND phase IN(3,4) AND id=ANY($2::uuid[])`}[i]
		tag, e := tx.Exec(ctx, query, ns[:], ids)
		if e != nil || tag.RowsAffected() != int64(len(ids)) {
			return CleanupCounts{}, 0, ErrUnavailable
		}
	}
	counts = CleanupCounts{int64(len(pending)), int64(len(ready)), int64(len(terminal))}
	return counts, bytes, nil
}
func (s *Store) CleanupOnce(ctx context.Context, limit int) (CleanupCounts, error) {
	if limit < 3 || limit > 1000 {
		return CleanupCounts{}, ErrInvalid
	}
	ctx, cancel, tx, e := s.start(ctx, "retention", true)
	if e != nil {
		return CleanupCounts{}, e
	}
	defer cancel()
	defer rollback(tx)
	now, e := s.now()
	if e != nil {
		return CleanupCounts{}, e
	}
	z, e := readState(ctx, tx, "FOR UPDATE")
	if e != nil {
		return CleanupCounts{}, e
	}
	if now < z.lastGC {
		return CleanupCounts{}, ErrUnavailable
	}
	rows, e := selectCleanup(ctx, tx, z.Metadata.Scope.Namespace, now, limit, false)
	if e != nil {
		return CleanupCounts{}, e
	}
	n, bytes, e := cleanupRows(ctx, tx, z.Metadata.Scope.Namespace, rows)
	if e != nil {
		return CleanupCounts{}, e
	}
	if e = s.usage(ctx, tx, -n.DeletedPending-n.ExpiredReady, -n.ExpiredReady, -bytes, -n.DeletedPending-n.DeletedAudit); e != nil {
		return CleanupCounts{}, e
	}
	tag, e := tx.Exec(ctx, `UPDATE ops_sso_v1.state SET last_gc_us=$1 WHERE singleton`, int64(now))
	if e != nil || tag.RowsAffected() != 1 {
		return CleanupCounts{}, ErrUnavailable
	}
	if e = s.commit(ctx, tx, nil, true); e != nil {
		return CleanupCounts{}, e
	}
	return n, nil
}
