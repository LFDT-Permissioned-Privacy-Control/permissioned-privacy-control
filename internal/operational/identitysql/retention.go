package identitysql

import (
	"context"
	b "privacy-proxy/internal/identitybroker"
	"time"
)

type CleanupCounts struct{ Pending, Families, PrivadoChallenges int64 }

// CleanupOnce uses the trusted retention credential. SQL grants themselves do
// not restrict DELETE to expired rows; the cleanup process is part of the TCB.
func (s *Store) CleanupOnce(ctx context.Context, limit int) (CleanupCounts, error) {
	if s.mode != "retention" || limit < 1 || limit > 1000 {
		return CleanupCounts{}, b.ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	now, err := s.now()
	if err != nil {
		return CleanupCounts{}, err
	}
	tx, err := begin(ctx, s.pool)
	if err != nil {
		return CleanupCounts{}, err
	}
	defer rollback(tx)
	if err := checkState(ctx, tx, s.scope); err != nil {
		return CleanupCounts{}, err
	}
	if err := lockPrivadoFlow(ctx, tx, s.scope); err != nil {
		return CleanupCounts{}, err
	}
	tag, err := tx.Exec(ctx, `DELETE FROM ops_identity_v2.pending_requests WHERE request_id IN(SELECT request_id FROM ops_identity_v2.pending_requests WHERE expires_at<=$1 ORDER BY expires_at LIMIT $2)`, now, limit)
	if err != nil {
		return CleanupCounts{}, b.ErrUnavailable
	}
	counts := CleanupCounts{Pending: tag.RowsAffected()}
	if left := min(256, limit-int(counts.Pending)); left > 0 {
		tag, err = tx.Exec(ctx, `DELETE FROM ops_identity_v2.privado_challenges WHERE request_id IN(SELECT request_id FROM ops_identity_v2.privado_challenges WHERE namespace=$1 AND expires_at<=$2 ORDER BY expires_at,request_id LIMIT $3)`, s.scope.Namespace.String(), now, left)
		if err != nil {
			return CleanupCounts{}, b.ErrUnavailable
		}
		counts.PrivadoChallenges = tag.RowsAffected()
	}
	if left := limit - int(counts.Pending+counts.PrivadoChallenges); left > 0 {
		tag, err = tx.Exec(ctx, `DELETE FROM ops_identity_v2.renewal_families WHERE family_id IN(SELECT family_id FROM ops_identity_v2.renewal_families WHERE absolute_expires_at<=$1 ORDER BY absolute_expires_at LIMIT $2)`, now.Add(-24*time.Hour), left)
		if err != nil {
			return CleanupCounts{}, b.ErrUnavailable
		}
		counts.Families = tag.RowsAffected()
	}
	if err := checkState(ctx, tx, s.scope); err != nil {
		return CleanupCounts{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return CleanupCounts{}, b.ErrUnavailable
	}
	return counts, nil
}
