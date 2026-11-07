package identitysql

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
	b "privacy-proxy/internal/identitybroker"
)

// BootstrapEmpty is only for a new installation with no broker state. It does
// not reset an existing session store or change its expected epoch.
func BootstrapEmpty(ctx context.Context, dsn string, scope b.Scope) error {
	if !scope.Valid() {
		return b.ErrInvalid
	}
	return offline(ctx, dsn, func(ctx context.Context, tx pgx.Tx) error {
		if err := checkSchema(ctx, tx); err != nil {
			return err
		}
		var ready, empty bool
		var ns, epoch string
		if err := tx.QueryRow(ctx, `SELECT namespace,recovery_epoch::text,ready,NOT EXISTS(SELECT 1 FROM ops_identity_v2.pending_requests)AND NOT EXISTS(SELECT 1 FROM ops_identity_v2.renewal_families)AND NOT EXISTS(SELECT 1 FROM ops_identity_v2.privado_challenges)AND NOT EXISTS(SELECT 1 FROM ops_identity_v2.privado_offers) FROM ops_identity_v2.metadata WHERE singleton FOR UPDATE`).Scan(&ns, &epoch, &ready, &empty); err != nil {
			return b.ErrUnavailable
		}
		if ns != scope.Namespace.String() || epoch != scope.State.RecoveryEpoch || ready || !empty {
			return b.ErrConflict
		}
		_, err := tx.Exec(ctx, `UPDATE ops_identity_v2.metadata SET ready=true,updated_at=clock_timestamp() WHERE singleton`)
		if err != nil {
			return b.ErrUnavailable
		}
		return nil
	})
}

// BeginRecovery requires all broker workers to be drained. The NEW epoch must
// be selected outside the restored database and provided to every new worker.
// The operator and that deployment binding are part of the trusted boundary.
func BeginRecovery(ctx context.Context, dsn string, scope b.Scope, allWorkersDrained bool) error {
	if !scope.Valid() || !allWorkersDrained {
		return b.ErrInvalid
	}
	return offline(ctx, dsn, func(ctx context.Context, tx pgx.Tx) error {
		if err := checkSchema(ctx, tx); err != nil {
			return err
		}
		var ns, epoch string
		var ready bool
		if err := tx.QueryRow(ctx, `SELECT namespace,recovery_epoch::text,ready FROM ops_identity_v2.metadata WHERE singleton FOR UPDATE`).Scan(&ns, &epoch, &ready); err != nil {
			return b.ErrUnavailable
		}
		if ns != scope.Namespace.String() || epoch == scope.State.RecoveryEpoch && ready {
			return b.ErrConflict
		}
		_, err := tx.Exec(ctx, `UPDATE ops_identity_v2.metadata SET recovery_epoch=$1::uuid,ready=false,updated_at=clock_timestamp() WHERE singleton`, scope.State.RecoveryEpoch)
		if err != nil {
			return b.ErrUnavailable
		}
		return nil
	})
}

// FinalizeRecovery invalidates all previous pending logins and families. This
// is restartable after interruption while readiness remains false. No provider
// tokens are restored into an authenticated session.
func FinalizeRecovery(ctx context.Context, dsn string, scope b.Scope, allWorkersDrained bool) error {
	if !scope.Valid() || !allWorkersDrained {
		return b.ErrInvalid
	}
	return offline(ctx, dsn, func(ctx context.Context, tx pgx.Tx) error {
		if err := checkSchema(ctx, tx); err != nil {
			return err
		}
		var ok bool
		if err := tx.QueryRow(ctx, `SELECT namespace=$1 AND recovery_epoch=$2::uuid AND NOT ready FROM ops_identity_v2.metadata WHERE singleton FOR UPDATE`, scope.Namespace.String(), scope.State.RecoveryEpoch).Scan(&ok); err != nil || !ok {
			return b.ErrConflict
		}
		if e := lockPrivadoFlow(ctx, tx, scope); e != nil {
			return e
		}
		for _, q := range []string{
			`DELETE FROM ops_identity_v2.privado_challenges WHERE request_id IN(SELECT request_id FROM ops_identity_v2.privado_challenges ORDER BY request_id LIMIT 256)`,
			`DELETE FROM ops_identity_v2.pending_requests WHERE request_id IN(SELECT request_id FROM ops_identity_v2.pending_requests ORDER BY request_id LIMIT 1000)`,
			`DELETE FROM ops_identity_v2.renewal_families WHERE family_id IN(SELECT family_id FROM ops_identity_v2.renewal_families ORDER BY family_id LIMIT 1000)`,
		} {
			for {
				tag, err := tx.Exec(ctx, q)
				if err != nil {
					return b.ErrUnavailable
				}
				if tag.RowsAffected() == 0 {
					break
				}
			}
		}
		_, err := tx.Exec(ctx, `UPDATE ops_identity_v2.metadata SET ready=true,updated_at=clock_timestamp() WHERE singleton`)
		if err != nil {
			return b.ErrUnavailable
		}
		return nil
	})
}
func offline(ctx context.Context, dsn string, callback func(context.Context, pgx.Tx) error) error {
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	conn, err := offlineConnection(ctx, dsn)
	if err != nil {
		return err
	}
	defer closeConnection(conn)
	tx, err := begin(ctx, connPool{conn})
	if err != nil {
		return err
	}
	defer rollback(tx)
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(49222381407003)`); err != nil {
		return b.ErrUnavailable
	}
	if err := callback(ctx, tx); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return b.ErrUnavailable
	}
	return nil
}

type connPool struct{ *pgx.Conn }
