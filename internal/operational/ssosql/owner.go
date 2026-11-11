package ssosql

import (
	"context"
	"github.com/jackc/pgx/v5"
	m "privacy-proxy/internal/ssotransaction"
	"strconv"
	"time"
)

func ownerTx(ctx context.Context, dsn string) (*pgx.Conn, pgx.Tx, error) {
	conn, e := offline(ctx, dsn)
	if e != nil {
		return nil, nil, e
	}
	tx, e := begin(ctx, conn)
	if e != nil {
		closeConn(conn)
		return nil, nil, e
	}
	if e = checkOwner(ctx, tx); e != nil {
		rollback(tx)
		closeConn(conn)
		return nil, nil, e
	}
	if checkCatalog(ctx, tx) != nil {
		rollback(tx)
		closeConn(conn)
		return nil, nil, ErrUnavailable
	}
	return conn, tx, nil
}
func ownerState(ctx context.Context, tx pgx.Tx, scope m.Scope, unready bool) (state, error) {
	z, e := readState(ctx, tx, "FOR UPDATE")
	if e != nil {
		return z, e
	}
	if z.Metadata.Scope != scope || unready && z.Ready {
		return state{}, ErrConflict
	}
	for _, mode := range []string{"app", "retention"} {
		if e = checkPrivileges(ctx, tx, z.Metadata.Roles, mode); e != nil {
			return state{}, e
		}
	}
	return z, nil
}
func Initialize(ctx context.Context, dsn string, r Registration, drained bool) error {
	if !drained || !r.scope().Valid() || !r.Limits.Valid() || !validRoles(r.Roles) {
		return ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	conn, tx, e := ownerTx(ctx, dsn)
	if e != nil {
		return e
	}
	defer closeConn(conn)
	defer rollback(tx)
	if _, e = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(7665821920)`); e != nil {
		return ErrUnavailable
	}
	var n int
	if tx.QueryRow(ctx, `SELECT count(*) FROM ops_sso_v1.state`).Scan(&n) != nil {
		return ErrUnavailable
	}
	if n != 0 {
		z, e := ownerState(ctx, tx, r.scope(), false)
		if e != nil {
			return e
		}
		if z.Metadata.Limits != r.Limits || z.Metadata.Roles != r.Roles {
			return ErrConflict
		}
		if e = tx.Commit(ctx); e != nil {
			return ErrUnavailable
		}
		return nil
	}
	for _, mode := range []string{"app", "retention"} {
		if e = checkPrivileges(ctx, tx, r.Roles, mode); e != nil {
			return e
		}
	}
	if tx.QueryRow(ctx, `SELECT count(*) FROM ops_sso_v1.transactions`).Scan(&n) != nil || n != 0 {
		return ErrUnavailable
	}
	l := r.Limits
	_, e = tx.Exec(ctx, `INSERT INTO ops_sso_v1.state(singleton,schema_version,schema_checksum,namespace,epoch,broker_namespace,broker_epoch,ready,app_role,retention_role,max_active_rows,max_ready_rows,max_active_bytes,max_all_rows,max_metadata_bytes,audit_retention_seconds)VALUES(true,1,$1,$2,$3::uuid,$4,$5::uuid,true,$6,$7,$8,$9,$10,$11,$12,$13)`, SchemaChecksum(), r.Namespace[:], r.Epoch, r.BrokerNamespace[:], r.BrokerRecoveryEpoch, r.Roles.App, r.Roles.Retention, l.ActiveRows, l.ReadyRows, l.ActiveCipherBytes, l.AllRows, l.MetadataBytes, l.AuditRetentionSeconds)
	if e != nil {
		return ErrUnavailable
	}
	if _, e = ownerState(ctx, tx, r.scope(), false); e != nil {
		return e
	}
	if e = tx.Commit(ctx); e != nil {
		return ErrUnavailable
	}
	return nil
}
func Status(ctx context.Context, dsn string, namespace m.Digest) (StatusResult, error) {
	if !namespace.Valid() {
		return StatusResult{}, ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	conn, tx, e := ownerTx(ctx, dsn)
	if e != nil {
		return StatusResult{}, e
	}
	defer closeConn(conn)
	defer rollback(tx)
	z, e := readState(ctx, tx, "FOR SHARE")
	if e != nil {
		return StatusResult{}, e
	}
	if z.Metadata.Scope.Namespace != namespace {
		return StatusResult{}, ErrConflict
	}
	if e = tx.Commit(ctx); e != nil {
		return StatusResult{}, ErrUnavailable
	}
	return z.StatusResult, nil
}
func BeginRecovery(ctx context.Context, dsn string, current m.Scope, r Registration, drained bool) (StatusResult, error) {
	if !drained || !current.Valid() || !r.scope().Valid() || r.Epoch == current.Epoch || !r.Limits.Valid() || !validRoles(r.Roles) {
		return StatusResult{}, ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	conn, tx, e := ownerTx(ctx, dsn)
	if e != nil {
		return StatusResult{}, e
	}
	defer closeConn(conn)
	defer rollback(tx)
	z, e := ownerState(ctx, tx, current, false)
	if e != nil {
		return StatusResult{}, e
	}
	if r.Namespace != current.Namespace || r.BrokerNamespace != current.BrokerNamespace || r.Limits != z.Metadata.Limits || r.Roles != z.Metadata.Roles {
		return StatusResult{}, ErrConflict
	}
	tag, e := tx.Exec(ctx, `UPDATE ops_sso_v1.state SET ready=false,epoch=$1::uuid,broker_epoch=$2::uuid WHERE singleton`, r.Epoch, r.BrokerRecoveryEpoch)
	if e != nil || tag.RowsAffected() != 1 {
		return StatusResult{}, ErrUnavailable
	}
	z, e = ownerState(ctx, tx, r.scope(), true)
	if e != nil {
		return StatusResult{}, e
	}
	if e = tx.Commit(ctx); e != nil {
		return StatusResult{}, ErrUnavailable
	}
	return z.StatusResult, nil
}
func Reconfigure(ctx context.Context, dsn string, scope m.Scope, l m.Limits, drained bool) error {
	if !drained || !scope.Valid() || !l.Valid() {
		return ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	conn, tx, e := ownerTx(ctx, dsn)
	if e != nil {
		return e
	}
	defer closeConn(conn)
	defer rollback(tx)
	z, e := ownerState(ctx, tx, scope, true)
	if e != nil {
		return e
	}
	if !usageValid(z.Usage, l) {
		return ErrCapacity
	}
	tag, e := tx.Exec(ctx, `UPDATE ops_sso_v1.state SET max_active_rows=$1,max_ready_rows=$2,max_active_bytes=$3,max_all_rows=$4,max_metadata_bytes=$5,audit_retention_seconds=$6 WHERE singleton`, l.ActiveRows, l.ReadyRows, l.ActiveCipherBytes, l.AllRows, l.MetadataBytes, l.AuditRetentionSeconds)
	if e != nil || tag.RowsAffected() != 1 {
		return ErrUnavailable
	}
	if _, e = ownerState(ctx, tx, scope, true); e != nil {
		return e
	}
	if e = tx.Commit(ctx); e != nil {
		return ErrUnavailable
	}
	return nil
}
func FinalizeRecovery(ctx context.Context, dsn string, scope m.Scope, drained bool) error {
	if !drained || !scope.Valid() {
		return ErrInvalid
	}
	duration := 30 * time.Minute
	if _, ok := ctx.Deadline(); !ok {
		duration = 10 * time.Minute
	}
	ctx, cancel := context.WithTimeout(ctx, duration)
	defer cancel()
	// Every batch is independently committed while UNREADY. Cleanup is not undone
	// by a later validation failure. ALL epochs are selected, including reused ones.
	for {
		conn, tx, e := ownerTx(ctx, dsn)
		if e != nil {
			return e
		}
		z, e := ownerState(ctx, tx, scope, true)
		if e != nil {
			rollback(tx)
			closeConn(conn)
			return e
		}
		rows, e := selectCleanup(ctx, tx, scope.Namespace, 0, 1000, true)
		if e != nil {
			rollback(tx)
			closeConn(conn)
			return e
		}
		n, bytes, e := cleanupRows(ctx, tx, scope.Namespace, rows)
		if e == nil {
			helper := &Store{metadata: z.Metadata}
			e = helper.usage(ctx, tx, -n.DeletedPending-n.ExpiredReady, -n.ExpiredReady, -bytes, -n.DeletedPending)
		}
		if e == nil {
			_, e = ownerState(ctx, tx, scope, true)
		}
		if e == nil {
			if tx.Commit(ctx) != nil {
				e = ErrUnavailable
			}
		}
		rollback(tx)
		closeConn(conn)
		if e != nil {
			return e
		}
		if len(rows) == 0 {
			break
		}
	}
	conn, tx, e := ownerTx(ctx, dsn)
	if e != nil {
		return e
	}
	defer closeConn(conn)
	defer rollback(tx)
	z, e := ownerState(ctx, tx, scope, true)
	if e != nil {
		return e
	}
	if z.Usage.ActiveRows != 0 || z.Usage.ReadyRows != 0 || z.Usage.ActiveCipherBytes != 0 {
		return ErrUnavailable
	}
	deadline, _ := ctx.Deadline()
	ms := time.Until(deadline).Milliseconds()
	if ms <= 0 {
		return ErrUnavailable
	}
	if _, e = tx.Exec(ctx, `SELECT set_config('statement_timeout',$1,true)`, strconv.FormatInt(ms, 10)+"ms"); e != nil {
		return ErrUnavailable
	}
	rows, e := tx.Query(ctx, `SELECT `+rowProjection+` FROM ops_sso_v1.transactions ORDER BY id`)
	if e != nil {
		return ErrUnavailable
	}
	var count int64
	for rows.Next() {
		r, e := scanRecord(rows, scope.BrokerNamespace)
		if e != nil || r.Pending.Scope.Namespace != scope.Namespace || r.Phase == m.Pending || r.Phase == m.Ready {
			rows.Close()
			return ErrUnavailable
		}
		count++
		if count > z.Metadata.Limits.AllRows {
			rows.Close()
			return ErrUnavailable
		}
	}
	e = rows.Err()
	rows.Close()
	if e != nil || count != z.Usage.AllRows || count*m.MetadataChargeBytes != z.Usage.MetadataBytes {
		return ErrUnavailable
	}
	if _, e = ownerState(ctx, tx, scope, true); e != nil {
		return e
	}
	tag, e := tx.Exec(ctx, `UPDATE ops_sso_v1.state SET ready=true WHERE singleton`)
	if e != nil || tag.RowsAffected() != 1 {
		return ErrUnavailable
	}
	if tx.Commit(ctx) != nil {
		return ErrUnavailable
	}
	return nil
}
