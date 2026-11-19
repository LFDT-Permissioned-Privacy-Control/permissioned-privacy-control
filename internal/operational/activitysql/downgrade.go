package activitysql

import (
	"context"
	"github.com/jackc/pgx/v5"
	a "privacy-proxy/internal/activitylog"
	"time"
)

// DowngradeTo005 is an explicit offline owner operation. 005/006 are exact
// catalog versions, not a mutable version row. No history or authority changes.
func DowngradeTo005(ctx context.Context, dsn, writerRole, readerRole, retentionRole string, drained bool) error {
	roles := RoleNames{writerRole, readerRole, retentionRole}
	if !drained || !roles.Valid() {
		return a.ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Minute)
	defer cancel()
	return ownerTx(ctx, dsn, func(tx pgx.Tx) error {
		if e := checkSchema(ctx, tx); e != nil {
			return e
		}
		if e := checkRole(ctx, tx, roles, "owner"); e != nil {
			return e
		}
		if _, e := tx.Exec(ctx, `DROP INDEX public.activity_org_page`); e != nil {
			return a.ErrUnavailable
		}
		if e := checkSchemaAgainst(ctx, tx, previousCatalog); e != nil {
			return e
		}
		return checkRole(ctx, tx, roles, "owner")
	})
}
