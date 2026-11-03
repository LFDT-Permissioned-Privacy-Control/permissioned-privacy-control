package db

import (
	"context"
	"io/fs"
)

// MigrateAuditFSToForTest applies the audit migrations in fsys up to target,
// so a test can hold a database at an earlier schema version.
func MigrateAuditFSToForTest(ctx context.Context, d *DB, fsys fs.FS, target int32) error {
	conn, err := d.connectPgxUTC(ctx)
	if err != nil {
		return err
	}
	defer conn.Close(ctx)
	migrator, err := newMigrator(ctx, conn, "schema_version_audit")
	if err != nil {
		return err
	}
	if err := migrator.LoadMigrations(fsys); err != nil {
		return err
	}
	return migrator.MigrateTo(ctx, target)
}
