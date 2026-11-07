package disclosuresql

import (
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	c "privacy-proxy/internal/disclosurecase"
)

//go:embed migrations/001.sql
var schemaSQL string

func SchemaChecksum() string {
	sum := sha256.Sum256([]byte(schemaSQL))
	return "sha256:" + hex.EncodeToString(sum[:])
}

var rolePattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,62}$`)

// Migrate is an offline operation using explicit migrator credentials. It does
// not create credentials or run from the HTTP/application startup path.
func Migrate(ctx context.Context, dsn, appRole, retentionRole string) error {
	if strings.TrimSpace(dsn) == "" || !rolePattern.MatchString(appRole) || !rolePattern.MatchString(retentionRole) || appRole == retentionRole {
		return c.ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	config, err := pgx.ParseConfig(dsn)
	if err != nil {
		return c.ErrUnavailable
	}
	config.ConnectTimeout = 3 * time.Second
	conn, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		return c.ErrUnavailable
	}
	defer closeConnection(conn)
	tx, err := conn.Begin(ctx)
	if err != nil {
		return c.ErrUnavailable
	}
	defer rollback(tx)
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(49222381407001)`); err != nil {
		return c.ErrUnavailable
	}
	var safe int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM pg_roles WHERE rolname=ANY($1::text[]) AND NOT rolsuper AND NOT rolcreaterole AND NOT rolcreatedb AND rolname<>current_user`, []string{appRole, retentionRole}).Scan(&safe); err != nil || safe != 2 {
		return c.ErrInvalid
	}
	var existing *string
	if err := tx.QueryRow(ctx, `SELECT to_regclass('ops_v2.disclosure_schema_version')::text`).Scan(&existing); err != nil {
		return c.ErrUnavailable
	}
	if existing == nil {
		if _, err := tx.Exec(ctx, schemaSQL); err != nil {
			return c.ErrUnavailable
		}
		if _, err := tx.Exec(ctx, `INSERT INTO ops_v2.disclosure_schema_version(singleton,version,source_checksum)VALUES(true,1,$1)`, SchemaChecksum()); err != nil {
			return c.ErrUnavailable
		}
	}
	if err := checkSchema(ctx, tx); err != nil {
		return err
	}
	app := pgx.Identifier{appRole}.Sanitize()
	retention := pgx.Identifier{retentionRole}.Sanitize()
	// These are checked/quoted identifiers, never source-policy values or DSNs.
	statements := []string{
		`REVOKE ALL ON ops_v2.disclosure_cases,ops_v2.disclosure_events,ops_v2.disclosure_schema_version FROM PUBLIC`,
		`REVOKE ALL ON ops_v2.disclosure_cases,ops_v2.disclosure_events,ops_v2.disclosure_schema_version FROM ` + app + `,` + retention,
		`GRANT USAGE ON SCHEMA ops_v2 TO ` + app + `,` + retention,
		`GRANT SELECT,INSERT ON ops_v2.disclosure_cases,ops_v2.disclosure_events TO ` + app,
		`GRANT UPDATE(status,version,revoked_at,revoked_by_actor,revoke_reason) ON ops_v2.disclosure_cases TO ` + app,
		`GRANT SELECT ON ops_v2.disclosure_schema_version TO ` + app + `,` + retention,
		`GRANT SELECT,DELETE ON ops_v2.disclosure_cases,ops_v2.disclosure_events TO ` + retention,
	}
	for _, statement := range statements {
		if _, err := tx.Exec(ctx, statement); err != nil {
			return c.ErrUnavailable
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return c.ErrUnavailable
	}
	return nil
}

type schemaQuerier interface {
	QueryRow(context.Context, string, ...any) pgx.Row
	Query(context.Context, string, ...any) (pgx.Rows, error)
}

func (s *Store) CheckSchema(ctx context.Context) error {
	ctx, cancel := bounded(ctx)
	defer cancel()
	return checkSchema(ctx, s.pool)
}

func checkSchema(ctx context.Context, q schemaQuerier) error {
	var version, count int
	var checksum string
	if err := q.QueryRow(ctx, `SELECT version,source_checksum,(SELECT count(*) FROM ops_v2.disclosure_schema_version) FROM ops_v2.disclosure_schema_version WHERE singleton=true`).Scan(&version, &checksum, &count); err != nil || version != 1 || checksum != SchemaChecksum() || count != 1 {
		return c.ErrUnavailable
	}
	// Exact known columns make manual/mismatched schema changes a startup error.
	expected := map[string]map[string]string{
		"disclosure_schema_version": {"singleton": "boolean", "version": "integer", "source_checksum": "text"},
		"disclosure_cases":          {"case_id": "uuid", "store_epoch": "text", "creator_actor": "text", "recipient_actor": "text", "rule_id": "text", "data_org": "text", "original_rule_digest": "text", "original_bundle_digest": "text", "request_digest": "text", "immutable_scope": "jsonb", "case_reference": "text", "purpose": "text", "legal_basis": "text", "created_at": "timestamp with time zone", "expires_at": "timestamp with time zone", "status": "text", "version": "bigint", "idempotency_key": "uuid", "revoked_at": "timestamp with time zone", "revoked_by_actor": "text", "revoke_reason": "text"},
		"disclosure_events":         {"event_id": "uuid", "case_id": "uuid", "store_epoch": "text", "actor": "text", "action": "text", "outcome": "text", "rule_id": "text", "rule_digest": "text", "bundle_digest": "text", "case_version": "bigint", "prepared_at": "timestamp with time zone", "summary": "jsonb", "attempt_id": "uuid"},
	}
	rows, err := q.Query(ctx, `SELECT table_name,column_name,data_type FROM information_schema.columns WHERE table_schema='ops_v2' AND table_name IN ('disclosure_schema_version','disclosure_cases','disclosure_events')`)
	if err != nil {
		return c.ErrUnavailable
	}
	defer rows.Close()
	for rows.Next() {
		var table, column, typ string
		if rows.Scan(&table, &column, &typ) != nil || expected[table][column] != typ {
			return c.ErrUnavailable
		}
		delete(expected[table], column)
	}
	if rows.Err() != nil {
		return c.ErrUnavailable
	}
	rows.Close()
	for _, columns := range expected {
		if len(columns) != 0 {
			return c.ErrUnavailable
		}
	}
	var trigger bool
	if err := q.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='ops_v2.disclosure_cases'::regclass AND tgname='disclosure_case_monotonic' AND tgenabled='O' AND NOT tgisinternal)`).Scan(&trigger); err != nil || !trigger {
		return c.ErrUnavailable
	}
	return nil
}
