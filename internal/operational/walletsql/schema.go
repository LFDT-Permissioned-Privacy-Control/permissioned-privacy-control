package walletsql

import (
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	w "privacy-proxy/internal/walletops"
)

//go:embed migrations/001.sql
var schemaSQL string

func SchemaChecksum() string {
	sum := sha256.Sum256([]byte(schemaSQL))
	return "sha256:" + hex.EncodeToString(sum[:])
}

var rolePattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,62}$`)

type querier interface {
	QueryRow(context.Context, string, ...any) pgx.Row
	Query(context.Context, string, ...any) (pgx.Rows, error)
}

func Migrate(ctx context.Context, dsn, appRole, readerRole, retentionRole string) error {
	roles := []string{appRole, readerRole, retentionRole}
	seen := map[string]bool{}
	for _, role := range roles {
		if !rolePattern.MatchString(role) || seen[role] {
			return w.ErrInvalid
		}
		seen[role] = true
	}
	if strings.TrimSpace(dsn) == "" {
		return w.ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	config, err := pgx.ParseConfig(dsn)
	if err != nil {
		return w.ErrUnavailable
	}
	config.ConnectTimeout = 3 * time.Second
	conn, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		return w.ErrUnavailable
	}
	defer closeConnection(conn)
	tx, err := conn.Begin(ctx)
	if err != nil {
		return w.ErrUnavailable
	}
	defer rollback(tx)
	if _, err := tx.Exec(ctx, `SELECT set_config('lock_timeout','1s',true),set_config('statement_timeout','25s',true),pg_advisory_xact_lock(49222381407002)`); err != nil {
		return w.ErrUnavailable
	}
	var count int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM pg_roles WHERE rolname=ANY($1::text[]) AND NOT rolsuper AND NOT rolcreaterole AND NOT rolcreatedb AND rolname<>current_user`, roles).Scan(&count); err != nil || count != 3 {
		return w.ErrInvalid
	}
	var existing *string
	if err := tx.QueryRow(ctx, `SELECT to_regclass('ops_wallet_v2.schema_version')::text`).Scan(&existing); err != nil {
		return w.ErrUnavailable
	}
	if existing == nil {
		if _, err := tx.Exec(ctx, schemaSQL); err != nil {
			return w.ErrUnavailable
		}
		if _, err := tx.Exec(ctx, `INSERT INTO ops_wallet_v2.schema_version VALUES(true,1,$1)`, SchemaChecksum()); err != nil {
			return w.ErrUnavailable
		}
	}
	if err := checkSchema(ctx, tx); err != nil {
		return err
	}
	a, r, t := pgx.Identifier{appRole}.Sanitize(), pgx.Identifier{readerRole}.Sanitize(), pgx.Identifier{retentionRole}.Sanitize()
	statements := []string{
		// Trigger execution does not require callers to execute this function
		// directly. PUBLIC EXECUTE also breaks co-located restricted stores.
		`REVOKE ALL ON FUNCTION ops_wallet_v2.wallet_link_monotonic() FROM PUBLIC`,
		`REVOKE ALL ON ALL TABLES IN SCHEMA ops_wallet_v2 FROM PUBLIC`,
		`REVOKE ALL ON ALL TABLES IN SCHEMA ops_wallet_v2 FROM ` + a + `,` + r + `,` + t,
		`GRANT USAGE ON SCHEMA ops_wallet_v2 TO ` + a + `,` + r + `,` + t,
		`GRANT SELECT ON ops_wallet_v2.schema_version TO ` + a + `,` + r + `,` + t,
		`GRANT SELECT ON ops_wallet_v2.store_state TO ` + a + `,` + r,
		`GRANT SELECT,INSERT ON ops_wallet_v2.wallet_links TO ` + a,
		`GRANT UPDATE(revoked,revoked_at) ON ops_wallet_v2.wallet_links TO ` + a,
		`GRANT SELECT,INSERT,DELETE ON ops_wallet_v2.wallet_challenges TO ` + a,
		`GRANT SELECT(namespace,actor_id,address,proof_kind,accepted_at,revoked) ON ops_wallet_v2.wallet_links TO ` + r,
		`GRANT SELECT(namespace,generation,nonce,expires_at),DELETE ON ops_wallet_v2.wallet_challenges TO ` + t,
	}
	for _, statement := range statements {
		if _, err := tx.Exec(ctx, statement); err != nil {
			return w.ErrUnavailable
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return w.ErrUnavailable
	}
	return nil
}
func (s *Store) CheckSchema(ctx context.Context) error {
	ctx, cancel := bounded(ctx)
	defer cancel()
	return checkSchema(ctx, s.pool)
}

var expectedColumns = map[string]map[string]string{
	"schema_version":    {"singleton": "boolean", "version": "integer", "source_checksum": "text"},
	"store_state":       {"namespace": "bytea", "generation": "uuid", "ready": "boolean", "revocation_coverage_digest": "bytea"},
	"wallet_links":      {"namespace": "bytea", "actor_id": "text", "address": "bytea", "proof_kind": "text", "message": "bytea", "signature": "bytea", "message_hash": "bytea", "accepted_at": "timestamp with time zone", "revoked": "boolean", "revoked_at": "timestamp with time zone"},
	"wallet_challenges": {"namespace": "bytea", "generation": "uuid", "actor_id": "text", "nonce": "bytea", "address": "bytea", "message": "bytea", "issued_at": "timestamp with time zone", "expires_at": "timestamp with time zone"},
}

func checkSchema(ctx context.Context, q querier) error {
	// RLS can hide stored links and turn a populated scope into a false empty
	// snapshot. These ordinary permanent relations are the supported shape.
	var unsafe bool
	if err := q.QueryRow(ctx, `SELECT EXISTS(
 SELECT 1 FROM pg_catalog.pg_class c
 JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
 WHERE n.nspname='ops_wallet_v2'
 AND c.relname IN('schema_version','store_state','wallet_links','wallet_challenges')
 AND(c.relkind<>'r' OR c.relpersistence<>'p' OR c.relrowsecurity OR c.relforcerowsecurity)
) AS unsafe
`).Scan(&unsafe); err != nil || unsafe {
		return w.ErrUnavailable
	}
	var version, count int
	var checksum string
	if err := q.QueryRow(ctx, `SELECT version,source_checksum,(SELECT count(*) FROM ops_wallet_v2.schema_version)FROM ops_wallet_v2.schema_version WHERE singleton`).Scan(&version, &checksum, &count); err != nil || version != 1 || count != 1 || checksum != SchemaChecksum() {
		return w.ErrUnavailable
	}
	remaining := map[string]map[string]string{}
	for table, cols := range expectedColumns {
		remaining[table] = map[string]string{}
		for col, typ := range cols {
			remaining[table][col] = typ
		}
	}
	rows, err := q.Query(ctx, `SELECT c.relname,a.attname,format_type(a.atttypid,a.atttypmod) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace JOIN pg_attribute a ON a.attrelid=c.oid WHERE n.nspname='ops_wallet_v2' AND c.relkind='r' AND a.attnum>0 AND NOT a.attisdropped ORDER BY c.relname,a.attnum`)
	if err != nil {
		return w.ErrUnavailable
	}
	defer rows.Close()
	for rows.Next() {
		var table, col, typ string
		if rows.Scan(&table, &col, &typ) != nil || remaining[table][col] != typ {
			return w.ErrUnavailable
		}
		delete(remaining[table], col)
	}
	if rows.Err() != nil {
		return w.ErrUnavailable
	}
	rows.Close()
	for _, cols := range remaining {
		if len(cols) != 0 {
			return w.ErrUnavailable
		}
	}
	var trigger bool
	if err := q.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='ops_wallet_v2.wallet_links'::regclass AND tgname='wallet_link_monotonic' AND tgenabled='O' AND NOT tgisinternal)`).Scan(&trigger); err != nil || !trigger {
		return w.ErrUnavailable
	}
	return nil
}

func (s *Store) checkPrivileges(ctx context.Context) error {
	var unsafe bool
	if err := s.pool.QueryRow(ctx, `SELECT r.rolsuper OR r.rolcreaterole OR r.rolcreatedb
 OR has_schema_privilege(current_user,'ops_wallet_v2','CREATE')
 OR EXISTS(SELECT 1 FROM pg_database d WHERE d.datname=current_database() AND pg_has_role(current_user,d.datdba,'MEMBER'))
 OR EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='ops_wallet_v2' AND pg_has_role(current_user,c.relowner,'MEMBER'))
 OR EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname NOT IN('ops_wallet_v2','pg_catalog','information_schema') AND n.nspname<>'pg_toast' AND left(n.nspname,14)<>'pg_toast_temp_' AND left(n.nspname,8)<>'pg_temp_' AND c.relkind IN('r','p','v','m') AND(has_table_privilege(current_user,c.oid,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,TRIGGER') OR has_any_column_privilege(current_user,c.oid,'SELECT,INSERT,UPDATE')))
 FROM pg_roles r WHERE r.rolname=current_user`).Scan(&unsafe); err != nil || unsafe {
		return w.ErrUnavailable
	}
	for table, cols := range expectedColumns {
		name := "ops_wallet_v2." + table
		for _, privilege := range []string{"INSERT", "DELETE", "TRUNCATE", "REFERENCES", "TRIGGER"} {
			want := s.mode == "app" && (privilege == "INSERT" && (table == "wallet_links" || table == "wallet_challenges") || privilege == "DELETE" && table == "wallet_challenges") || s.mode == "retention" && table == "wallet_challenges" && privilege == "DELETE"
			var actual bool
			if err := s.pool.QueryRow(ctx, `SELECT has_table_privilege(current_user,$1,$2)`, name, privilege).Scan(&actual); err != nil || actual != want {
				return w.ErrUnavailable
			}
		}
		for col := range cols {
			selectWant := table == "schema_version" || s.mode == "app" || s.mode == "reader" && (table == "store_state" || table == "wallet_links" && (col == "namespace" || col == "actor_id" || col == "address" || col == "proof_kind" || col == "accepted_at" || col == "revoked")) || s.mode == "retention" && table == "wallet_challenges" && (col == "namespace" || col == "generation" || col == "nonce" || col == "expires_at")
			updateWant := s.mode == "app" && table == "wallet_links" && (col == "revoked" || col == "revoked_at")
			insertWant := s.mode == "app" && (table == "wallet_links" || table == "wallet_challenges")
			var selectActual, updateActual, insertActual bool
			if err := s.pool.QueryRow(ctx, `SELECT has_column_privilege(current_user,$1,$2,'SELECT'),has_column_privilege(current_user,$1,$2,'UPDATE'),has_column_privilege(current_user,$1,$2,'INSERT')`, name, col).Scan(&selectActual, &updateActual, &insertActual); err != nil || selectActual != selectWant || updateActual != updateWant || insertActual != insertWant {
				return w.ErrUnavailable
			}
		}
	}
	return nil
}
