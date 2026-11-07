package identitysql

import (
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	b "privacy-proxy/internal/identitybroker"
)

//go:embed migrations/001.sql
var schemaSQL string

func SchemaChecksumV1() string {
	sum := sha256.Sum256([]byte(schemaSQL))
	return "sha256:" + hex.EncodeToString(sum[:])
}

type querier interface {
	QueryRow(context.Context, string, ...any) pgx.Row
	Query(context.Context, string, ...any) (pgx.Rows, error)
}

var rolePattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,62}$`)

// Migrate uses an offline schema owner. Runtime Open never performs DDL. A new
// store starts unready; BootstrapEmpty or a drained recovery must finish it.
func Migrate(ctx context.Context, dsn, appRole, retentionRole string, scope b.Scope) error {
	if strings.TrimSpace(dsn) == "" || !scope.Valid() || !rolePattern.MatchString(appRole) || !rolePattern.MatchString(retentionRole) || appRole == retentionRole {
		return b.ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	conn, err := offlineConnection(ctx, dsn)
	if err != nil {
		return err
	}
	defer closeConnection(conn)
	tx, err := conn.Begin(ctx)
	if err != nil {
		return b.ErrUnavailable
	}
	defer rollback(tx)
	if _, err := tx.Exec(ctx, `SELECT set_config('lock_timeout','1s',true),set_config('statement_timeout','25s',true),pg_advisory_xact_lock(49222381407003)`); err != nil {
		return b.ErrUnavailable
	}
	var count int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM pg_roles WHERE rolname=ANY($1::text[]) AND NOT rolsuper AND NOT rolcreaterole AND NOT rolcreatedb AND rolname<>current_user`, []string{appRole, retentionRole}).Scan(&count); err != nil || count != 2 {
		return b.ErrInvalid
	}
	var existing *string
	if err := tx.QueryRow(ctx, `SELECT to_regclass('ops_identity_v2.metadata')::text`).Scan(&existing); err != nil {
		return b.ErrUnavailable
	}
	if existing == nil {
		if _, err := tx.Exec(ctx, schemaSQL); err != nil {
			return b.ErrUnavailable
		}
		if _, err := tx.Exec(ctx, `INSERT INTO ops_identity_v2.metadata(singleton,schema_version,migration_checksum,namespace,recovery_epoch,ready,updated_at)VALUES(true,1,$1,$2,$3::uuid,false,clock_timestamp())`, SchemaChecksumV1(), scope.Namespace.String(), scope.State.RecoveryEpoch); err != nil {
			return b.ErrUnavailable
		}
	}
	if err := checkSchemaV1(ctx, tx); err != nil {
		return err
	}
	var namespace string
	if err := tx.QueryRow(ctx, `SELECT namespace FROM ops_identity_v2.metadata WHERE singleton`).Scan(&namespace); err != nil || namespace != scope.Namespace.String() {
		return b.ErrConflict
	}
	a, r := pgx.Identifier{appRole}.Sanitize(), pgx.Identifier{retentionRole}.Sanitize()
	// Table-level REVOKE does not remove a separately granted column privilege.
	// Clear those explicitly before installing the exact application grants.
	for table, columns := range expectedColumns {
		list := []string{}
		for column := range columns {
			list = append(list, pgx.Identifier{column}.Sanitize())
		}
		joined := strings.Join(list, ",")
		statement := `REVOKE SELECT(` + joined + `),INSERT(` + joined + `),UPDATE(` + joined + `),REFERENCES(` + joined + `) ON ops_identity_v2.` + pgx.Identifier{table}.Sanitize() + ` FROM PUBLIC,` + a + `,` + r
		if _, err := tx.Exec(ctx, statement); err != nil {
			return b.ErrUnavailable
		}
	}
	for _, sql := range []string{
		`REVOKE ALL ON ALL TABLES IN SCHEMA ops_identity_v2 FROM PUBLIC`,
		`REVOKE ALL ON ALL TABLES IN SCHEMA ops_identity_v2 FROM ` + a + `,` + r,
		`GRANT USAGE ON SCHEMA ops_identity_v2 TO ` + a + `,` + r,
		`GRANT SELECT ON ops_identity_v2.metadata TO ` + a + `,` + r,
		`GRANT SELECT,INSERT,DELETE ON ops_identity_v2.pending_requests TO ` + a,
		`GRANT SELECT,INSERT ON ops_identity_v2.renewal_families TO ` + a,
		`GRANT UPDATE(generation,current_handle_hash,encryption_key_id,refresh_ciphertext,last_rotated_at,revoked_at) ON ops_identity_v2.renewal_families TO ` + a,
		`GRANT SELECT,DELETE ON ops_identity_v2.pending_requests,ops_identity_v2.renewal_families TO ` + r,
	} {
		if _, err := tx.Exec(ctx, sql); err != nil {
			return b.ErrUnavailable
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return b.ErrUnavailable
	}
	return nil
}
func offlineConnection(ctx context.Context, dsn string) (*pgx.Conn, error) {
	if strings.TrimSpace(dsn) == "" {
		return nil, b.ErrInvalid
	}
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		return nil, b.ErrUnavailable
	}
	cfg.ConnectTimeout = 3 * time.Second
	conn, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		return nil, b.ErrUnavailable
	}
	return conn, nil
}

var expectedColumns = map[string]map[string]string{
	"metadata":         {"singleton": "boolean", "schema_version": "integer", "migration_checksum": "text", "namespace": "text", "recovery_epoch": "uuid", "ready": "boolean", "updated_at": "timestamp with time zone"},
	"pending_requests": {"request_id": "uuid", "namespace": "text", "recovery_epoch": "uuid", "state_hash": "bytea", "profile_id": "text", "profile_digest": "text", "recipient_hash": "bytea", "encryption_key_id": "text", "secret_ciphertext": "bytea", "created_at": "timestamp with time zone", "expires_at": "timestamp with time zone"},
	"renewal_families": {"family_id": "uuid", "originating_request_id": "uuid", "namespace": "text", "recovery_epoch": "uuid", "actor_id": "text", "profile_id": "text", "profile_digest": "text", "identity_authority": "text", "source_tenant": "text", "source_subject": "text", "principal_kind": "text", "oidc_subject_hash": "bytea", "login_nonce_hash": "bytea", "original_auth_time": "bigint", "recipient_hash": "bytea", "generation": "bigint", "current_handle_hash": "bytea", "encryption_key_id": "text", "refresh_ciphertext": "bytea", "created_at": "timestamp with time zone", "absolute_expires_at": "timestamp with time zone", "last_rotated_at": "timestamp with time zone", "revoked_at": "timestamp with time zone"},
}
var expectedIndexes = map[string]string{
	"metadata_pkey":                               "CREATE UNIQUE INDEX metadata_pkey ON ops_identity_v2.metadata USING btree (singleton)",
	"pending_requests_pkey":                       "CREATE UNIQUE INDEX pending_requests_pkey ON ops_identity_v2.pending_requests USING btree (request_id)",
	"pending_requests_state_hash_key":             "CREATE UNIQUE INDEX pending_requests_state_hash_key ON ops_identity_v2.pending_requests USING btree (state_hash)",
	"pending_expiry":                              "CREATE INDEX pending_expiry ON ops_identity_v2.pending_requests USING btree (expires_at)",
	"renewal_families_pkey":                       "CREATE UNIQUE INDEX renewal_families_pkey ON ops_identity_v2.renewal_families USING btree (family_id)",
	"renewal_families_originating_request_id_key": "CREATE UNIQUE INDEX renewal_families_originating_request_id_key ON ops_identity_v2.renewal_families USING btree (originating_request_id)",
	"family_expiry":                               "CREATE INDEX family_expiry ON ops_identity_v2.renewal_families USING btree (absolute_expires_at)",
	"family_active_expiry":                        "CREATE INDEX family_active_expiry ON ops_identity_v2.renewal_families USING btree (absolute_expires_at) WHERE (revoked_at IS NULL)",
}

func checkSchemaV1Legacy(ctx context.Context, q querier) error {
	var version, count int
	var checksum string
	if err := q.QueryRow(ctx, `SELECT schema_version,migration_checksum,(SELECT count(*) FROM ops_identity_v2.metadata)FROM ops_identity_v2.metadata WHERE singleton`).Scan(&version, &checksum, &count); err != nil || version != 1 || count != 1 || checksum != SchemaChecksumV1() {
		return b.ErrUnavailable
	}
	remaining := map[string]map[string]string{}
	for table, cols := range expectedColumns {
		remaining[table] = map[string]string{}
		for col, typ := range cols {
			remaining[table][col] = typ
		}
	}
	rows, err := q.Query(ctx, `SELECT c.relname,a.attname,format_type(a.atttypid,a.atttypmod) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace JOIN pg_attribute a ON a.attrelid=c.oid WHERE n.nspname='ops_identity_v2' AND c.relkind IN('r','p','v','m','f') AND a.attnum>0 AND NOT a.attisdropped ORDER BY c.relname,a.attnum`)
	if err != nil {
		return b.ErrUnavailable
	}
	for rows.Next() {
		var table, col, typ string
		if rows.Scan(&table, &col, &typ) != nil || remaining[table][col] != typ {
			rows.Close()
			return b.ErrUnavailable
		}
		delete(remaining[table], col)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return b.ErrUnavailable
	}
	for _, cols := range remaining {
		if len(cols) != 0 {
			return b.ErrUnavailable
		}
	}
	indexes := map[string]string{}
	for name, def := range expectedIndexes {
		indexes[name] = def
	}
	rows, err = q.Query(ctx, `SELECT c.relname,pg_get_indexdef(c.oid),i.indisvalid AND i.indisready FROM pg_index i JOIN pg_class c ON c.oid=i.indexrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='ops_identity_v2'`)
	if err != nil {
		return b.ErrUnavailable
	}
	for rows.Next() {
		var name, def string
		var valid bool
		if rows.Scan(&name, &def, &valid) != nil || !valid || indexes[name] != def {
			rows.Close()
			return b.ErrUnavailable
		}
		delete(indexes, name)
	}
	err = rows.Err()
	rows.Close()
	if err != nil || len(indexes) != 0 {
		return b.ErrUnavailable
	}
	var trigger bool
	if err := q.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_trigger t JOIN pg_proc p ON p.oid=t.tgfoid WHERE t.tgrelid='ops_identity_v2.renewal_families'::regclass AND t.tgname='family_monotonic' AND t.tgenabled='O' AND NOT t.tgisinternal AND p.oid='ops_identity_v2.family_monotonic()'::regprocedure) AND NOT EXISTS(SELECT 1 FROM pg_constraint c JOIN pg_namespace n ON n.oid=c.connamespace WHERE n.nspname='ops_identity_v2' AND (NOT c.convalidated OR c.contype='f'))`).Scan(&trigger); err != nil || !trigger {
		return b.ErrUnavailable
	}
	return nil
}
func (s *Store) checkPrivileges(ctx context.Context) error {
	var unsafe bool
	if err := s.pool.QueryRow(ctx, `SELECT r.rolsuper OR r.rolcreaterole OR r.rolcreatedb
 OR has_schema_privilege(current_user,'ops_identity_v2','CREATE')
 OR EXISTS(SELECT 1 FROM pg_database d WHERE d.datname=current_database() AND pg_has_role(current_user,d.datdba,'MEMBER'))
 OR EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='ops_identity_v2' AND pg_has_role(current_user,c.relowner,'MEMBER'))
 OR EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname NOT IN('ops_identity_v2','pg_catalog','information_schema') AND n.nspname NOT LIKE 'pg_toast%' AND n.nspname NOT LIKE 'pg_temp%' AND c.relkind IN('r','p','v','m','f') AND(has_table_privilege(current_user,c.oid,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,TRIGGER,REFERENCES') OR has_any_column_privilege(current_user,c.oid,'SELECT,INSERT,UPDATE,REFERENCES')))
 FROM pg_roles r WHERE r.rolname=current_user`).Scan(&unsafe); err != nil || unsafe {
		return b.ErrUnavailable
	}
	for table, cols := range expectedColumns {
		name := "ops_identity_v2." + table
		for _, p := range []string{"INSERT", "DELETE", "TRUNCATE", "REFERENCES", "TRIGGER"} {
			want := s.mode == "app" && (p == "INSERT" && table != "metadata" || p == "DELETE" && table == "pending_requests") || s.mode == "retention" && p == "DELETE" && table != "metadata"
			var actual bool
			if err := s.pool.QueryRow(ctx, `SELECT has_table_privilege(current_user,$1,$2)`, name, p).Scan(&actual); err != nil || actual != want {
				return b.ErrUnavailable
			}
		}
		for col := range cols {
			update := s.mode == "app" && table == "renewal_families" && (col == "generation" || col == "current_handle_hash" || col == "encryption_key_id" || col == "refresh_ciphertext" || col == "last_rotated_at" || col == "revoked_at")
			insert := s.mode == "app" && table != "metadata"
			var readActual, updateActual, insertActual, referenceActual bool
			if err := s.pool.QueryRow(ctx, `SELECT has_column_privilege(current_user,$1,$2,'SELECT'),has_column_privilege(current_user,$1,$2,'UPDATE'),has_column_privilege(current_user,$1,$2,'INSERT'),has_column_privilege(current_user,$1,$2,'REFERENCES')`, name, col).Scan(&readActual, &updateActual, &insertActual, &referenceActual); err != nil || !readActual || updateActual != update || insertActual != insert || referenceActual {
				return b.ErrUnavailable
			}
		}
	}
	return nil
}
