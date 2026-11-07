package admissionsql

import (
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	a "privacy-proxy/internal/admission"
)

//go:embed migrations/001.sql
var schemaSQL string

//go:embed migrations/002.sql
var creationSchemaSQL string

func CreationSchemaChecksum() string {
	sum := sha256.Sum256([]byte(schemaSQL + "\x00" + creationSchemaSQL))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func SchemaChecksum() string {
	sum := sha256.Sum256([]byte(schemaSQL))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// SchemaInfo describes the exact validated schema installed in the selected
// operational database. Migration tools must report it rather than assuming v1.
type SchemaInfo struct {
	Version        int    `json:"schemaVersion"`
	SourceChecksum string `json:"sourceChecksum"`
}

func InstalledSchema(ctx context.Context, dsn string) (SchemaInfo, error) {
	var out SchemaInfo
	err := offline(ctx, dsn, func(ctx context.Context, tx pgx.Tx) error {
		version, err := schemaVersion(ctx, tx)
		if err != nil {
			return err
		}
		out = SchemaInfo{Version: version, SourceChecksum: SchemaChecksum()}
		if version == 2 {
			out.SourceChecksum = CreationSchemaChecksum()
		}
		return nil
	})
	if err != nil {
		return SchemaInfo{}, err
	}
	return out, nil
}

var rolePattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,62}$`)

// Migrate uses explicit offline owner credentials. Application startup neither
// changes the schema nor creates/reuses an ambient legacy database connection.
func Migrate(ctx context.Context, dsn, appRole, readerRole, retentionRole string) error {
	roles := []string{appRole, readerRole, retentionRole}
	seen := map[string]bool{}
	for _, r := range roles {
		if !rolePattern.MatchString(r) || seen[r] {
			return a.ErrInvalid
		}
		seen[r] = true
	}
	return offlineConnection(ctx, dsn, 30*time.Second, func(ctx context.Context, tx pgx.Tx) error {
		var count int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM pg_roles WHERE rolname=ANY($1::text[]) AND NOT rolsuper AND NOT rolcreaterole AND NOT rolcreatedb AND rolname<>current_user`, roles).Scan(&count); err != nil || count != 3 {
			return a.ErrInvalid
		}
		var existing *string
		if err := tx.QueryRow(ctx, `SELECT to_regclass('ops_admission_v2.schema_version')::text`).Scan(&existing); err != nil {
			return a.ErrUnavailable
		}
		if existing == nil {
			if _, err := tx.Exec(ctx, schemaSQL); err != nil {
				return a.ErrUnavailable
			}
			if _, err := tx.Exec(ctx, `INSERT INTO ops_admission_v2.schema_version VALUES(true,1,$1)`, SchemaChecksum()); err != nil {
				return a.ErrUnavailable
			}
		}
		if err := checkSchema(ctx, tx); err != nil {
			return err
		}
		app, reader, retention := pgx.Identifier{appRole}.Sanitize(), pgx.Identifier{readerRole}.Sanitize(), pgx.Identifier{retentionRole}.Sanitize()
		statements := []string{
			`REVOKE ALL ON SCHEMA ops_admission_v2 FROM PUBLIC`,
			`REVOKE ALL ON ALL TABLES IN SCHEMA ops_admission_v2 FROM PUBLIC,` + app + `,` + reader + `,` + retention,
			`REVOKE ALL ON ALL SEQUENCES IN SCHEMA ops_admission_v2 FROM PUBLIC,` + app + `,` + reader + `,` + retention,
			`REVOKE ALL ON ALL FUNCTIONS IN SCHEMA ops_admission_v2 FROM PUBLIC`,
			`GRANT USAGE ON SCHEMA ops_admission_v2 TO ` + app + `,` + reader + `,` + retention,
			`GRANT SELECT ON ALL TABLES IN SCHEMA ops_admission_v2 TO ` + app + `,` + reader,
			`GRANT SELECT ON ops_admission_v2.schema_version,ops_admission_v2.network_state,ops_admission_v2.travel_records,ops_admission_v2.compliance_events TO ` + retention,
			`GRANT INSERT ON ops_admission_v2.travel_records,ops_admission_v2.compliance_events,ops_admission_v2.qualified_tx_origins,ops_admission_v2.extra_privacy_witnesses,ops_admission_v2.tx_shares TO ` + app,
			`GRANT UPDATE(used_at,used_tx_hash) ON ops_admission_v2.travel_records TO ` + app,
			`GRANT DELETE ON ops_admission_v2.travel_records TO ` + app + `,` + retention,
			`GRANT DELETE ON ops_admission_v2.compliance_events TO ` + retention,
			`GRANT USAGE ON SEQUENCE ops_admission_v2.compliance_events_id_seq TO ` + app,
			`GRANT EXECUTE ON FUNCTION ops_admission_v2.valid_recipients(text[]) TO ` + app,
		}
		version, err := schemaVersion(ctx, tx)
		if err != nil {
			return err
		}
		if version == 2 {
			statements = append(statements, creationGrantStatements(app)...)
		}
		for _, sql := range statements {
			if _, err := tx.Exec(ctx, sql); err != nil {
				return a.ErrUnavailable
			}
		}
		return nil
	})
}

func offlineConnection(ctx context.Context, dsn string, timeout time.Duration, callback func(context.Context, pgx.Tx) error) error {
	if strings.TrimSpace(dsn) == "" {
		return a.ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	config, err := pgx.ParseConfig(dsn)
	if err != nil {
		return a.ErrUnavailable
	}
	config.ConnectTimeout = 3 * time.Second
	conn, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		return a.ErrUnavailable
	}
	defer closeConnection(conn)
	tx, err := conn.Begin(ctx)
	if err != nil {
		return a.ErrUnavailable
	}
	defer rollback(tx)
	if _, err := tx.Exec(ctx, `SELECT set_config('lock_timeout','1s',true),set_config('statement_timeout','25s',true),pg_advisory_xact_lock(49222381407003)`); err != nil {
		return a.ErrUnavailable
	}
	if err := callback(ctx, tx); err != nil {
		return err
	}
	if tx.Commit(ctx) != nil {
		return a.ErrUnavailable
	}
	return nil
}

var expectedColumns = map[string]map[string]string{
	"schema_version":          {"singleton": "boolean", "version": "integer", "source_checksum": "text"},
	"network_state":           {"network_key": "bytea", "environment": "text", "chain_id": "text", "genesis_hash": "bytea", "deployment_id": "text", "generation": "uuid", "ready": "boolean", "coverage_digest": "bytea", "history_floor": "timestamp with time zone"},
	"travel_records":          {"id": "uuid", "network_key": "bytea", "org_id": "uuid", "actor_id": "text", "originator_data": "jsonb", "beneficiary_data": "jsonb", "transfer_type": "text", "token": "bytea", "beneficiary": "bytea", "amount_wei": "text", "amount_fiat": "numeric", "currency": "text", "created_at": "timestamp with time zone", "expires_at": "timestamp with time zone", "used_at": "timestamp with time zone", "used_tx_hash": "bytea", "created_by_actor": "text", "creation_policy_digest": "bytea", "quote_digest": "bytea"},
	"compliance_events":       {"id": "bigint", "network_key": "bytea", "tx_hash": "bytea", "actor_id": "text", "org_id": "uuid", "kind": "text", "coverage": "text", "from_address": "bytea", "to_address": "bytea", "token": "bytea", "amount_wei": "text", "amount_fiat": "numeric", "threshold_fiat": "numeric", "currency": "text", "decision": "text", "monitored": "boolean", "reason": "text", "record_id": "uuid", "decision_at": "timestamp with time zone", "policy_digest": "bytea", "quote_digest": "bytea", "quote_id": "text", "quote_source": "text", "quote_value": "numeric", "quote_as_of": "timestamp with time zone", "quote_observed_at": "timestamp with time zone", "anchor_hash": "bytea", "anchor_number": "numeric", "anchor_timestamp": "numeric", "evidence_profile": "text"},
	"qualified_tx_origins":    {"network_key": "bytea", "tx_hash": "bytea", "actor_id": "text", "org_id": "uuid", "first_admitted_at": "timestamp with time zone", "witness_id": "bytea", "anchor_hash": "bytea", "anchor_number": "numeric", "anchor_timestamp": "numeric", "evidence_profile": "text", "wallet_version": "bytea", "decision_at": "timestamp with time zone", "manifest_digest": "bytea", "compliance_digest": "bytea", "wallet_evidence_at": "timestamp with time zone"},
	"extra_privacy_witnesses": {"network_key": "bytea", "tx_hash": "bytea", "witness_id": "bytea", "anchor_hash": "bytea", "anchor_number": "numeric", "anchor_timestamp": "numeric", "evidence_profile": "text", "wallet_version": "bytea", "decision_at": "timestamp with time zone", "manifest_digest": "bytea", "compliance_digest": "bytea", "wallet_evidence_at": "timestamp with time zone"},
	"tx_shares":               {"network_key": "bytea", "tx_hash": "bytea", "sender_actor_id": "text", "sender_org_id": "uuid", "recipients": "text[]", "recipient_digest": "bytea", "declared_at": "timestamp with time zone", "anchor_hash": "bytea", "anchor_number": "numeric", "anchor_timestamp": "numeric", "manifest_digest": "bytea", "wallet_version": "bytea", "wallet_evidence_at": "timestamp with time zone"},
}

var creationColumns = map[string]map[string]string{
	"creation_capacity":       {"network_key": "bytea", "work_count": "bigint", "plan_count": "bigint", "plan_bytes": "bigint", "wallet_ref_count": "bigint", "factory_ref_count": "bigint"},
	"creation_plans":          {"network_key": "bytea", "tx_hash": "bytea", "plan_digest": "bytea", "version": "integer", "payload": "bytea", "entry_count": "integer", "root_org": "uuid", "manifest_digest": "bytea", "runtime_digest": "bytea", "chain_id": "text", "evidence_profile": "text", "created_at": "timestamp with time zone"},
	"creation_authority_refs": {"network_key": "bytea", "tx_hash": "bytea", "seed_digest": "bytea", "plan_digest": "bytea", "kind": "text", "branch": "smallint", "wallet_actor": "text", "wallet_org": "uuid", "witness_id": "bytea", "anchor_hash": "bytea", "anchor_number": "numeric", "anchor_timestamp": "numeric", "evidence_profile": "text", "manifest_digest": "bytea", "runtime_digest": "bytea", "captured_at": "timestamp with time zone"},
	"creation_work":           {"network_key": "bytea", "tx_hash": "bytea", "generation": "bigint", "created_at": "timestamp with time zone", "updated_at": "timestamp with time zone"},
}

func schemaColumns(version int) map[string]map[string]string {
	out := map[string]map[string]string{}
	for table, cols := range expectedColumns {
		out[table] = cols
	}
	if version == 2 {
		for table, cols := range creationColumns {
			out[table] = cols
		}
	}
	return out
}
func schemaVersion(ctx context.Context, q querier) (int, error) {
	var version, count int
	var checksum string
	if err := q.QueryRow(ctx, `SELECT version,source_checksum,(SELECT count(*) FROM ops_admission_v2.schema_version)FROM ops_admission_v2.schema_version WHERE singleton`).Scan(&version, &checksum, &count); err != nil || count != 1 {
		return 0, a.ErrUnavailable
	}
	if version == 1 && checksum == SchemaChecksum() || version == 2 && checksum == CreationSchemaChecksum() {
		return version, nil
	}
	return 0, a.ErrUnavailable
}
func creationGrantStatements(app string) []string {
	return []string{
		`GRANT INSERT ON ops_admission_v2.creation_plans,ops_admission_v2.creation_authority_refs,ops_admission_v2.creation_work TO ` + app,
		`GRANT UPDATE(generation,updated_at) ON ops_admission_v2.creation_work TO ` + app,
		`GRANT UPDATE(work_count,plan_count,plan_bytes,wallet_ref_count,factory_ref_count) ON ops_admission_v2.creation_capacity TO ` + app,
	}
}

// MigrateCreationIntents is an explicit offline upgrade. Existing network
// readiness must already be fenced with old processes stopped. No pool is
// assumed to be invalidated just by changing a schema version row.
func MigrateCreationIntents(ctx context.Context, dsn, appRole, readerRole, retentionRole string) error {
	if err := Migrate(ctx, dsn, appRole, readerRole, retentionRole); err != nil {
		return err
	}
	return offlineConnection(ctx, dsn, 30*time.Second, func(ctx context.Context, tx pgx.Tx) error {
		if err := checkSchema(ctx, tx); err != nil {
			return err
		}
		var ready bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM ops_admission_v2.network_state WHERE ready)`).Scan(&ready); err != nil {
			return a.ErrUnavailable
		}
		if ready {
			return a.ErrConflict
		}
		version, err := schemaVersion(ctx, tx)
		if err != nil {
			return err
		}
		if version == 1 {
			if _, err := tx.Exec(ctx, creationSchemaSQL); err != nil {
				return a.ErrUnavailable
			}
			if _, err := tx.Exec(ctx, `UPDATE ops_admission_v2.schema_version SET version=2,source_checksum=$1 WHERE singleton`, CreationSchemaChecksum()); err != nil {
				return a.ErrUnavailable
			}
		}
		app, reader := pgx.Identifier{appRole}.Sanitize(), pgx.Identifier{readerRole}.Sanitize()
		statements := []string{`REVOKE ALL ON ops_admission_v2.creation_capacity,ops_admission_v2.creation_plans,ops_admission_v2.creation_authority_refs,ops_admission_v2.creation_work FROM PUBLIC,` + app + `,` + reader + `,` + pgx.Identifier{retentionRole}.Sanitize(), `GRANT SELECT ON ops_admission_v2.creation_capacity,ops_admission_v2.creation_plans,ops_admission_v2.creation_authority_refs,ops_admission_v2.creation_work TO ` + app + `,` + reader}
		statements = append(statements, creationGrantStatements(app)...)
		for _, sql := range statements {
			if _, err := tx.Exec(ctx, sql); err != nil {
				return a.ErrUnavailable
			}
		}
		return checkSchema(ctx, tx)
	})
}

func (s *Store) CheckSchema(ctx context.Context) error {
	ctx, cancel := bounded(ctx)
	defer cancel()
	return checkSchema(ctx, s.pool)
}
func checkSchema(ctx context.Context, q querier) error {
	version, err := schemaVersion(ctx, q)
	if err != nil {
		return err
	}
	remaining := map[string]map[string]string{}
	for table, cols := range schemaColumns(version) {
		remaining[table] = map[string]string{}
		for col, typ := range cols {
			remaining[table][col] = typ
		}
	}
	rows, err := q.Query(ctx, `SELECT c.relname,a.attname,format_type(a.atttypid,a.atttypmod) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace JOIN pg_attribute a ON a.attrelid=c.oid WHERE n.nspname='ops_admission_v2' AND c.relkind='r' AND a.attnum>0 AND NOT a.attisdropped ORDER BY c.relname,a.attnum`)
	if err != nil {
		return a.ErrUnavailable
	}
	defer rows.Close()
	for rows.Next() {
		var table, col, typ string
		if rows.Scan(&table, &col, &typ) != nil || remaining[table][col] != typ {
			return a.ErrUnavailable
		}
		delete(remaining[table], col)
	}
	if rows.Err() != nil {
		return a.ErrUnavailable
	}
	rows.Close()
	for _, cols := range remaining {
		if len(cols) != 0 {
			return a.ErrUnavailable
		}
	}
	var trigger bool
	if err := q.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='ops_admission_v2.travel_records'::regclass AND tgname='travel_record_monotonic' AND tgenabled='O' AND NOT tgisinternal)`).Scan(&trigger); err != nil || !trigger {
		return a.ErrUnavailable
	}
	var indexes int
	if err := q.QueryRow(ctx, `SELECT count(*) FROM pg_index i JOIN pg_class c ON c.oid=i.indexrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='ops_admission_v2' AND i.indisvalid AND i.indisready AND c.relname=ANY($1::text[])`, []string{"travel_scoped_used_hash", "travel_unused_lookup", "travel_org_page", "compliance_org_page", "compliance_scoped_record", "shares_recipients", "qualified_tx_origins_pkey", "extra_privacy_witnesses_pkey", "tx_shares_pkey"}).Scan(&indexes); err != nil || indexes != 9 {
		return a.ErrUnavailable
	}
	if version == 2 {
		return checkCreationSchema(ctx, q)
	}
	return nil
}

func (s *Store) checkPrivileges(ctx context.Context) error {
	var unsafe bool
	if err := s.pool.QueryRow(ctx, `SELECT r.rolsuper OR r.rolcreaterole OR r.rolcreatedb
 OR has_schema_privilege(current_user,'ops_admission_v2','CREATE')
 OR EXISTS(SELECT 1 FROM pg_database d WHERE d.datname=current_database() AND pg_has_role(current_user,d.datdba,'MEMBER'))
 OR EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='ops_admission_v2' AND pg_has_role(current_user,c.relowner,'MEMBER'))
 OR EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname NOT IN('ops_admission_v2','pg_catalog','information_schema') AND n.nspname NOT LIKE 'pg_toast%' AND n.nspname NOT LIKE 'pg_temp%' AND c.relkind IN('r','p','v','m') AND(has_table_privilege(current_user,c.oid,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,TRIGGER') OR has_any_column_privilege(current_user,c.oid,'SELECT,INSERT,UPDATE')))
 FROM pg_roles r WHERE r.rolname=current_user`).Scan(&unsafe); err != nil || unsafe {
		return a.ErrUnavailable
	}
	for table, cols := range schemaColumns(s.schemaVersion) {
		name := "ops_admission_v2." + table
		data := table != "schema_version" && table != "network_state" && table != "creation_capacity"
		for _, privilege := range []string{"INSERT", "DELETE", "TRUNCATE", "REFERENCES", "TRIGGER"} {
			want := s.mode == "app" && (privilege == "INSERT" && data || privilege == "DELETE" && table == "travel_records") || s.mode == "retention" && privilege == "DELETE" && (table == "travel_records" || table == "compliance_events")
			var actual bool
			if err := s.pool.QueryRow(ctx, `SELECT has_table_privilege(current_user,$1,$2)`, name, privilege).Scan(&actual); err != nil || actual != want {
				return a.ErrUnavailable
			}
		}
		for col := range cols {
			selectWant := s.mode != "retention" || table == "schema_version" || table == "network_state" || table == "travel_records" || table == "compliance_events"
			insertWant := s.mode == "app" && data
			updateWant := s.mode == "app" && (table == "travel_records" && (col == "used_at" || col == "used_tx_hash") || table == "creation_work" && (col == "generation" || col == "updated_at") || table == "creation_capacity" && col != "network_key")
			var sel, ins, upd bool
			if err := s.pool.QueryRow(ctx, `SELECT has_column_privilege(current_user,$1,$2,'SELECT'),has_column_privilege(current_user,$1,$2,'INSERT'),has_column_privilege(current_user,$1,$2,'UPDATE')`, name, col).Scan(&sel, &ins, &upd); err != nil || sel != selectWant || ins != insertWant || upd != updateWant {
				return a.ErrUnavailable
			}
		}
	}
	var usage, update, select_ bool
	if err := s.pool.QueryRow(ctx, `SELECT has_sequence_privilege(current_user,'ops_admission_v2.compliance_events_id_seq','USAGE'),has_sequence_privilege(current_user,'ops_admission_v2.compliance_events_id_seq','UPDATE'),has_sequence_privilege(current_user,'ops_admission_v2.compliance_events_id_seq','SELECT')`).Scan(&usage, &update, &select_); err != nil || usage != (s.mode == "app") || update || select_ {
		return a.ErrUnavailable
	}
	return nil
}
