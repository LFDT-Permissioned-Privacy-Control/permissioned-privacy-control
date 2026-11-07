package admissionsql

import (
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"
	a "privacy-proxy/internal/admission"
	"privacy-proxy/internal/creationfacts"
)

//go:embed migrations/003.sql
var observerSchemaSQL string

//go:embed migrations/003-catalog.json
var observerCatalogJSON []byte

func ObserverSchemaChecksum() string {
	sum := sha256.Sum256([]byte(schemaSQL + "\x00" + creationSchemaSQL + "\x00" + observerSchemaSQL))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func observerCatalog() (map[string]map[string]string, []string) {
	var data struct {
		Tables []string
		Types  []struct{ Table, Name, Type string }
	}
	if json.Unmarshal(observerCatalogJSON, &data) != nil || len(data.Tables) != 11 {
		return nil, nil
	}
	columns := map[string]map[string]string{}
	for _, c := range data.Types {
		if columns[c.Table] == nil {
			columns[c.Table] = map[string]string{}
		}
		columns[c.Table][c.Name] = c.Type
	}
	return columns, data.Tables
}
func checkObserverSchema(ctx context.Context, q querier) error {
	_, tables := observerCatalog()
	if len(tables) != 11 {
		return a.ErrUnavailable
	}
	return checkOperationalCatalog(ctx, q, observerCatalogJSON, tables, 3)
}

func OpenCreationObserved(ctx context.Context, dsn string, limits a.CreationLimits, observed ...creationfacts.Limits) (*Store, error) {
	if len(observed) > 1 || (len(observed) == 1 && !observed[0].Valid()) {
		return nil, a.ErrInvalid
	}
	s, err := OpenCreationWriter(ctx, dsn, limits)
	if err != nil {
		return nil, err
	}
	if s.schemaVersion != 3 {
		s.Close()
		return nil, a.ErrUnavailable
	}
	if len(observed) == 1 {
		s.observerLimits = observed[0]
	}
	return s, nil
}
func OpenObserver(ctx context.Context, dsn string, observed ...creationfacts.Limits) (*Store, error) {
	if len(observed) > 1 || (len(observed) == 1 && !observed[0].Valid()) {
		return nil, a.ErrInvalid
	}
	s, err := open(ctx, dsn, "observer")
	if err != nil {
		return nil, err
	}
	if s.schemaVersion != 3 {
		s.Close()
		return nil, a.ErrUnavailable
	}
	if len(observed) == 1 {
		s.observerLimits = observed[0]
	}
	return s, nil
}
func OpenCreationFacts(ctx context.Context, dsn string) (*Store, error) {
	s, err := open(ctx, dsn, "facts")
	if err != nil {
		return nil, err
	}
	if s.schemaVersion != 3 {
		s.Close()
		return nil, a.ErrUnavailable
	}
	return s, nil
}
func (s *Store) CreationCoveredSchemaVersion() int {
	if s == nil || s.mode != "app" || s.schemaVersion != 3 {
		return 0
	}
	return 3
}

var observerReadTables = []string{"schema_version", "network_state", "creation_capacity", "creation_plans", "creation_authority_refs", "creation_work", "qualified_tx_origins", "extra_privacy_witnesses", "creation_capture_coverage", "creation_observer_state", "creation_headers", "creation_births", "creation_authority_associations", "revoked_creation_capture_epochs"}
var factsReadTables = []string{"schema_version", "network_state", "creation_authority_refs", "creation_capture_coverage", "creation_observer_state", "creation_headers", "creation_births", "creation_authority_associations", "revoked_creation_capture_epochs"}
var schedulingColumns = []string{"processed_generation", "next_attempt_at", "retry_count", "outcome", "inclusion_hash", "inclusion_number", "last_reorg_epoch"}
var appCapacityColumns = []string{"work_count", "plan_count", "plan_bytes", "wallet_ref_count", "factory_ref_count", "capture_coverage_count", "capture_coverage_bytes"}
var workerCapacityColumns = []string{"header_count", "birth_count", "association_count"}

func observerGrantStatements(app, reader, retention, observer, facts string) []string {
	roles := app + "," + reader + "," + retention + "," + observer + "," + facts
	statements := []string{`REVOKE ALL ON ALL TABLES IN SCHEMA ops_admission_v2 FROM PUBLIC,` + roles, `REVOKE ALL ON ALL SEQUENCES IN SCHEMA ops_admission_v2 FROM PUBLIC,` + roles, `GRANT USAGE ON SCHEMA ops_admission_v2 TO ` + roles, `GRANT SELECT ON ALL TABLES IN SCHEMA ops_admission_v2 TO ` + app + `,` + reader,
		`GRANT SELECT ON ops_admission_v2.schema_version,ops_admission_v2.network_state,ops_admission_v2.travel_records,ops_admission_v2.compliance_events TO ` + retention,
		`GRANT INSERT ON ops_admission_v2.travel_records,ops_admission_v2.compliance_events,ops_admission_v2.qualified_tx_origins,ops_admission_v2.extra_privacy_witnesses,ops_admission_v2.tx_shares,ops_admission_v2.creation_plans,ops_admission_v2.creation_authority_refs,ops_admission_v2.creation_work,ops_admission_v2.creation_capture_coverage TO ` + app,
		`GRANT UPDATE(used_at,used_tx_hash)ON ops_admission_v2.travel_records TO ` + app, `GRANT DELETE ON ops_admission_v2.travel_records TO ` + app + `,` + retention, `GRANT DELETE ON ops_admission_v2.compliance_events TO ` + retention, `GRANT USAGE ON SEQUENCE ops_admission_v2.compliance_events_id_seq TO ` + app, `GRANT EXECUTE ON FUNCTION ops_admission_v2.valid_recipients(text[])TO ` + app,
		`GRANT UPDATE(generation,updated_at)ON ops_admission_v2.creation_work TO ` + app,
		`GRANT UPDATE(` + joinIdentifiers(appCapacityColumns) + `)ON ops_admission_v2.creation_capacity TO ` + app,
		`GRANT INSERT ON ops_admission_v2.creation_headers,ops_admission_v2.creation_births,ops_admission_v2.creation_authority_associations TO ` + observer, `GRANT DELETE ON ops_admission_v2.creation_headers TO ` + observer,
		`GRANT UPDATE(` + joinIdentifiers(schedulingColumns) + `)ON ops_admission_v2.creation_work TO ` + observer, `GRANT UPDATE(` + joinIdentifiers(workerCapacityColumns) + `)ON ops_admission_v2.creation_capacity TO ` + observer}
	columns, _ := observerCatalog()
	stateCols := []string{}
	for c := range columns["creation_observer_state"] {
		if c != "network_key" && c != "floor_number" && c != "floor_hash" {
			stateCols = append(stateCols, c)
		}
	}
	slices.Sort(stateCols)
	statements = append(statements, `GRANT UPDATE(`+joinIdentifiers(stateCols)+`)ON ops_admission_v2.creation_observer_state TO `+observer)
	for _, table := range observerReadTables {
		statements = append(statements, `GRANT SELECT ON ops_admission_v2.`+pgx.Identifier{table}.Sanitize()+` TO `+observer)
	}
	for _, table := range factsReadTables {
		statements = append(statements, `GRANT SELECT ON ops_admission_v2.`+pgx.Identifier{table}.Sanitize()+` TO `+facts)
	}
	return statements
}
func joinIdentifiers(names []string) string {
	out := ""
	for i, n := range names {
		if i > 0 {
			out += ","
		}
		out += pgx.Identifier{n}.Sanitize()
	}
	return out
}

// MigrateCreationObserver is offline only. Old images reject schema3 at startup;
// this cannot fence an old live pool, which operators must stop/drain first.
func MigrateCreationObserver(ctx context.Context, dsn, app, reader, retention, observer, facts string) error {
	roles := []string{app, reader, retention, observer, facts}
	seen := map[string]bool{}
	for _, r := range roles {
		if !rolePattern.MatchString(r) || seen[r] {
			return a.ErrInvalid
		}
		seen[r] = true
	}
	// Existing migrations remain byte-exact and explicit, never runtime DDL.
	version := 0
	if err := offlineConnection(ctx, dsn, 30*time.Second, func(ctx context.Context, tx pgx.Tx) error {
		var existing *string
		if err := tx.QueryRow(ctx, `SELECT to_regclass('ops_admission_v2.schema_version')::text`).Scan(&existing); err != nil {
			return a.ErrUnavailable
		}
		if existing != nil {
			var err error
			version, err = schemaVersion(ctx, tx)
			return err
		}
		return nil
	}); err != nil {
		return err
	}
	if version != 3 {
		if err := MigrateCreationIntents(ctx, dsn, app, reader, retention); err != nil {
			return err
		}
	}
	return offlineConnection(ctx, dsn, 30*time.Second, func(ctx context.Context, tx pgx.Tx) error {
		var roleCount int
		if err := tx.QueryRow(ctx, `SELECT count(*)FROM pg_roles WHERE rolname=ANY($1::text[])AND NOT rolsuper AND NOT rolcreaterole AND NOT rolcreatedb AND rolname<>current_user`, roles).Scan(&roleCount); err != nil || roleCount != 5 {
			return a.ErrInvalid
		}
		if err := checkSchema(ctx, tx); err != nil {
			return err
		}
		var ready bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM ops_admission_v2.network_state WHERE ready)`).Scan(&ready); err != nil || ready {
			return a.ErrConflict
		}
		version, err := schemaVersion(ctx, tx)
		if err != nil {
			return err
		}
		if version == 2 {
			if _, err = tx.Exec(ctx, observerSchemaSQL); err != nil {
				return a.ErrUnavailable
			}
			if _, err = tx.Exec(ctx, `UPDATE ops_admission_v2.schema_version SET version=3,source_checksum=$1 WHERE singleton`, ObserverSchemaChecksum()); err != nil {
				return a.ErrUnavailable
			}
		} else if version != 3 {
			return a.ErrUnavailable
		}
		for _, sql := range observerGrantStatements(pgx.Identifier{app}.Sanitize(), pgx.Identifier{reader}.Sanitize(), pgx.Identifier{retention}.Sanitize(), pgx.Identifier{observer}.Sanitize(), pgx.Identifier{facts}.Sanitize()) {
			if _, err := tx.Exec(ctx, sql); err != nil {
				return a.ErrUnavailable
			}
		}
		return checkSchema(ctx, tx)
	})
}

func (s *Store) observerPrivilege(table, col, privilege string) bool {
	if privilege == "SELECT" {
		if s.mode == "observer" {
			return slices.Contains(observerReadTables, table)
		}
		if s.mode == "facts" {
			return slices.Contains(factsReadTables, table)
		}
		return s.mode != "retention" || table == "schema_version" || table == "network_state" || table == "travel_records" || table == "compliance_events"
	}
	if s.mode == "observer" {
		switch privilege {
		case "INSERT":
			return table == "creation_headers" || table == "creation_births" || table == "creation_authority_associations"
		case "DELETE":
			return table == "creation_headers"
		case "UPDATE":
			return table == "creation_observer_state" && col != "network_key" && col != "floor_number" && col != "floor_hash" || table == "creation_work" && slices.Contains(schedulingColumns, col) || table == "creation_capacity" && slices.Contains(workerCapacityColumns, col)
		}
		return false
	}
	if s.mode == "facts" {
		return false
	}
	data := table == "travel_records" || table == "compliance_events" || table == "qualified_tx_origins" || table == "extra_privacy_witnesses" || table == "tx_shares" || table == "creation_plans" || table == "creation_authority_refs" || table == "creation_work" || table == "creation_capture_coverage"
	switch privilege {
	case "INSERT":
		return s.mode == "app" && data
	case "DELETE":
		return s.mode == "app" && table == "travel_records" || s.mode == "retention" && (table == "travel_records" || table == "compliance_events")
	case "UPDATE":
		return s.mode == "app" && (table == "travel_records" && (col == "used_at" || col == "used_tx_hash") || table == "creation_work" && (col == "generation" || col == "updated_at") || table == "creation_capacity" && slices.Contains(appCapacityColumns, col))
	}
	return false
}
