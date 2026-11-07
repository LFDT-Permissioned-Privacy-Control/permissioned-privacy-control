package admissionsql

import (
	"context"
	_ "embed"
	"encoding/json"

	a "privacy-proxy/internal/admission"
)

func OpenCreationWriter(ctx context.Context, dsn string, limits a.CreationLimits) (*Store, error) {
	if !limits.Valid() {
		return nil, a.ErrInvalid
	}
	s, err := open(ctx, dsn, "app")
	if err != nil {
		return nil, err
	}
	if s.schemaVersion != 2 && s.schemaVersion != 3 {
		s.Close()
		return nil, a.ErrUnavailable
	}
	s.creationLimits = limits
	return s, nil
}

// The expected definitions were read from PostgreSQL 16 after applying the
// embedded migrations in a disposable database. Runtime performs no DDL.
//
//go:embed migrations/002-catalog.json
var creationCatalogJSON []byte

func (s *Store) CreationIntentSchemaVersion() int {
	if s == nil || s.mode != "app" {
		return 0
	}
	return s.schemaVersion
}

type creationColumnAttribute struct {
	Table, Name, Default, Identity, Generated string
	NotNull                                   bool
}

func checkCreationSchema(ctx context.Context, q querier) error {
	return checkOperationalCatalog(ctx, q, creationCatalogJSON, []string{"creation_capacity", "creation_plans", "creation_authority_refs", "creation_work"}, 2)
}

func checkOperationalCatalog(ctx context.Context, q querier, catalog []byte, tables []string, version int) error {
	allowed := []string{}
	for name := range schemaColumns(version) {
		allowed = append(allowed, name)
	}
	return checkCatalogInSchema(ctx, q, "ops_admission_v2", catalog, tables, allowed)
}

// The admission wrapper retains its existing schema and complete allowed set.
// Namespace facts use the same exact checks in their separate closed schema.
func checkCatalogInSchema(ctx context.Context, q querier, schema string, catalog []byte, tables, allowed []string) error {
	var expected struct {
		Constraints []struct{ Table, Name, Type, Definition string }
		Indexes     []struct{ Name, Definition string }
		Columns     []creationColumnAttribute
	}
	if json.Unmarshal(catalog, &expected) != nil {
		return a.ErrUnavailable
	}
	columns := map[string]creationColumnAttribute{}
	for _, c := range expected.Columns {
		columns[c.Table+"/"+c.Name] = c
	}
	rows, err := q.Query(ctx, `SELECT c.relname,a.attname,a.attnotnull,COALESCE(pg_get_expr(d.adbin,d.adrelid),''),a.attidentity::text,a.attgenerated::text FROM pg_attribute a JOIN pg_class c ON a.attrelid=c.oid JOIN pg_namespace n ON c.relnamespace=n.oid LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE n.nspname=$2 AND c.relname=ANY($1::text[]) AND a.attnum>0 AND NOT a.attisdropped`, tables, schema)
	if err != nil {
		return a.ErrUnavailable
	}
	for rows.Next() {
		var c creationColumnAttribute
		if rows.Scan(&c.Table, &c.Name, &c.NotNull, &c.Default, &c.Identity, &c.Generated) != nil || columns[c.Table+"/"+c.Name] != c {
			rows.Close()
			return a.ErrUnavailable
		}
		delete(columns, c.Table+"/"+c.Name)
	}
	err = rows.Err()
	rows.Close()
	if err != nil || len(columns) > 0 {
		return a.ErrUnavailable
	}
	constraints := map[string]string{}
	for _, c := range expected.Constraints {
		constraints[c.Table+"/"+c.Name] = c.Type + "/" + c.Definition
	}
	rows, err = q.Query(ctx, `SELECT r.relname,c.conname,c.contype::text,pg_get_constraintdef(c.oid,true),c.convalidated FROM pg_constraint c JOIN pg_class r ON c.conrelid=r.oid JOIN pg_namespace n ON r.relnamespace=n.oid WHERE n.nspname=$2 AND r.relname=ANY($1::text[])`, tables, schema)
	if err != nil {
		return a.ErrUnavailable
	}
	for rows.Next() {
		var table, name, kind, definition string
		var valid bool
		if rows.Scan(&table, &name, &kind, &definition, &valid) != nil || !valid || constraints[table+"/"+name] != kind+"/"+definition {
			rows.Close()
			return a.ErrUnavailable
		}
		delete(constraints, table+"/"+name)
	}
	err = rows.Err()
	rows.Close()
	if err != nil || len(constraints) > 0 {
		return a.ErrUnavailable
	}
	indexes := map[string]string{}
	for _, i := range expected.Indexes {
		indexes[i.Name] = i.Definition
	}
	rows, err = q.Query(ctx, `SELECT i.relname,pg_get_indexdef(i.oid),x.indisvalid AND x.indisready FROM pg_index x JOIN pg_class i ON x.indexrelid=i.oid JOIN pg_class t ON x.indrelid=t.oid JOIN pg_namespace n ON t.relnamespace=n.oid WHERE n.nspname=$2 AND t.relname=ANY($1::text[])`, tables, schema)
	if err != nil {
		return a.ErrUnavailable
	}
	for rows.Next() {
		var name, definition string
		var valid bool
		if rows.Scan(&name, &definition, &valid) != nil || !valid || indexes[name] != definition {
			rows.Close()
			return a.ErrUnavailable
		}
		delete(indexes, name)
	}
	err = rows.Err()
	rows.Close()
	if err != nil || len(indexes) > 0 {
		return a.ErrUnavailable
	}
	var unsafe bool
	if err := q.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_trigger g JOIN pg_class c ON g.tgrelid=c.oid JOIN pg_namespace n ON c.relnamespace=n.oid WHERE n.nspname=$2 AND c.relname=ANY($1::text[]) AND NOT g.tgisinternal) OR EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON c.relnamespace=n.oid WHERE n.nspname=$2 AND c.relname=ANY($1::text[]) AND(c.relkind<>'r' OR c.relpersistence<>'p' OR c.relrowsecurity OR c.relforcerowsecurity))`, tables, schema).Scan(&unsafe); err != nil || unsafe {
		return a.ErrUnavailable
	}
	if err := q.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON c.relnamespace=n.oid WHERE n.nspname=$2 AND c.relkind IN('r','p','v','m','f') AND NOT(c.relname=ANY($1::text[])))`, allowed, schema).Scan(&unsafe); err != nil || unsafe {
		return a.ErrUnavailable
	}
	return nil
}
