package admissionsql

import (
	"context"
	_ "embed"
	"encoding/json"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"
	h "privacy-proxy/internal/historynamespace"
)

const namespaceSchema = "ops_history_namespace_v1"

var namespaceTables = []string{"legacy_contract_lifetimes", "namespace_cohorts", "namespace_network_state", "namespace_transfers", "revoked_namespace_cohorts"}

//go:embed migrations/namespace-001.sql
var namespaceSchemaSQL string

//go:embed migrations/namespace-001-catalog.json
var namespaceCatalogJSON []byte

type namespaceColumnType struct{ Table, Name, Type string }

func namespaceColumns() (map[string]map[string]string, error) {
	var catalog struct {
		Tables []string
		Types  []namespaceColumnType
	}
	if json.Unmarshal(namespaceCatalogJSON, &catalog) != nil || !slices.Equal(catalog.Tables, namespaceTables) || len(catalog.Types) != 75 {
		return nil, h.ErrUnavailable
	}
	columns := map[string]map[string]string{}
	for _, c := range catalog.Types {
		if !slices.Contains(namespaceTables, c.Table) {
			return nil, h.ErrUnavailable
		}
		if columns[c.Table] == nil {
			columns[c.Table] = map[string]string{}
		}
		if _, exists := columns[c.Table][c.Name]; exists {
			return nil, h.ErrUnavailable
		}
		columns[c.Table][c.Name] = c.Type
	}
	return columns, nil
}

func checkNamespaceSchema(ctx context.Context, q querier) error {
	columns, err := namespaceColumns()
	if err != nil {
		return err
	}
	rows, err := q.Query(ctx, `SELECT c.relname,a.attname,format_type(a.atttypid,a.atttypmod) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace JOIN pg_attribute a ON a.attrelid=c.oid WHERE n.nspname=$1 AND c.relkind='r' AND a.attnum>0 AND NOT a.attisdropped ORDER BY c.relname,a.attnum`, namespaceSchema)
	if err != nil {
		return h.ErrUnavailable
	}
	for rows.Next() {
		var table, name, typ string
		if rows.Scan(&table, &name, &typ) != nil || columns[table][name] != typ {
			rows.Close()
			return h.ErrUnavailable
		}
		delete(columns[table], name)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return h.ErrUnavailable
	}
	for _, c := range columns {
		if len(c) != 0 {
			return h.ErrUnavailable
		}
	}
	if checkCatalogInSchema(ctx, q, namespaceSchema, namespaceCatalogJSON, namespaceTables, namespaceTables) != nil {
		return h.ErrUnavailable
	}
	var extra bool
	if q.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname=$1)
 OR EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=$1 AND c.relkind='S')
 OR EXISTS(SELECT 1 FROM pg_namespace n CROSS JOIN LATERAL aclexplode(COALESCE(n.nspacl,acldefault('n',n.nspowner)))g WHERE n.nspname=$1 AND(g.grantee=0 OR(g.grantee<>n.nspowner AND g.privilege_type<>'USAGE')))
 OR EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace CROSS JOIN LATERAL aclexplode(COALESCE(c.relacl,acldefault('r',c.relowner)))g WHERE n.nspname=$1 AND(g.grantee=0 OR(g.grantee<>c.relowner AND g.privilege_type<>'SELECT')))
 OR EXISTS(SELECT 1 FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid JOIN pg_namespace n ON n.oid=c.relnamespace CROSS JOIN LATERAL aclexplode(a.attacl)g WHERE n.nspname=$1 AND a.attnum>0 AND(g.grantee=0 OR(g.grantee<>c.relowner AND g.privilege_type<>'SELECT')))`, namespaceSchema).Scan(&extra) != nil || extra {
		return h.ErrUnavailable
	}
	return nil
}

func namespaceReadRelations() []string {
	out := make([]string, 0, len(namespaceTables)+len(factsReadTables))
	for _, table := range namespaceTables {
		out = append(out, namespaceSchema+"."+table)
	}
	for _, table := range factsReadTables {
		out = append(out, "ops_admission_v2."+table)
	}
	return out
}

// Effective checks include PUBLIC, column grants and role memberships. A serving
// reader is distinct from all owners/writers and has no SQL mutation API.
func checkNamespacePrivileges(ctx context.Context, q querier) error {
	allowed := namespaceReadRelations()
	var unsafe bool
	if q.QueryRow(ctx, `SELECT r.rolsuper OR r.rolcreaterole OR r.rolcreatedb OR r.rolreplication OR r.rolbypassrls
 OR EXISTS(SELECT 1 FROM pg_roles other WHERE other.oid<>r.oid AND pg_has_role(current_user,other.oid,'MEMBER'))
 OR has_database_privilege(current_user,current_database(),'CREATE')
 OR EXISTS(SELECT 1 FROM pg_namespace n WHERE n.oid<>pg_my_temp_schema() AND NOT pg_is_other_temp_schema(n.oid) AND has_schema_privilege(current_user,n.oid,'CREATE'))
 OR has_schema_privilege(current_user,'ops_admission_v2','CREATE') OR has_schema_privilege(current_user,$2,'CREATE')
 OR NOT has_schema_privilege(current_user,'ops_admission_v2','USAGE') OR NOT has_schema_privilege(current_user,$2,'USAGE')
 OR EXISTS(SELECT 1 FROM pg_database d WHERE d.datname=current_database() AND pg_has_role(current_user,d.datdba,'MEMBER'))
 OR EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname NOT IN('pg_catalog','information_schema') AND n.nspname NOT LIKE 'pg_toast%' AND n.nspname NOT LIKE 'pg_temp%' AND(
  pg_has_role(current_user,c.relowner,'MEMBER') OR
  (c.relkind IN('r','p','v','m','f') AND(has_table_privilege(current_user,c.oid,'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') OR has_any_column_privilege(current_user,c.oid,'INSERT,UPDATE,REFERENCES') OR
   (NOT(n.nspname||'.'||c.relname=ANY($1::text[])) AND(has_table_privilege(current_user,c.oid,'SELECT') OR has_any_column_privilege(current_user,c.oid,'SELECT'))))) OR
  (c.relkind='S' AND has_sequence_privilege(current_user,c.oid,'SELECT,USAGE,UPDATE'))))
 OR EXISTS(SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname NOT IN('pg_catalog','information_schema') AND n.nspname NOT LIKE 'pg_temp%' AND has_function_privilege(current_user,p.oid,'EXECUTE'))
 OR EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace CROSS JOIN LATERAL aclexplode(COALESCE(c.relacl,acldefault('r',c.relowner)))g WHERE n.nspname=$2 AND g.grantee<>c.relowner AND g.grantee<>r.oid)
 OR EXISTS(SELECT 1 FROM pg_namespace n CROSS JOIN LATERAL aclexplode(COALESCE(n.nspacl,acldefault('n',n.nspowner)))g WHERE n.nspname=$2 AND g.grantee<>n.nspowner AND g.grantee<>r.oid)
 OR EXISTS(SELECT 1 FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid JOIN pg_namespace n ON n.oid=c.relnamespace CROSS JOIN LATERAL aclexplode(a.attacl)g WHERE n.nspname=$2 AND a.attnum>0 AND g.grantee<>c.relowner AND g.grantee<>r.oid)
 FROM pg_roles r WHERE r.rolname=current_user`, allowed, namespaceSchema).Scan(&unsafe) != nil || unsafe {
		return h.ErrUnavailable
	}
	for _, relation := range allowed {
		var read bool
		if q.QueryRow(ctx, `SELECT has_table_privilege(current_user,$1,'SELECT')`, relation).Scan(&read) != nil || !read {
			return h.ErrUnavailable
		}
	}
	return nil
}

// MigrateNamespace creates only the separate source schema. Existing admission
// schema bytes, versions and role grants are preserved. All clients must be
// drained by the offline operator; DDL cannot revoke an already running image.
func MigrateNamespace(ctx context.Context, dsn, readerRole string, acknowledgeDrained bool) error {
	if ctx == nil || !acknowledgeDrained || !rolePattern.MatchString(readerRole) {
		return h.ErrInvalid
	}
	err := offlineConnection(ctx, dsn, 60*time.Second, func(ctx context.Context, tx pgx.Tx) error {
		if version, err := schemaVersion(ctx, tx); err != nil || version != 3 || checkSchema(ctx, tx) != nil {
			return h.ErrUnavailable
		}
		var owner string
		var roleSafe bool
		if tx.QueryRow(ctx, `SELECT current_user,EXISTS(SELECT 1 FROM pg_roles r WHERE r.rolname=$1 AND NOT r.rolsuper AND NOT r.rolcreaterole AND NOT r.rolcreatedb AND NOT r.rolreplication AND NOT r.rolbypassrls AND NOT EXISTS(SELECT 1 FROM pg_roles other WHERE other.oid<>r.oid AND pg_has_role(r.oid,other.oid,'MEMBER')))`, readerRole).Scan(&owner, &roleSafe) != nil || owner == readerRole || !roleSafe {
			return h.ErrUnavailable
		}
		var existing *string
		if tx.QueryRow(ctx, `SELECT to_regclass('ops_history_namespace_v1.namespace_network_state')::text`).Scan(&existing) != nil {
			return h.ErrUnavailable
		}
		var otherAccess, ownAccess bool
		if tx.QueryRow(ctx, `SELECT
 EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname NOT IN('ops_history_namespace_v1','pg_catalog','information_schema') AND n.nspname NOT LIKE 'pg_toast%' AND n.nspname NOT LIKE 'pg_temp%' AND c.relkind IN('r','p','v','m','f') AND(has_table_privilege($1,c.oid,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') OR has_any_column_privilege($1,c.oid,'SELECT,INSERT,UPDATE,REFERENCES'))),
 EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='ops_history_namespace_v1' AND c.relkind='r' AND has_table_privilege($1,c.oid,'SELECT'))`, readerRole).Scan(&otherAccess, &ownAccess) != nil || otherAccess && !ownAccess {
			return h.ErrUnavailable
		}
		if existing == nil {
			// A fresh namespace reader is a dedicated blank role, not an upgrade
			// of the existing app/observer/facts role whose old client must stay valid.
			var privileged bool
			if tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname NOT IN('pg_catalog','information_schema') AND n.nspname NOT LIKE 'pg_toast%' AND n.nspname NOT LIKE 'pg_temp%' AND c.relkind IN('r','p','v','m','f') AND(has_table_privilege($1,c.oid,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') OR has_any_column_privilege($1,c.oid,'SELECT,INSERT,UPDATE,REFERENCES')))`, readerRole).Scan(&privileged) != nil || privileged {
				return h.ErrUnavailable
			}
			if _, err := tx.Exec(ctx, namespaceSchemaSQL); err != nil {
				return h.ErrUnavailable
			}
		} else if checkNamespaceSchema(ctx, tx) != nil {
			return h.ErrUnavailable
		}
		role := pgx.Identifier{readerRole}.Sanitize()
		if _, err := tx.Exec(ctx, `GRANT USAGE ON SCHEMA ops_history_namespace_v1,ops_admission_v2 TO `+role); err != nil {
			return h.ErrUnavailable
		}
		for _, relation := range namespaceReadRelations() {
			if _, err := tx.Exec(ctx, `GRANT SELECT ON `+relation+` TO `+role); err != nil {
				return h.ErrUnavailable
			}
		}
		if _, err := tx.Exec(ctx, `SET LOCAL ROLE `+role); err != nil {
			return h.ErrUnavailable
		}
		if checkNamespacePrivileges(ctx, tx) != nil || checkNamespaceSchema(ctx, tx) != nil {
			return h.ErrUnavailable
		}
		if _, err := tx.Exec(ctx, `RESET ROLE`); err != nil {
			return h.ErrUnavailable
		}
		return nil
	})
	if err != nil {
		return h.ErrUnavailable
	}
	return nil
}
