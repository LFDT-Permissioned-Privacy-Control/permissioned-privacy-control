package identitysql

import (
	"context"
	"encoding/json"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5"
	b "privacy-proxy/internal/identitybroker"
)

func columnsV2() map[string][]string {
	var v struct {
		Columns []struct {
			Table string `json:"table_name"`
			Name  string `json:"attname"`
		}
	}
	if json.Unmarshal(catalogV2, &v) != nil {
		panic("invalid compiled identity schema")
	}
	out := map[string][]string{}
	for _, c := range v.Columns {
		out[c.Table] = append(out[c.Table], c.Name)
	}
	return out
}
func tableAllowed(mode, table, privilege string) bool {
	switch privilege {
	case "SELECT":
		return mode != "proof" || table == "metadata" || table == "privado_challenges" || table == "privado_offers"
	case "INSERT":
		return mode == "app" && (table == "pending_requests" || table == "renewal_families" || table == "privado_challenges") || mode == "proof" && table == "privado_offers"
	case "DELETE":
		return mode == "app" && (table == "pending_requests" || table == "privado_challenges") || mode == "retention" && (table == "pending_requests" || table == "renewal_families" || table == "privado_challenges")
	default:
		return false
	}
}
func columnAllowed(mode, table, column, privilege string) bool {
	if tableAllowed(mode, table, privilege) {
		return true
	}
	return mode == "app" && table == "renewal_families" && privilege == "UPDATE" && (column == "generation" || column == "current_handle_hash" || column == "encryption_key_id" || column == "refresh_ciphertext" || column == "last_rotated_at" || column == "revoked_at")
}
func installV2ACL(ctx context.Context, tx pgx.Tx, roles []string) error {
	if len(roles) != 3 {
		return b.ErrInvalid
	}
	var count int
	if tx.QueryRow(ctx, `SELECT count(*) FROM pg_roles WHERE rolname=ANY($1::text[]) AND NOT rolsuper AND NOT rolcreaterole AND NOT rolcreatedb AND rolname<>current_user`, roles).Scan(&count) != nil || count != 3 {
		return b.ErrInvalid
	}
	quoted := make([]string, 3)
	for i, r := range roles {
		quoted[i] = pgx.Identifier{r}.Sanitize()
	}
	list := strings.Join(quoted, ",")
	cols := columnsV2()
	tables := make([]string, 0, len(cols))
	for table := range cols {
		tables = append(tables, table)
	}
	sort.Strings(tables)
	for _, table := range tables {
		names := []string{}
		for _, c := range cols[table] {
			names = append(names, pgx.Identifier{c}.Sanitize())
		}
		joined := strings.Join(names, ",")
		if _, e := tx.Exec(ctx, `REVOKE SELECT(`+joined+`),INSERT(`+joined+`),UPDATE(`+joined+`),REFERENCES(`+joined+`) ON ops_identity_v2.`+pgx.Identifier{table}.Sanitize()+` FROM PUBLIC,`+list); e != nil {
			return b.ErrUnavailable
		}
	}
	statements := []string{`REVOKE ALL ON SCHEMA ops_identity_v2 FROM PUBLIC,` + list, `REVOKE ALL ON ALL TABLES IN SCHEMA ops_identity_v2 FROM PUBLIC,` + list, `REVOKE ALL ON ALL FUNCTIONS IN SCHEMA ops_identity_v2 FROM PUBLIC,` + list, `GRANT USAGE ON SCHEMA ops_identity_v2 TO ` + list}
	for i, mode := range []string{"app", "proof", "retention"} {
		for _, table := range tables {
			for _, p := range []string{"SELECT", "INSERT", "DELETE"} {
				if tableAllowed(mode, table, p) {
					statements = append(statements, `GRANT `+p+` ON ops_identity_v2.`+pgx.Identifier{table}.Sanitize()+` TO `+quoted[i])
				}
			}
		}
	}
	statements = append(statements, `GRANT UPDATE(generation,current_handle_hash,encryption_key_id,refresh_ciphertext,last_rotated_at,revoked_at) ON ops_identity_v2.renewal_families TO `+quoted[0])
	for _, sql := range statements {
		if _, e := tx.Exec(ctx, sql); e != nil {
			return b.ErrUnavailable
		}
	}
	return nil
}
func checkV2Privileges(ctx context.Context, q querier, role, mode string) error {
	if mode != "app" && mode != "proof" && mode != "retention" {
		return b.ErrInvalid
	}
	if role == "" {
		if q.QueryRow(ctx, `SELECT current_user`).Scan(&role) != nil {
			return b.ErrUnavailable
		}
	}
	var unsafe bool
	err := q.QueryRow(ctx, `SELECT r.rolsuper OR r.rolcreaterole OR r.rolcreatedb OR has_schema_privilege(r.rolname,'ops_identity_v2','CREATE')
 OR EXISTS(SELECT 1 FROM pg_roles other WHERE other.oid<>r.oid AND pg_has_role(r.oid,other.oid,'MEMBER'))
 OR EXISTS(SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='ops_identity_v2' AND has_function_privilege(r.rolname,p.oid,'EXECUTE'))
 OR EXISTS(SELECT 1 FROM pg_database d WHERE d.datname=current_database() AND pg_has_role(r.oid,d.datdba,'MEMBER'))
 OR EXISTS(SELECT 1 FROM pg_namespace n WHERE n.nspname='ops_identity_v2' AND pg_has_role(r.oid,n.nspowner,'MEMBER'))
 OR EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname NOT IN('ops_identity_v2','pg_catalog','information_schema') AND n.nspname NOT LIKE 'pg_toast%' AND n.nspname NOT LIKE 'pg_temp%' AND c.relkind IN('r','p','v','m','f') AND(has_table_privilege(r.rolname,c.oid,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,TRIGGER,REFERENCES') OR has_any_column_privilege(r.rolname,c.oid,'SELECT,INSERT,UPDATE,REFERENCES')))
 FROM pg_roles r WHERE r.rolname=$1`, role).Scan(&unsafe)
	if err != nil || unsafe {
		return b.ErrUnavailable
	}
	rows, e := q.Query(ctx, `SELECT c.relname,p,has_table_privilege($1,c.oid,p) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace CROSS JOIN unnest(ARRAY['SELECT','INSERT','UPDATE','DELETE','TRUNCATE','TRIGGER','REFERENCES'])p WHERE n.nspname='ops_identity_v2' AND c.relkind='r'`, role)
	if e != nil {
		return b.ErrUnavailable
	}
	n := 0
	for rows.Next() {
		var table, p string
		var allowed bool
		if rows.Scan(&table, &p, &allowed) != nil || allowed != tableAllowed(mode, table, p) {
			rows.Close()
			return b.ErrUnavailable
		}
		n++
	}
	e = rows.Err()
	rows.Close()
	if e != nil || n != 35 {
		return b.ErrUnavailable
	}
	rows, e = q.Query(ctx, `SELECT c.relname,a.attname,p,has_column_privilege($1,c.oid,a.attnum,p) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace JOIN pg_attribute a ON a.attrelid=c.oid CROSS JOIN unnest(ARRAY['SELECT','INSERT','UPDATE','REFERENCES'])p WHERE n.nspname='ops_identity_v2' AND c.relkind='r' AND a.attnum>0 AND NOT a.attisdropped`, role)
	if e != nil {
		return b.ErrUnavailable
	}
	n = 0
	for rows.Next() {
		var table, column, p string
		var allowed bool
		if rows.Scan(&table, &column, &p, &allowed) != nil || allowed != columnAllowed(mode, table, column, p) {
			rows.Close()
			return b.ErrUnavailable
		}
		n++
	}
	e = rows.Err()
	rows.Close()
	if e != nil || n != 312 {
		return b.ErrUnavailable
	}
	return nil
}
