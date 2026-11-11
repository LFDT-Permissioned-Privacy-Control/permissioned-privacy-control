package ssosql

import (
	"bytes"
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"github.com/jackc/pgx/v5"
	"regexp"
	"slices"
	"strings"
	"time"
)

//go:embed migrations/001.sql
var schemaSQL string

//go:embed schema/catalog-v1.json
var expectedCatalog []byte
var roleName = regexp.MustCompile(`^[a-z][a-z0-9_]{0,62}$`)

func validRoles(r Roles) bool {
	return roleName.MatchString(r.App) && roleName.MatchString(r.Retention) && !strings.HasPrefix(r.App, "pg_") && !strings.HasPrefix(r.Retention, "pg_") && r.App != r.Retention
}
func SchemaChecksum() string {
	h := sha256.Sum256([]byte(schemaSQL))
	return "sha256:" + hex.EncodeToString(h[:])
}

type querier interface {
	QueryRow(context.Context, string, ...any) pgx.Row
	Query(context.Context, string, ...any) (pgx.Rows, error)
}

func checkCatalog(ctx context.Context, q querier) error {
	var raw []byte
	if q.QueryRow(ctx, catalogQuery).Scan(&raw) != nil || len(raw) > 128<<10 {
		return ErrUnavailable
	}
	var a, z any
	if json.Unmarshal(raw, &a) != nil || json.Unmarshal(expectedCatalog, &z) != nil {
		return ErrUnavailable
	}
	ab, _ := json.Marshal(a)
	zb, _ := json.Marshal(z)
	if !bytes.Equal(ab, zb) {
		return ErrUnavailable
	}
	var good bool
	e := q.QueryRow(ctx, `SELECT current_setting('server_version_num')::int/10000=16 AND NOT pg_is_in_recovery() AND current_setting('transaction_read_only')='off'
 AND NOT EXISTS(SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='ops_sso_v1' AND (p.proowner<>n.nspowner OR pg_get_function_identity_arguments(p.oid)<>'' OR pg_get_function_result(p.oid)<>'trigger'))
 AND NOT EXISTS(SELECT 1 FROM pg_namespace n CROSS JOIN LATERAL aclexplode(coalesce(n.nspacl,acldefault('n',n.nspowner)))a WHERE n.nspname='ops_sso_v1' AND (a.grantee=0 OR a.is_grantable AND a.grantee<>n.nspowner))`).Scan(&good)
	if e != nil || !good {
		return ErrUnavailable
	}
	return nil
}
func rolesAvailable(ctx context.Context, q querier, r Roles) error {
	if !validRoles(r) {
		return ErrInvalid
	}
	var good bool
	e := q.QueryRow(ctx, `SELECT count(*)=2 AND bool_and(rolcanlogin AND NOT rolinherit AND NOT rolsuper AND NOT rolcreatedb AND NOT rolcreaterole AND NOT rolreplication AND NOT rolbypassrls AND rolname<>current_user AND NOT EXISTS(SELECT 1 FROM pg_auth_members m WHERE m.member=pg_roles.oid)) FROM pg_roles WHERE rolname=ANY($1::text[])`, []string{r.App, r.Retention}).Scan(&good)
	if e != nil || !good {
		return ErrRole
	}
	return nil
}
func installACL(ctx context.Context, tx pgx.Tx, r Roles) error {
	if rolesAvailable(ctx, tx, r) != nil {
		return ErrRole
	}
	app, ret := pgx.Identifier{r.App}.Sanitize(), pgx.Identifier{r.Retention}.Sanitize()
	for _, s := range []string{`GRANT USAGE ON SCHEMA ops_sso_v1 TO ` + app + `,` + ret, `GRANT SELECT ON ops_sso_v1.state TO ` + app + `,` + ret, `GRANT SELECT,INSERT ON ops_sso_v1.transactions TO ` + app, `GRANT SELECT,DELETE ON ops_sso_v1.transactions TO ` + ret} {
		if _, e := tx.Exec(ctx, s); e != nil {
			return ErrUnavailable
		}
	}
	for mode, role := range map[string]string{"app": app, "retention": ret} {
		for table, cols := range map[string][]string{"state": stateUpdates[mode], "transactions": rowUpdates[mode]} {
			names := make([]string, len(cols))
			for i, s := range cols {
				names[i] = pgx.Identifier{s}.Sanitize()
			}
			if _, e := tx.Exec(ctx, `GRANT UPDATE(`+strings.Join(names, ",")+`) ON ops_sso_v1.`+table+` TO `+role); e != nil {
				return ErrUnavailable
			}
		}
	}
	return nil
}
func tableAllowed(mode, table, p string) bool {
	if p == "SELECT" {
		return true
	}
	return table == "transactions" && (mode == "app" && p == "INSERT" || mode == "retention" && p == "DELETE")
}
func columnAllowed(mode, table, col, p string) bool {
	if tableAllowed(mode, table, p) {
		return true
	}
	if p != "UPDATE" {
		return false
	}
	if table == "state" {
		return slices.Contains(stateUpdates[mode], col)
	}
	return slices.Contains(rowUpdates[mode], col)
}
func checkPrivileges(ctx context.Context, q querier, r Roles, mode string) error {
	if !validRoles(r) || (mode != "app" && mode != "retention") {
		return ErrRole
	}
	role := r.App
	if mode == "retention" {
		role = r.Retention
	}
	var good bool
	e := q.QueryRow(ctx, `SELECT NOT r.rolsuper AND NOT r.rolinherit AND NOT r.rolcreaterole AND NOT r.rolcreatedb AND NOT r.rolreplication AND NOT r.rolbypassrls AND r.rolcanlogin
 AND NOT EXISTS(SELECT 1 FROM pg_auth_members m WHERE m.member=r.oid)
 AND NOT has_database_privilege(r.oid,current_database(),'CREATE')
 AND NOT EXISTS(SELECT 1 FROM pg_namespace n WHERE left(n.nspname,8)<>'pg_temp_' AND left(n.nspname,14)<>'pg_toast_temp_' AND has_schema_privilege(r.oid,n.oid,'CREATE'))
 AND NOT EXISTS(SELECT 1 FROM pg_database d WHERE d.datname=current_database() AND d.datdba=r.oid)
 AND NOT EXISTS(SELECT 1 FROM pg_namespace n WHERE n.nspname='ops_sso_v1' AND n.nspowner=r.oid)
 AND NOT EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname NOT IN('ops_sso_v1','pg_catalog','information_schema','pg_toast') AND left(n.nspname,8)<>'pg_temp_' AND left(n.nspname,14)<>'pg_toast_temp_' AND c.relkind IN('r','p','v','m','f') AND(has_table_privilege(r.oid,c.oid,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,TRIGGER,REFERENCES') OR has_any_column_privilege(r.oid,c.oid,'SELECT,INSERT,UPDATE,REFERENCES')))
 AND has_schema_privilege(r.oid,'ops_sso_v1','USAGE')
 AND NOT EXISTS(SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='ops_sso_v1' AND has_function_privilege(r.oid,p.oid,'EXECUTE'))
 FROM pg_roles r WHERE r.rolname=$1`, role).Scan(&good)
	if e != nil || !good {
		return ErrRole
	}
	// Explicit grantees are only the trusted owner and the two declared roles.
	e = q.QueryRow(ctx, `SELECT NOT EXISTS(SELECT 1 FROM pg_namespace n CROSS JOIN LATERAL aclexplode(coalesce(n.nspacl,acldefault('n',n.nspowner)))a WHERE n.nspname='ops_sso_v1' AND a.grantee<>n.nspowner AND a.grantee<>ALL(ARRAY[$1::regrole::oid,$2::regrole::oid]))
 AND NOT EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace CROSS JOIN LATERAL aclexplode(coalesce(c.relacl,acldefault('r',c.relowner)))a WHERE n.nspname='ops_sso_v1' AND(a.is_grantable AND a.grantee<>n.nspowner OR a.grantee<>n.nspowner AND a.grantee<>ALL(ARRAY[$1::regrole::oid,$2::regrole::oid])))
 AND NOT EXISTS(SELECT 1 FROM pg_attribute att JOIN pg_class c ON c.oid=att.attrelid JOIN pg_namespace n ON n.oid=c.relnamespace CROSS JOIN LATERAL aclexplode(att.attacl)a WHERE n.nspname='ops_sso_v1' AND(a.is_grantable AND a.grantee<>n.nspowner OR a.grantee<>n.nspowner AND a.grantee<>ALL(ARRAY[$1::regrole::oid,$2::regrole::oid])))
 AND NOT EXISTS(SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace CROSS JOIN LATERAL aclexplode(coalesce(p.proacl,acldefault('f',p.proowner)))a WHERE n.nspname='ops_sso_v1' AND a.grantee<>n.nspowner)`, r.App, r.Retention).Scan(&good)
	if e != nil || !good {
		return ErrRole
	}
	rows, e := q.Query(ctx, `SELECT c.relname,p,has_table_privilege($1,c.oid,p) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace CROSS JOIN unnest(ARRAY['SELECT','INSERT','UPDATE','DELETE','TRUNCATE','TRIGGER','REFERENCES'])p WHERE n.nspname='ops_sso_v1' AND c.relkind='r'`, role)
	if e != nil {
		return ErrUnavailable
	}
	count := 0
	for rows.Next() {
		var table, p string
		var got bool
		if rows.Scan(&table, &p, &got) != nil || got != tableAllowed(mode, table, p) {
			rows.Close()
			return ErrRole
		}
		count++
	}
	e = rows.Err()
	rows.Close()
	if e != nil || count != 14 {
		return ErrRole
	}
	rows, e = q.Query(ctx, `SELECT c.relname,a.attname,p,has_column_privilege($1,c.oid,a.attnum,p) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace JOIN pg_attribute a ON a.attrelid=c.oid CROSS JOIN unnest(ARRAY['SELECT','INSERT','UPDATE','REFERENCES'])p WHERE n.nspname='ops_sso_v1' AND c.relkind='r' AND a.attnum>0 AND NOT a.attisdropped`, role)
	if e != nil {
		return ErrUnavailable
	}
	count = 0
	for rows.Next() {
		var table, col, p string
		var got bool
		if rows.Scan(&table, &col, &p, &got) != nil || got != columnAllowed(mode, table, col, p) {
			rows.Close()
			return ErrRole
		}
		count++
	}
	e = rows.Err()
	rows.Close()
	if e != nil || count != 236 {
		return ErrRole
	}
	return nil
}
func offline(ctx context.Context, dsn string) (*pgx.Conn, error) {
	if strings.TrimSpace(dsn) == "" {
		return nil, ErrInvalid
	}
	c, e := pgx.ParseConfig(dsn)
	if e != nil {
		return nil, ErrUnavailable
	}
	c.ConnectTimeout = 3 * time.Second
	conn, e := pgx.ConnectConfig(ctx, c)
	if e != nil {
		return nil, ErrUnavailable
	}
	return conn, nil
}
func closeConn(c *pgx.Conn) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_ = c.Close(ctx)
}
func Migrate(ctx context.Context, dsn string, r Roles, drained bool) error {
	if !drained || !validRoles(r) {
		return ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	conn, e := offline(ctx, dsn)
	if e != nil {
		return e
	}
	defer closeConn(conn)
	tx, e := begin(ctx, conn)
	if e != nil {
		return e
	}
	defer rollback(tx)
	if _, e = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(7665821920)`); e != nil {
		return ErrUnavailable
	}
	var exists bool
	if tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_namespace WHERE nspname='ops_sso_v1')`).Scan(&exists) != nil {
		return ErrUnavailable
	}
	if !exists {
		if rolesAvailable(ctx, tx, r) != nil {
			return ErrRole
		}
		if _, e = tx.Exec(ctx, schemaSQL); e != nil {
			return ErrUnavailable
		}
		if e = installACL(ctx, tx, r); e != nil {
			return e
		}
	}
	if e = checkOwner(ctx, tx); e != nil {
		return e
	}
	if checkCatalog(ctx, tx) != nil {
		return ErrUnavailable
	}
	for _, m := range []string{"app", "retention"} {
		if e = checkPrivileges(ctx, tx, r, m); e != nil {
			return e
		}
	}
	if e = tx.Commit(ctx); e != nil {
		return ErrUnavailable
	}
	return nil
}
func checkOwner(ctx context.Context, q querier) error {
	var ok bool
	e := q.QueryRow(ctx, `SELECT current_user=pg_get_userbyid(nspowner) FROM pg_namespace WHERE nspname='ops_sso_v1'`).Scan(&ok)
	if e != nil || !ok {
		return ErrRole
	}
	return nil
}
