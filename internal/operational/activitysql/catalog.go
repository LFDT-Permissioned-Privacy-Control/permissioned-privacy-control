package activitysql

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"strings"

	a "privacy-proxy/internal/activitylog"
)

// Expected objects and permissions are derived from the independently replayed
// PostgreSQL16 catalog. Only explicit installed owner/role names are normalized.
//
//go:embed migrations/005-catalog.json
var expectedCatalog []byte

//go:embed migrations/005-acl.json
var expectedACL []byte

//go:embed migrations/catalog-query.sql
var catalogQuery string

//go:embed migrations/005.sql
var schemaSQL string

func normalizeOwner(v any, owner string) {
	switch x := v.(type) {
	case []any:
		for _, item := range x {
			normalizeOwner(item, owner)
		}
	case map[string]any:
		for key, value := range x {
			if key == "owner" && value == owner {
				x[key] = "$INSTALLED_OWNER"
			} else {
				normalizeOwner(value, owner)
			}
		}
	}
}
func equalJSON(a, b []byte) bool {
	var x, y any
	if json.Unmarshal(a, &x) != nil || json.Unmarshal(b, &y) != nil {
		return false
	}
	xb, _ := json.Marshal(x)
	yb, _ := json.Marshal(y)
	return bytes.Equal(xb, yb)
}
func schemaOwner(ctx context.Context, q queryer) (string, error) {
	var owner string
	if q.QueryRow(ctx, `SELECT pg_get_userbyid(nspowner) FROM pg_catalog.pg_namespace WHERE nspname='ops_activity_v1'`).Scan(&owner) != nil || owner == "" {
		return "", a.ErrUnavailable
	}
	return owner, nil
}
func checkSchema(ctx context.Context, q queryer) error {
	owner, err := schemaOwner(ctx, q)
	if err != nil {
		return err
	}
	var actual []byte
	if q.QueryRow(ctx, catalogQuery).Scan(&actual) != nil || len(actual) > 2<<20 {
		return a.ErrUnavailable
	}
	var observed, wanted any
	if json.Unmarshal(actual, &observed) != nil || json.Unmarshal(expectedCatalog, &wanted) != nil {
		return a.ErrUnavailable
	}
	normalizeOwner(observed, owner)
	normalizeOwner(wanted, "postgres")
	x, _ := json.Marshal(observed)
	y, _ := json.Marshal(wanted)
	if !bytes.Equal(x, y) {
		return fmt.Errorf("%w: activity schema differs from qualified catalog", a.ErrUnavailable)
	}
	return nil
}

func roleArgs(r RoleNames) []any { return []any{r.Writer, r.Reader, r.Retention} }

const actualRole = `CASE e.role WHEN 'b1_writer' THEN $2 WHEN 'b1_reader' THEN $3 WHEN 'b1_retention' THEN $4 END`

func checkRole(ctx context.Context, q queryer, roles RoleNames, mode string) error {
	if !roles.Valid() {
		return a.ErrInvalid
	}
	owner, err := schemaOwner(ctx, q)
	if err != nil {
		return err
	}
	var user string
	if q.QueryRow(ctx, `SELECT current_user::text`).Scan(&user) != nil {
		return a.ErrUnavailable
	}
	wanted := map[string]string{"writer": roles.Writer, "reader": roles.Reader, "retention": roles.Retention, "owner": owner}[mode]
	if user != wanted || wanted == "" {
		return a.ErrUnavailable
	}
	var safe bool
	if q.QueryRow(ctx, `SELECT count(*)=3 AND bool_and(rolcanlogin AND NOT rolinherit AND NOT rolsuper AND NOT rolcreatedb AND NOT rolcreaterole AND NOT rolreplication AND NOT rolbypassrls AND rolname<>$2 AND NOT pg_has_role(rolname,$2,'MEMBER')) AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_auth_members m JOIN pg_catalog.pg_roles r ON r.oid=m.member WHERE r.rolname=ANY($1::text[])) FROM pg_catalog.pg_roles WHERE rolname=ANY($1::text[])`, []string{roles.Writer, roles.Reader, roles.Retention}, owner).Scan(&safe) != nil || !safe {
		return a.ErrUnavailable
	}
	var expected map[string]json.RawMessage
	if json.Unmarshal(expectedACL, &expected) != nil {
		return a.ErrUnavailable
	}
	// A fixed number of batched privilege queries covers all qualified facts,
	// rather than one network round trip per catalog column.
	tests := []struct{ part, query string }{
		{"table", `SELECT coalesce(bool_and(has_table_privilege(` + actualRole + `,e.relation,e.privilege)=e.effective),false) FROM jsonb_to_recordset($1::jsonb)e(role text,relation text,privilege text,effective boolean)`},
		{"column", `SELECT coalesce(bool_and(has_column_privilege(` + actualRole + `,e.relation,e."column",e.privilege)=e.effective),false) FROM jsonb_to_recordset($1::jsonb)e(role text,relation text,"column" text,privilege text,effective boolean)`},
		{"sequence", `SELECT coalesce(bool_and(has_sequence_privilege(` + actualRole + `,e.sequence,e.privilege)=e.effective),false) FROM jsonb_to_recordset($1::jsonb)e(role text,sequence text,privilege text,effective boolean)`},
		{"function", `SELECT coalesce(bool_and(has_function_privilege(` + actualRole + `,'ops_activity_v1.'||e.function||'()','EXECUTE')=e.execute),false) FROM jsonb_to_recordset($1::jsonb)e(role text,function text,execute boolean)`},
		{"schema", `SELECT coalesce(bool_and(has_schema_privilege(` + actualRole + `,e.schema,e.privilege)=e.effective),false) FROM jsonb_to_recordset($1::jsonb)e(role text,schema text,privilege text,effective boolean)`},
	}
	for _, test := range tests {
		args := []any{string(expected[test.part]), roles.Writer, roles.Reader, roles.Retention}
		if q.QueryRow(ctx, test.query, args...).Scan(&safe) != nil || !safe {
			return fmt.Errorf("%w: activity %s privileges differ", a.ErrUnavailable, test.part)
		}
	}
	// PUBLIC must not bypass the caller allowlist. No grant options, role
	// membership, other-schema object privileges or schema creation are allowed.
	if q.QueryRow(ctx, `SELECT NOT EXISTS(
 SELECT 1 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace CROSS JOIN LATERAL aclexplode(coalesce(c.relacl,acldefault(CASE WHEN c.relkind='S'THEN'S'::"char" ELSE'r'::"char" END,c.relowner)))p
 WHERE (n.nspname='ops_activity_v1' OR n.nspname='public' AND c.relname='access_logs') AND(p.grantee=0 OR p.is_grantable AND p.grantee IN(SELECT oid FROM pg_catalog.pg_roles WHERE rolname=ANY($1::text[]))))
 AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace JOIN pg_catalog.pg_attribute a ON a.attrelid=c.oid CROSS JOIN LATERAL aclexplode(a.attacl)p WHERE p.is_grantable AND p.grantee IN(SELECT oid FROM pg_catalog.pg_roles WHERE rolname=ANY($1::text[])) AND n.nspname IN('public','ops_activity_v1'))
 AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_namespace n CROSS JOIN unnest($1::text[])r WHERE n.nspname NOT LIKE 'pg_%' AND n.nspname<>'information_schema' AND has_schema_privilege(r,n.oid,'CREATE'))
 AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace CROSS JOIN unnest($1::text[])r WHERE c.relkind IN('r','p','v','m') AND n.nspname NOT LIKE 'pg_%' AND n.nspname<>'information_schema' AND NOT(n.nspname='ops_activity_v1' OR n.nspname='public' AND c.relname IN('access_logs','audit_chain_anchor','audit_chain_checkpoint','audit_chain_reanchor')) AND(has_table_privilege(r,c.oid,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') OR has_any_column_privilege(r,c.oid,'SELECT,INSERT,UPDATE,REFERENCES')))
 AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace CROSS JOIN unnest($1::text[])r WHERE n.nspname NOT LIKE 'pg_%' AND n.nspname<>'information_schema' AND NOT(n.nspname='ops_activity_v1' AND p.proname IN('guard_log','guard_update','guard_delete')) AND has_function_privilege(r,p.oid,'EXECUTE'))`, []string{roles.Writer, roles.Reader, roles.Retention}).Scan(&safe) != nil || !safe {
		return a.ErrUnavailable
	}
	var defaults []byte
	if q.QueryRow(ctx, `SELECT coalesce(jsonb_agg(jsonb_build_object('owner',pg_get_userbyid(d.defaclrole),'schema',coalesce(n.nspname,''),'object_type',d.defaclobjtype::text,'acl',d.defaclacl::text)ORDER BY d.defaclrole,n.nspname,d.defaclobjtype),'[]'::jsonb)FROM pg_catalog.pg_default_acl d LEFT JOIN pg_catalog.pg_namespace n ON n.oid=d.defaclnamespace`).Scan(&defaults) != nil {
		return a.ErrUnavailable
	}
	var quotedOwner string
	if q.QueryRow(ctx, `SELECT quote_ident($1)`, owner).Scan(&quotedOwner) != nil {
		return a.ErrUnavailable
	}
	var rows []map[string]any
	var wantRows []map[string]any
	if json.Unmarshal(defaults, &rows) != nil || json.Unmarshal(expected["default_acl"], &wantRows) != nil {
		return a.ErrUnavailable
	}
	for _, row := range rows {
		if row["owner"] == owner {
			row["owner"] = "$INSTALLED_OWNER"
			if acl, ok := row["acl"].(string); ok {
				acl = strings.ReplaceAll(acl, "/"+quotedOwner, "/$INSTALLED_OWNER")
				row["acl"] = strings.ReplaceAll(acl, "/"+owner, "/$INSTALLED_OWNER")
			}
		}
	}
	for _, row := range wantRows {
		if row["owner"] == "postgres" {
			row["owner"] = "$INSTALLED_OWNER"
			if acl, ok := row["acl"].(string); ok {
				row["acl"] = strings.ReplaceAll(acl, "/postgres", "/$INSTALLED_OWNER")
			}
		}
	}
	x, _ := json.Marshal(rows)
	y, _ := json.Marshal(wantRows)
	if !equalJSON(x, y) {
		return a.ErrUnavailable
	}
	return nil
}
