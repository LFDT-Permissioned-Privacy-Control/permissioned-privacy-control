package identitysql_test

import (
	"github.com/jackc/pgx/v5"
	"privacy-proxy/internal/operational/identitysql"
	"testing"
)

// Legitimate TEMP remains usable; a similarly named persistent schema never
// hides foreign privileges from any operational role.
func TestRoleSchemaExclusions(t *testing.T) {
	f := setup(t)
	temp, e := pgx.Connect(t.Context(), f.appDSN)
	if e != nil {
		t.Fatal(e)
	}
	defer temp.Close(t.Context())
	if _, e = temp.Exec(t.Context(), `CREATE TEMP TABLE role_temp_control(n int)`); e != nil {
		t.Fatal(e)
	}
	for _, role := range []struct {
		name, sqlRole string
		open          func() error
	}{
		{"app", "broker_app", func() error {
			s, e := identitysql.Open(t.Context(), f.appDSN, f.scope, f.clock)
			if s != nil {
				s.Close()
			}
			return e
		}},
		{"proof", "broker_proof", func() error {
			s, e := identitysql.OpenProofV2(t.Context(), f.proofDSN, f.scope, f.clock)
			if s != nil {
				s.Close()
			}
			return e
		}},
		{"retention", "broker_retention", func() error {
			s, e := identitysql.OpenRetention(t.Context(), f.retentionDSN, f.scope, f.clock)
			if s != nil {
				s.Close()
			}
			return e
		}},
	} {
		if e := role.open(); e != nil {
			t.Fatal("ordinary TEMP affected baseline", role.name, e)
		}
		for _, schema := range []string{"pgxtempyuntrusted", "pgxtoastuntrusted"} {
			t.Run(role.name+"/"+schema, func(t *testing.T) {
				if _, e := f.owner.Exec(t.Context(), `CREATE SCHEMA `+schema+`;CREATE TABLE `+schema+`.private_data(n int);GRANT USAGE ON SCHEMA `+schema+` TO `+role.sqlRole+`;GRANT SELECT ON `+schema+`.private_data TO `+role.sqlRole); e != nil {
					t.Fatal(e)
				}
				if e := role.open(); e == nil {
					t.Error("foreign persistent SELECT accepted under temp-like schema name")
				}
				if _, e := f.owner.Exec(t.Context(), `DROP SCHEMA `+schema+` CASCADE`); e != nil {
					t.Fatal(e)
				}
				if e := role.open(); e != nil {
					t.Fatal("repaired role rejected", e)
				}
			})
		}
	}
}
