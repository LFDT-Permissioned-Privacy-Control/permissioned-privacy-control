package admissionsql_test

import (
	"github.com/jackc/pgx/v5"
	h "privacy-proxy/internal/historynamespace"
	"privacy-proxy/internal/operational/admissionsql"
	"testing"
)

// Legitimate TEMP remains usable; a similarly named persistent schema never
// hides foreign privileges from any operational role.
func TestRoleSchemaExclusions(t *testing.T) {
	d := setup(t)
	temp, e := pgx.Connect(t.Context(), d.appDSN)
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
		{"app", "admission_app", func() error {
			s, e := admissionsql.Open(t.Context(), d.appDSN)
			if s != nil {
				s.Close()
			}
			return e
		}},
		{"reader", "admission_reader", func() error {
			s, e := admissionsql.OpenReader(t.Context(), d.readerDSN)
			if s != nil {
				s.Close()
			}
			return e
		}},
		{"retention", "admission_retention", func() error {
			s, e := admissionsql.OpenRetention(t.Context(), d.retentionDSN)
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
				if _, e := d.owner.Exec(t.Context(), `CREATE SCHEMA `+schema+`;CREATE TABLE `+schema+`.private_data(n int);GRANT USAGE ON SCHEMA `+schema+` TO `+role.sqlRole+`;GRANT SELECT ON `+schema+`.private_data TO `+role.sqlRole); e != nil {
					t.Fatal(e)
				}
				if e := role.open(); e == nil {
					t.Error("foreign persistent SELECT accepted under temp-like schema name")
				}
				if _, e := d.owner.Exec(t.Context(), `DROP SCHEMA `+schema+` CASCADE`); e != nil {
					t.Fatal(e)
				}
				if e := role.open(); e != nil {
					t.Fatal("repaired role rejected", e)
				}
			})
		}
	}
}

func TestNamespaceRoleSchemaExclusions(t *testing.T) {
	d, dsn := namespaceDBSetup(t)
	binding, scope := creationScope(t, d.db)
	era := h.ModelEra{EntryNumber: 100, EntryHash: h.Hash{1}, EntryTimestamp: 1000, EndTimestampExclusive: 2000}
	if e := admissionsql.BootstrapNamespace(t.Context(), d.db.ownerDSN, binding, scope.State.Generation, era, h.DefaultCapacityLimits(), true, true); e != nil {
		t.Fatal(e)
	}
	metadata, e := admissionsql.ReadNamespaceOwnerMetadata(t.Context(), d.db.ownerDSN, binding)
	if e != nil {
		t.Fatal(e)
	}
	if e = admissionsql.FinalizeNamespaceRecovery(t.Context(), d.db.ownerDSN, binding, metadata.State, h.Digest{7}, true, true, 600); e != nil {
		t.Fatal(e)
	}
	temporary, e := pgx.Connect(t.Context(), dsn)
	if e != nil {
		t.Fatal(e)
	}
	defer temporary.Close(t.Context())
	if _, e = temporary.Exec(t.Context(), `CREATE TEMP TABLE role_temp_control(n int)`); e != nil {
		t.Fatal(e)
	}
	open := func() error {
		r, e := admissionsql.OpenNamespaceReader(t.Context(), dsn, binding, scope.State.Generation, era)
		if r != nil {
			r.Close()
		}
		return e
	}
	if e = open(); e != nil {
		t.Fatal("ordinary TEMP rejected", e)
	}
	for _, schema := range []string{"pgxtempyuntrusted", "pgxtoastuntrusted"} {
		t.Run(schema, func(t *testing.T) {
			if _, e := d.db.owner.Exec(t.Context(), `CREATE SCHEMA `+schema+`;CREATE TABLE `+schema+`.private_data(n int);GRANT USAGE ON SCHEMA `+schema+` TO namespace_reader;GRANT SELECT ON `+schema+`.private_data TO namespace_reader`); e != nil {
				t.Fatal(e)
			}
			if e := open(); e == nil {
				t.Error("foreign persistent SELECT accepted by namespace reader")
			}
			if _, e := d.db.owner.Exec(t.Context(), `DROP SCHEMA `+schema+` CASCADE`); e != nil {
				t.Fatal(e)
			}
			if e := open(); e != nil {
				t.Fatal("repaired namespace role rejected", e)
			}
		})
	}
}
