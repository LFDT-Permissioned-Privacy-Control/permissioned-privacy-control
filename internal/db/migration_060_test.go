package db

import (
	"context"
	"database/sql"
	"strings"
	"testing"

	"privacy-proxy/internal/db/migrations"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/tern/v2/migrate"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMigration060_OrgAdminCleanup faithfully exercises migration 060's one-time
// data normalization (RD-968). ResetTestDatabase preserves migration state, so the
// shared test DB is always fully migrated and cannot reproduce the pre-060 rows we
// need to seed. This test therefore drives a fresh, isolated database up to the
// migration *before* 060, seeds rows that violate the new invariants, applies 060,
// and asserts the outcome.
func TestMigration060_OrgAdminCleanup(t *testing.T) {
	connStr, cleanup := SetupTestContainer(t)
	defer cleanup()

	// SetupTestContainer falls back to the SHARED external Postgres when Docker is
	// unavailable. Driving migrations down/up on the shared DB would corrupt every
	// other test, so we only run when we have an isolated container.
	if strings.Contains(connStr, "privacy_proxy_test") {
		t.Skip("needs an isolated, non-migrated database (testcontainers unavailable)")
	}
	ctx := context.Background()

	pgxConn, err := pgx.Connect(ctx, connStr)
	require.NoError(t, err)
	defer pgxConn.Close(ctx)

	migrator, err := migrate.NewMigrator(ctx, pgxConn, "schema_version")
	require.NoError(t, err)
	require.NoError(t, migrator.LoadMigrations(migrations.FS))

	// Find migration 060's 1-based sequence (its position in tern's sorted
	// order) so the test applies 060 in isolation and stays correct as later
	// migrations (061+) are added — it must NOT assume 060 is the last one.
	var seq060 int32
	for i, m := range migrator.Migrations {
		if strings.HasPrefix(m.Name, "060_") {
			seq060 = int32(i + 1) // tern migration versions are 1-based
			break
		}
	}
	require.NotZero(t, seq060, "migration 060 should be loaded")

	// Migrate up to the migration just before 060 so we can seed offending rows
	// before the cleanup + CHECK constraint land.
	require.NoError(t, migrator.MigrateTo(ctx, seq060-1))

	sqlDB, err := sql.Open("pgx", connStr)
	require.NoError(t, err)
	defer sqlDB.Close()

	orgID := uuid.New().String()
	groupBoth := uuid.New().String()           // is_org_admin AND is_org_readonly_admin (Gap 2)
	groupAdminNoMethods := uuid.New().String() // is_org_admin, stale claims, empty methods (Gaps 1 & 3)
	groupNormal := uuid.New().String()         // not org admin — must be left untouched

	_, err = sqlDB.ExecContext(ctx,
		`INSERT INTO organizations (id, slug, name) VALUES ($1, $2, $3)`,
		orgID, "mig060-"+uuid.New().String()[:8], "Mig060 Org")
	require.NoError(t, err)

	insertGroup := func(id string, isAdmin, isRO bool) {
		slug := "g-" + uuid.New().String()[:8]
		_, e := sqlDB.ExecContext(ctx,
			`INSERT INTO groups (id, org_id, slug, name, path, is_org_admin, is_org_readonly_admin)
			 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
			id, orgID, slug, slug, slug, isAdmin, isRO)
		require.NoError(t, e)
	}
	insertGroup(groupBoth, true, true)
	insertGroup(groupAdminNoMethods, true, false)
	insertGroup(groupNormal, false, false)

	// group_access rows. Arrays are written as SQL literals (test-controlled, no
	// injection risk) to avoid driver array-encoding ceremony.
	insertAccess := func(groupID, methodsSQL, claimsSQL string) {
		_, e := sqlDB.ExecContext(ctx,
			`INSERT INTO group_access (id, group_id, allowed_methods, claims)
			 VALUES ($1, $2, `+methodsSQL+`, `+claimsSQL+`)`,
			uuid.New().String(), groupID)
		require.NoError(t, e)
	}
	insertAccess(groupBoth, `ARRAY['eth_call']::text[]`, `ARRAY['admin']::text[]`)
	insertAccess(groupAdminNoMethods, `ARRAY[]::text[]`, `ARRAY['deploy','upgrade']::text[]`)
	insertAccess(groupNormal, `ARRAY['eth_call']::text[]`, `ARRAY['deploy']::text[]`)

	// Apply migration 060 (only — not anything stacked after it).
	require.NoError(t, migrator.MigrateTo(ctx, seq060))

	// 1) Mutual exclusion: read-only flag cleared where is_org_admin was also set.
	var roStillSet bool
	require.NoError(t, sqlDB.QueryRowContext(ctx,
		`SELECT is_org_readonly_admin FROM groups WHERE id = $1`, groupBoth).Scan(&roStillSet))
	assert.False(t, roStillSet, "is_org_readonly_admin must be cleared where is_org_admin was also set")

	// 2) Claims cleared on org-admin groups (dead data — resolver grants all claims).
	claimLen := func(groupID string) int {
		var n int
		require.NoError(t, sqlDB.QueryRowContext(ctx,
			`SELECT COALESCE(array_length(claims, 1), 0) FROM group_access WHERE group_id = $1`, groupID).Scan(&n))
		return n
	}
	assert.Equal(t, 0, claimLen(groupBoth), "claims must be cleared on org-admin group (both-flags)")
	assert.Equal(t, 0, claimLen(groupAdminNoMethods), "claims must be cleared on org-admin group")

	// 3) Methods are NOT rewritten — no silent backfill / privilege grant.
	var methodLen int
	require.NoError(t, sqlDB.QueryRowContext(ctx,
		`SELECT COALESCE(array_length(allowed_methods, 1), 0) FROM group_access WHERE group_id = $1`, groupAdminNoMethods).Scan(&methodLen))
	assert.Equal(t, 0, methodLen, "migration must not backfill allowed_methods on org-admin groups")

	// 4) Non-org-admin group is untouched (claims preserved).
	assert.Equal(t, 1, claimLen(groupNormal), "claims on a non-org-admin group must be left untouched")

	// 5) The CHECK constraint now blocks reintroducing the contradiction.
	_, err = sqlDB.ExecContext(ctx,
		`UPDATE groups SET is_org_readonly_admin = true WHERE id = $1`, groupBoth)
	require.Error(t, err, "CHECK constraint must reject both admin flags on one group")
	assert.Contains(t, err.Error(), "groups_admin_role_exclusive")
}
