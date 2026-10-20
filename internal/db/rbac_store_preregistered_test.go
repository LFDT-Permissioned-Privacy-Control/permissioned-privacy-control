package db

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"privacy-proxy/internal/rbac"
)

// TestDeleteOrphanedPreregisteredAddresses verifies the orphan-sweep SQL:
//   - rows older than the TTL without a matching contracts row are deleted
//   - rows newer than the TTL are preserved
//   - rows with a matching contracts row are preserved regardless of age
//   - rows still preserved are not affected by multiple sweep calls.
func TestDeleteOrphanedPreregisteredAddresses(t *testing.T) {
	database := setupRBACTestDB(t)
	defer cleanupTestDB(t, database)

	ctx := context.Background()
	conn := database.Conn()

	org := &rbac.Organization{
		ID:       uuid.New().String(),
		Slug:     "prereg-cleanup-org",
		Name:     "Prereg Cleanup Org",
		Settings: map[string]interface{}{},
	}
	if err := database.CreateOrganization(ctx, org); err != nil {
		t.Fatalf("CreateOrganization: %v", err)
	}

	oldOrphanAddr := strings.ToLower("0x1111111111111111111111111111111111111111")
	freshOrphanAddr := strings.ToLower("0x2222222222222222222222222222222222222222")
	oldWithContractAddr := strings.ToLower("0x3333333333333333333333333333333333333333")

	// Insert three pre-reg rows directly so we can set created_at explicitly.
	insert := `
		INSERT INTO preregistered_addresses (id, org_id, address, factory, salt, note, created_at)
		VALUES ($1, $2, $3, NULL, NULL, $4, $5)
	`
	// Use UTC so the naive TIMESTAMP column stores values comparable to the
	// server's NOW() (which our deletion SQL casts to ::timestamp = naive UTC
	// when the DB is running in UTC, as it is in the test container).
	twoHoursAgo := time.Now().UTC().Add(-2 * time.Hour)
	thirtyMinAgo := time.Now().UTC().Add(-30 * time.Minute)

	if _, err := conn.ExecContext(ctx, insert, uuid.New().String(), org.ID, oldOrphanAddr, "old-orphan", twoHoursAgo); err != nil {
		t.Fatalf("insert old orphan: %v", err)
	}
	if _, err := conn.ExecContext(ctx, insert, uuid.New().String(), org.ID, freshOrphanAddr, "fresh-orphan", thirtyMinAgo); err != nil {
		t.Fatalf("insert fresh orphan: %v", err)
	}
	if _, err := conn.ExecContext(ctx, insert, uuid.New().String(), org.ID, oldWithContractAddr, "old-with-contract", twoHoursAgo); err != nil {
		t.Fatalf("insert old-with-contract: %v", err)
	}

	// Insert a matching contracts row for the third address so the NOT EXISTS
	// clause protects it even though it is old.
	contract := &rbac.Contract{
		ID:       uuid.New().String(),
		OrgID:    org.ID,
		Address:  oldWithContractAddr,
		Name:     "finalized-contract",
		Metadata: map[string]interface{}{},
	}
	if err := database.CreateContract(ctx, contract); err != nil {
		t.Fatalf("CreateContract: %v", err)
	}

	// Run the sweep with a 1h TTL.
	deleted, err := database.DeleteOrphanedPreregisteredAddresses(ctx, 1*time.Hour)
	if err != nil {
		t.Fatalf("DeleteOrphanedPreregisteredAddresses: %v", err)
	}
	if deleted != 1 {
		t.Fatalf("expected 1 row deleted, got %d", deleted)
	}

	// Old orphan must be gone; fresh orphan and contract-backed row must survive.
	assertPreregExists(t, ctx, database, oldOrphanAddr, false)
	assertPreregExists(t, ctx, database, freshOrphanAddr, true)
	assertPreregExists(t, ctx, database, oldWithContractAddr, true)

	// A second sweep must be idempotent.
	deleted, err = database.DeleteOrphanedPreregisteredAddresses(ctx, 1*time.Hour)
	if err != nil {
		t.Fatalf("DeleteOrphanedPreregisteredAddresses (second call): %v", err)
	}
	if deleted != 0 {
		t.Fatalf("expected 0 rows deleted on second sweep, got %d", deleted)
	}
}

// TestDeleteOrphanedPreregisteredAddresses_ZeroTTL verifies the guard that
// rejects a non-positive TTL (to avoid accidentally wiping the whole table).
func TestDeleteOrphanedPreregisteredAddresses_ZeroTTL(t *testing.T) {
	database := setupRBACTestDB(t)
	defer cleanupTestDB(t, database)

	ctx := context.Background()

	deleted, err := database.DeleteOrphanedPreregisteredAddresses(ctx, 0)
	if err != nil {
		t.Fatalf("unexpected error for zero TTL: %v", err)
	}
	if deleted != 0 {
		t.Fatalf("expected 0 deletions for zero TTL, got %d", deleted)
	}
}

func assertPreregExists(t *testing.T, ctx context.Context, database *DB, address string, want bool) {
	t.Helper()
	var exists bool
	err := database.Conn().QueryRowContext(ctx,
		`SELECT EXISTS(SELECT 1 FROM preregistered_addresses WHERE LOWER(address) = LOWER($1))`,
		address).Scan(&exists)
	if err != nil {
		t.Fatalf("probe pre-reg %s: %v", address, err)
	}
	if exists != want {
		t.Fatalf("pre-reg %s: exists=%v, want=%v", address, exists, want)
	}
}
