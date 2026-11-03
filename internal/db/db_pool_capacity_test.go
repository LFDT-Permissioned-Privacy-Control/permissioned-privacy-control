package db

import "testing"

// The startup pool check reads how many connections the server accepts for
// ordinary roles (RD-1410).
func TestAvailableConnectionsReadsTheServerLimit(t *testing.T) {
	d := setupTestDB(t)
	n, err := d.AvailableConnections(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	var max, reserved int
	if err := d.conn.QueryRowContext(t.Context(), `SELECT current_setting('max_connections')::int, current_setting('superuser_reserved_connections')::int`).Scan(&max, &reserved); err != nil {
		t.Fatal(err)
	}
	if n != max-reserved || n <= 0 {
		t.Fatalf("available %d, want %d - %d", n, max, reserved)
	}
}
