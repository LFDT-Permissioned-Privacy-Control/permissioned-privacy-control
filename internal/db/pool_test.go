package db

import (
	"database/sql"
	"testing"
	"time"
)

// Proof for RD-1112 Tier-2: the DB pool is env-configurable and MaxIdle
// defaults to MaxOpen (so idle connections are retained, not churned under
// bursty load — the same connection-reuse principle proven for the upstream
// HTTP transport). These run without a live Postgres.

func TestPoolConfigDefaultIdleEqualsOpen(t *testing.T) {
	d := defaultPoolConfig()
	if d.maxIdleConns != d.maxOpenConns {
		t.Errorf("default MaxIdle must equal MaxOpen to avoid churn (RD-1112): open=%d idle=%d",
			d.maxOpenConns, d.maxIdleConns)
	}
}

func TestWithPoolAppliesValuesAndKeepsDefaults(t *testing.T) {
	p := defaultPoolConfig()
	WithPool(33, 17, 2*time.Minute)(&p)
	if p.maxOpenConns != 33 || p.maxIdleConns != 17 || p.connMaxLifetime != 2*time.Minute {
		t.Errorf("WithPool did not apply values: %+v", p)
	}

	// Non-positive values must keep the current/default value.
	p2 := defaultPoolConfig()
	WithPool(0, 0, 0)(&p2)
	if p2 != defaultPoolConfig() {
		t.Errorf("WithPool(0,0,0) should keep defaults, got %+v", p2)
	}
}

func TestApplyPoolSetsHandleLimits(t *testing.T) {
	// sql.Open with the pgx driver does not connect (lazy), so this needs no DB.
	conn, err := sql.Open("pgx", "postgres://user:pass@localhost:5432/db?sslmode=disable")
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	defer conn.Close()

	applyPool(conn, WithPool(42, 42, time.Minute))
	if got := conn.Stats().MaxOpenConnections; got != 42 {
		t.Errorf("applyPool should set MaxOpenConnections=42, got %d", got)
	}

	// Default (no options) applies the default cap.
	conn2, err := sql.Open("pgx", "postgres://user:pass@localhost:5432/db?sslmode=disable")
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	defer conn2.Close()
	applyPool(conn2)
	if got := conn2.Stats().MaxOpenConnections; got != defaultPoolConfig().maxOpenConns {
		t.Errorf("applyPool default MaxOpenConnections=%d, got %d", defaultPoolConfig().maxOpenConns, got)
	}
}
