package config

import (
	"testing"
	"time"
)

// Proof for RD-1112 Tier-2: the DB pool + upstream-transport pool sizes are
// env-configurable, with MaxIdle defaulting to MaxOpen.

func TestLoadPoolAndTransportDefaults(t *testing.T) {
	cfg := Load()

	if cfg.DBMaxOpenConns != 50 {
		t.Errorf("DBMaxOpenConns default = 50, got %d", cfg.DBMaxOpenConns)
	}
	if cfg.DBMaxIdleConns != cfg.DBMaxOpenConns {
		t.Errorf("DBMaxIdleConns should default to MaxOpen (%d), got %d", cfg.DBMaxOpenConns, cfg.DBMaxIdleConns)
	}
	if cfg.DBConnMaxLifetime != 5*time.Minute {
		t.Errorf("DBConnMaxLifetime default = 5m, got %v", cfg.DBConnMaxLifetime)
	}
	if cfg.NodeMaxIdleConns != 512 {
		t.Errorf("NodeMaxIdleConns default = 512, got %d", cfg.NodeMaxIdleConns)
	}
	if cfg.NodeMaxIdleConnsPerHost != 256 {
		t.Errorf("NodeMaxIdleConnsPerHost default = 256, got %d", cfg.NodeMaxIdleConnsPerHost)
	}
	if cfg.NodeIdleConnTimeout != 90*time.Second {
		t.Errorf("NodeIdleConnTimeout default = 90s, got %v", cfg.NodeIdleConnTimeout)
	}
}

func TestLoadPoolAndTransportEnvOverrides(t *testing.T) {
	t.Setenv("DB_MAX_OPEN_CONNS", "120")
	t.Setenv("DB_CONN_MAX_LIFETIME", "10m")
	t.Setenv("NODE_HTTP_MAX_IDLE_CONNS_PER_HOST", "64")
	t.Setenv("NODE_HTTP_MAX_CONNS_PER_HOST", "200")

	cfg := Load()

	if cfg.DBMaxOpenConns != 120 {
		t.Errorf("DBMaxOpenConns = 120, got %d", cfg.DBMaxOpenConns)
	}
	if cfg.DBMaxIdleConns != 120 {
		t.Errorf("DBMaxIdleConns should follow MaxOpen when unset (=120), got %d", cfg.DBMaxIdleConns)
	}
	if cfg.DBConnMaxLifetime != 10*time.Minute {
		t.Errorf("DBConnMaxLifetime = 10m, got %v", cfg.DBConnMaxLifetime)
	}
	if cfg.NodeMaxIdleConnsPerHost != 64 {
		t.Errorf("NodeMaxIdleConnsPerHost = 64, got %d", cfg.NodeMaxIdleConnsPerHost)
	}
	if cfg.NodeMaxConnsPerHost != 200 {
		t.Errorf("NodeMaxConnsPerHost = 200, got %d", cfg.NodeMaxConnsPerHost)
	}
}

// R12.2 (RD-1410): pool sizes are validated. A zero or negative pool, an idle
// pool larger than the open pool, or an unparseable value is refused at
// startup instead of silently becoming the default.
func TestPoolSizesAreValidated(t *testing.T) {
	for _, env := range []map[string]string{
		{"DB_MAX_OPEN_CONNS": "0"},
		{"DB_MAX_OPEN_CONNS": "-5"},
		{"DB_MAX_OPEN_CONNS": "fifty"},
		{"DB_MAX_OPEN_CONNS": "20", "DB_MAX_IDLE_CONNS": "40"},
		{"DB_MAX_IDLE_CONNS": "-1"},
		{"DB_MAX_IDLE_CONNS": "0"},
	} {
		for k, v := range env {
			t.Setenv(k, v)
		}
		cfg := Load()
		if err := cfg.validatePool(); err == nil {
			t.Errorf("%v accepted", env)
		}
		for k := range env {
			t.Setenv(k, "")
		}
	}
	t.Setenv("DB_MAX_OPEN_CONNS", "120")
	t.Setenv("DB_MAX_IDLE_CONNS", "")
	if err := Load().validatePool(); err != nil {
		t.Fatalf("valid pool refused: %v", err)
	}
	if err := (&Config{}).validatePool(); err != nil {
		t.Fatalf("a literal configuration without pool sizes takes the defaults: %v", err)
	}
}
