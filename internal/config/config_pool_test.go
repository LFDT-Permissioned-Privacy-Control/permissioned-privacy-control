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

func TestLoadGetLogsParticipantBatchSize(t *testing.T) {
	resetFileConfig(t)
	t.Setenv("CONFIG_FILE", "")
	t.Setenv("GET_LOGS_PARTICIPANT_BATCH_SIZE", "")
	if got := Load().GetLogsParticipantBatchSize; got != 100 {
		t.Errorf("default batch size = %d, want 100", got)
	}

	t.Setenv("CONFIG_FILE", writeConfigFile(t, "version = 1\nGET_LOGS_PARTICIPANT_BATCH_SIZE = 80\n"))
	if got := Load().GetLogsParticipantBatchSize; got != 80 {
		t.Errorf("TOML batch size = %d, want 80", got)
	}

	t.Setenv("GET_LOGS_PARTICIPANT_BATCH_SIZE", "25")
	if got := Load().GetLogsParticipantBatchSize; got != 25 {
		t.Errorf("environment batch size = %d, want 25", got)
	}

	for _, value := range []string{"0", "-1", "invalid"} {
		t.Run(value, func(t *testing.T) {
			t.Setenv("GET_LOGS_PARTICIPANT_BATCH_SIZE", value)
			defer func() {
				if got := recover(); got != "GET_LOGS_PARTICIPANT_BATCH_SIZE must be a positive integer" {
					t.Errorf("invalid setting gave %v, want a configuration error", got)
				}
			}()
			Load()
		})
	}
}
