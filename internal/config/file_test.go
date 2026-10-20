package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// writeConfigFile writes content to a temp TOML file and returns its path.
func writeConfigFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write temp config: %v", err)
	}
	return path
}

// resetFileConfig clears the package-level config-file state after the test so
// cases don't leak into each other or into other config tests that call Load/
// Validate.
func resetFileConfig(t *testing.T) {
	t.Helper()
	t.Cleanup(func() {
		fileConfig = nil
		fileConfigErr = nil
	})
}

func TestLoadConfigFile_NoFileIsPureEnv(t *testing.T) {
	resetFileConfig(t)
	t.Setenv("CONFIG_FILE", "") // unset/empty => pure-environment mode
	if err := loadConfigFile(); err != nil {
		t.Fatalf("expected nil error with no CONFIG_FILE, got %v", err)
	}
	if fileConfig != nil {
		t.Fatalf("expected nil fileConfig, got %v", fileConfig)
	}
	// getEnv must behave exactly as before: env, then default.
	if got := getEnv("RD1130_UNSET_KEY", "fallback"); got != "fallback" {
		t.Errorf("getEnv fallback = %q, want fallback", got)
	}
}

func TestLoadConfigFile_PrecedenceAndCoercion(t *testing.T) {
	resetFileConfig(t)
	path := writeConfigFile(t, `
version = 1
RD1130_STRING = "from-file"
RD1130_BOOL = true
RD1130_INT = 42
RD1130_FLOAT = 1.5
RD1130_OVERRIDDEN = "file-value"
`)
	t.Setenv("CONFIG_FILE", path)
	t.Setenv("RD1130_OVERRIDDEN", "env-value") // env must win over the file

	if err := loadConfigFile(); err != nil {
		t.Fatalf("loadConfigFile: %v", err)
	}

	tests := []struct {
		key, def, want string
	}{
		{"RD1130_STRING", "dflt", "from-file"},     // file used (env unset)
		{"RD1130_BOOL", "dflt", "true"},            // bool coerced to string
		{"RD1130_INT", "dflt", "42"},               // integer coerced
		{"RD1130_FLOAT", "dflt", "1.5"},            // float coerced
		{"RD1130_OVERRIDDEN", "dflt", "env-value"}, // env > file
		{"RD1130_ABSENT", "dflt", "dflt"},          // neither => default
	}
	for _, tc := range tests {
		if got := getEnv(tc.key, tc.def); got != tc.want {
			t.Errorf("getEnv(%q, %q) = %q, want %q", tc.key, tc.def, got, tc.want)
		}
	}
}

func TestLoadConfigFile_Errors(t *testing.T) {
	cases := []struct {
		name, content string
	}{
		{"missing version", `FOO = "bar"`},
		{"unsupported version", "version = 2\nFOO = \"bar\"\n"},
		{"version not an integer", "version = \"1\"\nFOO = \"bar\"\n"},
		{"unparseable toml", "this is = = not [ valid"},
		{"nested table unsupported", "version = 1\n[section]\nKEY = \"v\"\n"},
		{"array value unsupported", "version = 1\nKEYS = [\"a\", \"b\"]\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resetFileConfig(t)
			path := writeConfigFile(t, tc.content)
			t.Setenv("CONFIG_FILE", path)
			if err := loadConfigFile(); err == nil {
				t.Fatalf("expected error, got nil (fileConfig=%v)", fileConfig)
			}
			// On any error the file layer must be inert (pure-env fallback).
			if fileConfig != nil {
				t.Errorf("expected fileConfig nil on error, got %v", fileConfig)
			}
		})
	}
}

func TestLoadConfigFile_MissingFilePathErrors(t *testing.T) {
	resetFileConfig(t)
	t.Setenv("CONFIG_FILE", filepath.Join(t.TempDir(), "does-not-exist.toml"))
	if err := loadConfigFile(); err == nil {
		t.Fatal("expected error for missing file path, got nil")
	}
}

func TestLoadConfigFile_SecretKeyRejected(t *testing.T) {
	// Secrets must never be sourced from the config file — the proxy refuses to
	// load a file containing ANY secret-class key, names the offending key (but
	// NOT its value), and stays in pure-env mode. Iterate the authoritative
	// denylist (secretKeys) rather than a hand-picked few, so every current key
	// is covered and a newly-added one is guarded automatically. This closes the
	// AUDIT_CHECKPOINT_KEY gap (RD-1112) and covers OPERATOR_API_TOKEN /
	// SIEM_AUTH_HEADER (RD-1140/1141), the RD-1147 separate-audit-database DSNs,
	// the JWT/DSN/RPC-key/OAuth secrets, etc.
	const secretValue = "super-secret-token-value-DO-NOT-LEAK"
	if len(secretKeys) == 0 {
		t.Fatal("secretKeys denylist is empty — nothing is guarded")
	}
	for key := range secretKeys {
		t.Run(key, func(t *testing.T) {
			resetFileConfig(t)
			path := writeConfigFile(t, "version = 1\nBASE_URL = \"https://ok\"\n"+key+" = \""+secretValue+"\"\n")
			t.Setenv("CONFIG_FILE", path)
			err := loadConfigFile()
			if err == nil {
				t.Fatalf("expected rejection when secret key %q is in the config file, got nil", key)
			}
			if !strings.Contains(err.Error(), key) {
				t.Errorf("error should name the offending secret key %q, got: %v", key, err)
			}
			// Fail-closed: the loader must never echo the secret VALUE.
			if strings.Contains(err.Error(), secretValue) {
				t.Errorf("error must NOT echo the secret value for %q, got: %v", key, err)
			}
			if fileConfig != nil {
				t.Errorf("expected fileConfig nil when %q is rejected, got %v", key, fileConfig)
			}
		})
	}
}

func TestValidate_SurfacesConfigFileError(t *testing.T) {
	resetFileConfig(t)
	// An unsupported version must make startup fail via Validate, even in
	// development mode (where Validate otherwise short-circuits to nil).
	path := writeConfigFile(t, "version = 99\n")
	t.Setenv("CONFIG_FILE", path)
	cfg := Load()
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected Validate to surface the config-file error, got nil")
	}
}

func TestLoad_ConfigFileFeedsConfig(t *testing.T) {
	resetFileConfig(t)
	// End-to-end: a value present only in the file lands in the built Config,
	// and an env var of the same name overrides it.
	path := writeConfigFile(t, "version = 1\nBASE_URL = \"https://from-file.example\"\n")
	t.Setenv("CONFIG_FILE", path)

	cfg := Load()
	if cfg.BaseURL != "https://from-file.example" {
		t.Errorf("BaseURL from file = %q, want https://from-file.example", cfg.BaseURL)
	}

	t.Setenv("BASE_URL", "https://from-env.example")
	cfg = Load()
	if cfg.BaseURL != "https://from-env.example" {
		t.Errorf("BaseURL with env override = %q, want https://from-env.example", cfg.BaseURL)
	}
}

func TestLoadConfigFile_TypedFieldsReachConfig(t *testing.T) {
	resetFileConfig(t)
	// A spread of real, typed settings sourced from the file must each land in
	// the corresponding Config field (string/bool/int/duration), and an env var
	// must still override the file value.
	path := writeConfigFile(t, `
version = 1
BASE_URL = "https://file.example"
ENABLE_TRAVEL_RULE = true
MAX_CONCURRENT_REQUESTS = 99
ETH_CALL_TRACE_TIMEOUT = "9s"
COMPLIANCE_DEFAULT_MODE = "monitor"
`)
	t.Setenv("CONFIG_FILE", path)
	t.Setenv("COMPLIANCE_DEFAULT_MODE", "enforce") // env overrides the file value

	cfg := Load()

	if cfg.BaseURL != "https://file.example" {
		t.Errorf("BaseURL (string) = %q, want https://file.example", cfg.BaseURL)
	}
	if !cfg.EnableTravelRule {
		t.Error("EnableTravelRule (bool) = false, want true (from file)")
	}
	if cfg.MaxConcurrentRequests != 99 {
		t.Errorf("MaxConcurrentRequests (int) = %d, want 99 (from file)", cfg.MaxConcurrentRequests)
	}
	if cfg.EthCallTraceTimeout != 9*time.Second {
		t.Errorf("EthCallTraceTimeout (duration) = %v, want 9s (from file)", cfg.EthCallTraceTimeout)
	}
	if cfg.ComplianceDefaultMode != "enforce" {
		t.Errorf("ComplianceDefaultMode = %q, want enforce (env must override the file)", cfg.ComplianceDefaultMode)
	}
}

// TestLoad_AutoKYC covers the RD-1131 per-identity-class auto-KYC config knobs:
// off by default, independently settable per class, and (via RD-1130) sourced
// from the config file as well as the environment.
func TestLoad_AutoKYC(t *testing.T) {
	resetFileConfig(t)

	t.Run("defaults to false for every class", func(t *testing.T) {
		cfg := Load()
		if cfg.AutoKYCPrivado || cfg.AutoKYCAzureUser || cfg.AutoKYCAzureServicePrincipal {
			t.Errorf("auto-KYC must default to false; got privado=%v azure_user=%v sp=%v",
				cfg.AutoKYCPrivado, cfg.AutoKYCAzureUser, cfg.AutoKYCAzureServicePrincipal)
		}
	})

	t.Run("enabled per class via env, independently", func(t *testing.T) {
		t.Setenv("AUTO_KYC_PRIVADO", "true")
		t.Setenv("AUTO_KYC_AZURE_SERVICE_PRINCIPAL", "true")
		// AUTO_KYC_AZURE_USER intentionally left unset — must stay false.
		cfg := Load()
		if !cfg.AutoKYCPrivado {
			t.Error("AUTO_KYC_PRIVADO=true should enable AutoKYCPrivado")
		}
		if !cfg.AutoKYCAzureServicePrincipal {
			t.Error("AUTO_KYC_AZURE_SERVICE_PRINCIPAL=true should enable AutoKYCAzureServicePrincipal")
		}
		if cfg.AutoKYCAzureUser {
			t.Error("AutoKYCAzureUser must stay false when its env var is unset")
		}
	})

	t.Run("settable from the config file when env is unset", func(t *testing.T) {
		path := writeConfigFile(t, "version = 1\nAUTO_KYC_AZURE_USER = true\n")
		t.Setenv("CONFIG_FILE", path)
		cfg := Load()
		if !cfg.AutoKYCAzureUser {
			t.Error("AUTO_KYC_AZURE_USER=true in the config file should enable AutoKYCAzureUser")
		}
	})
}
