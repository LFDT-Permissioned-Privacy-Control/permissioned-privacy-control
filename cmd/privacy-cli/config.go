package main

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	toml "github.com/pelletier/go-toml/v2"
)

// Config represents the privacy.toml configuration file.
type Config struct {
	Proxy ProxyConfig `toml:"proxy"`
	Org   OrgConfig   `toml:"org"`
	Auth  AuthConfig  `toml:"auth"`
}

// ProxyConfig contains proxy connection settings.
type ProxyConfig struct {
	APIURL string `toml:"api_url"`
	RPCURL string `toml:"rpc_url"`
}

// OrgConfig contains organization settings.
type OrgConfig struct {
	ID string `toml:"id"`
}

// AuthConfig contains authentication settings.
type AuthConfig struct {
	Token string `toml:"token"`
}

// DefaultConfigPaths returns the list of paths to search for config files.
func DefaultConfigPaths() []string {
	return []string{
		"privacy.toml",
		".privacy.toml",
		"config/privacy.toml",
	}
}

// LoadConfig loads the configuration from the specified file or searches default paths.
func LoadConfig(configPath string) (*Config, error) {
	var paths []string
	if configPath != "" {
		paths = []string{configPath}
	} else {
		paths = DefaultConfigPaths()
	}

	var cfg Config
	var loaded bool

	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, fmt.Errorf("failed to read config file %s: %w", path, err)
		}

		if err := toml.Unmarshal(data, &cfg); err != nil {
			return nil, fmt.Errorf("failed to parse config file %s: %w", path, err)
		}
		loaded = true
		break
	}

	if !loaded {
		// Return empty config - will use flags/env vars
		return &Config{}, nil
	}

	// Expand environment variables in config values
	expandEnvVars(&cfg)

	return &cfg, nil
}

// expandEnvVars expands ${VAR} and $VAR patterns in config string values.
func expandEnvVars(cfg *Config) {
	cfg.Proxy.APIURL = expandEnvVar(cfg.Proxy.APIURL)
	cfg.Proxy.RPCURL = expandEnvVar(cfg.Proxy.RPCURL)
	cfg.Org.ID = expandEnvVar(cfg.Org.ID)
	cfg.Auth.Token = expandEnvVar(cfg.Auth.Token)
}

// expandEnvVar expands environment variable references in a string.
// Supports both ${VAR} and $VAR syntax.
func expandEnvVar(s string) string {
	if s == "" {
		return s
	}

	// Pattern for ${VAR} syntax
	re := regexp.MustCompile(`\$\{([^}]+)\}`)
	result := re.ReplaceAllStringFunc(s, func(match string) string {
		// Extract variable name from ${VAR}
		varName := match[2 : len(match)-1]
		if val, exists := os.LookupEnv(varName); exists {
			return val
		}
		return match // Keep original if not found
	})

	// Pattern for $VAR syntax (word boundary)
	re2 := regexp.MustCompile(`\$([A-Za-z_][A-Za-z0-9_]*)`)
	result = re2.ReplaceAllStringFunc(result, func(match string) string {
		// Skip if this was part of ${VAR} (already processed)
		if strings.Contains(s, "${"+match[1:]+"}") {
			return match
		}
		varName := match[1:]
		if val, exists := os.LookupEnv(varName); exists {
			return val
		}
		return match // Keep original if not found
	})

	return result
}

// MergeWithFlags merges command-line flags with config values.
// Flags take precedence over config values.
func (c *Config) MergeWithFlags(apiURL, rpcURL, orgID, token string) {
	if apiURL != "" {
		c.Proxy.APIURL = apiURL
	}
	if rpcURL != "" {
		c.Proxy.RPCURL = rpcURL
	}
	if orgID != "" {
		c.Org.ID = orgID
	}
	if token != "" {
		c.Auth.Token = token
	}

	// Also check environment variables as fallback
	if c.Proxy.APIURL == "" {
		c.Proxy.APIURL = os.Getenv("PRIVACY_PROXY_API_URL")
	}
	if c.Proxy.RPCURL == "" {
		c.Proxy.RPCURL = os.Getenv("PRIVACY_PROXY_RPC_URL")
	}
	if c.Org.ID == "" {
		c.Org.ID = os.Getenv("PRIVACY_PROXY_ORG_ID")
	}
	if c.Auth.Token == "" {
		c.Auth.Token = os.Getenv("PRIVACY_PROXY_TOKEN")
	}
}

// Validate checks that required configuration values are present.
func (c *Config) Validate() error {
	if c.Proxy.APIURL == "" {
		return fmt.Errorf("api_url is required (set in privacy.toml, --api-url flag, or PRIVACY_PROXY_API_URL env)")
	}
	if c.Org.ID == "" {
		return fmt.Errorf("org_id is required (set in privacy.toml, --org-id flag, or PRIVACY_PROXY_ORG_ID env)")
	}
	return nil
}
