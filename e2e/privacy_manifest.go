package e2e

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// TrustZoneConfig mirrors deployments/privacy/trust-zone.yaml — the single
// source of truth for what counts as internal vs. public in privacy mode.
// Consumed by both the static compose-manifest test (PR-gated) and the
// runtime negative-network test (schedule-gated).
//
// Schema version 2 introduced a two-zone split: indexer_zone holds raw
// chain-data services, bff_zone holds the block-explorer BFF and its
// verification postgres. proxy-backend is the only service permitted to
// attach to both internal zones.
type TrustZoneConfig struct {
	Version int `yaml:"version"`

	IndexerZone []TrustZoneService `yaml:"indexer_zone"`
	BffZone     []TrustZoneService `yaml:"bff_zone"`
	Public      []PublicService    `yaml:"public"`
}

type TrustZoneService struct {
	Name                string `yaml:"name"`
	DefaultInternalPort int    `yaml:"default_internal_port"`
	Description         string `yaml:"description"`
}

type PublicService struct {
	Name            string `yaml:"name"`
	HostPortEnv     string `yaml:"host_port_env"`
	DefaultHostPort int    `yaml:"default_host_port"`
	Description     string `yaml:"description"`
}

// AllInternal returns every service that lives in an internal zone
// (indexer_zone or bff_zone). Used by the "no published ports" check
// which applies to both zones identically.
func (c *TrustZoneConfig) AllInternal() []TrustZoneService {
	out := make([]TrustZoneService, 0, len(c.IndexerZone)+len(c.BffZone))
	out = append(out, c.IndexerZone...)
	out = append(out, c.BffZone...)
	return out
}

// ZoneOf returns the docker network name a service must attach to:
// "indexer-zone", "bff-zone", or "" for a service that's not in any
// internal zone (e.g. a public-only service).
func (c *TrustZoneConfig) ZoneOf(name string) string {
	for _, s := range c.IndexerZone {
		if s.Name == name {
			return "indexer-zone"
		}
	}
	for _, s := range c.BffZone {
		if s.Name == name {
			return "bff-zone"
		}
	}
	return ""
}

// BridgeService is the single service permitted to attach to both
// indexer-zone and bff-zone. Tests hardcode this name; adding another
// bridge requires updating the test AND justifying why the new service
// needs the cross-zone path.
const BridgeService = "proxy-backend"

// LoadTrustZone reads deployments/privacy/trust-zone.yaml relative to the
// Open Privacy Suite repo root. repoRoot should be an absolute path.
func LoadTrustZone(repoRoot string) (*TrustZoneConfig, error) {
	path := filepath.Join(repoRoot, "deployments", "privacy", "trust-zone.yaml")
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var cfg TrustZoneConfig
	if err := yaml.Unmarshal(b, &cfg); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if cfg.Version != 2 {
		return nil, fmt.Errorf("%s: unsupported version %d (expected 2)", path, cfg.Version)
	}
	if len(cfg.IndexerZone) == 0 {
		return nil, fmt.Errorf("%s: indexer_zone list is empty — misconfiguration", path)
	}
	if len(cfg.BffZone) == 0 {
		return nil, fmt.Errorf("%s: bff_zone list is empty — misconfiguration", path)
	}
	return &cfg, nil
}
