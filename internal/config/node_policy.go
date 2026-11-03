package config

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type NodePolicyConfig struct {
	Mode            string
	URL             string
	Token           string
	PrivateKeyFile  string
	KeyID           string
	ChainID         uint64
	DeploymentID    string
	ConsumerID      string
	FactTTL         time.Duration
	PublishInterval time.Duration
	IdentityTTL     time.Duration
	// Connection lanes to the private node (RD-1410): bounded
	// keep-alive pools for fact publication/status, transactions and outcome
	// status. The node's connection limit must cover the sum over instances.
	ControlConns, TransactionConns, RecoveryConns int
	parseError                                    error
}

// Private-node connection lane bounds and defaults; they mirror
// nodepolicy.MaxLaneConnections and nodepolicy.DefaultLanes.
const (
	maxNodePolicyLaneConns            = 1024
	defaultNodePolicyControlConns     = 4
	defaultNodePolicyTransactionConns = 64
	defaultNodePolicyRecoveryConns    = 16
)

func (c NodePolicyConfig) Enabled() bool { return c.Mode == "reth" }
func loadNodePolicy(get func(string) string) NodePolicyConfig {
	value := func(key, fallback string) string {
		if v := strings.TrimSpace(get(key)); v != "" {
			return v
		}
		return fallback
	}
	c := NodePolicyConfig{Mode: value("OPS_NODE_POLICY_MODE", "legacy"), URL: value("OPS_NODE_POLICY_URL", ""), Token: value("OPS_NODE_POLICY_TOKEN", ""), PrivateKeyFile: value("OPS_NODE_POLICY_PRIVATE_KEY_FILE", ""), KeyID: value("OPS_NODE_POLICY_KEY_ID", ""), DeploymentID: value("OPS_NODE_POLICY_DEPLOYMENT_ID", ""), ConsumerID: value("OPS_NODE_POLICY_CONSUMER_ID", "producer")}
	if !c.Enabled() {
		return c
	}
	var err error
	c.ChainID, err = strconv.ParseUint(value("OPS_NODE_POLICY_CHAIN_ID", "0"), 10, 64)
	if err != nil {
		c.parseError = fmt.Errorf("OPS_NODE_POLICY_CHAIN_ID must be an unsigned integer")
	}
	for _, lane := range []struct {
		key      string
		fallback int
		dst      *int
	}{
		{"OPS_NODE_POLICY_CONTROL_CONNS", defaultNodePolicyControlConns, &c.ControlConns}, {"OPS_NODE_POLICY_TRANSACTION_CONNS", defaultNodePolicyTransactionConns, &c.TransactionConns}, {"OPS_NODE_POLICY_RECOVERY_CONNS", defaultNodePolicyRecoveryConns, &c.RecoveryConns},
	} {
		*lane.dst, err = strconv.Atoi(value(lane.key, strconv.Itoa(lane.fallback)))
		if err != nil || *lane.dst < 1 || *lane.dst > maxNodePolicyLaneConns {
			c.parseError = fmt.Errorf("%s must be an integer in 1..%d", lane.key, maxNodePolicyLaneConns)
		}
	}
	for _, duration := range []struct {
		key, fallback string
		dst           *time.Duration
	}{
		{"OPS_NODE_POLICY_FACT_TTL", "30s", &c.FactTTL}, {"OPS_NODE_POLICY_PUBLISH_INTERVAL", "1s", &c.PublishInterval}, {"OPS_NODE_POLICY_IDENTITY_TTL", "1m", &c.IdentityTTL},
	} {
		*duration.dst, err = time.ParseDuration(value(duration.key, duration.fallback))
		if err != nil {
			c.parseError = fmt.Errorf("%s must be a duration", duration.key)
		}
	}
	return c
}
func (c NodePolicyConfig) Validate() error {
	if c.Mode == "" || c.Mode == "legacy" {
		return nil
	}
	if c.Mode != "reth" {
		return fmt.Errorf("OPS_NODE_POLICY_MODE must be legacy or reth")
	}
	if c.parseError != nil {
		return c.parseError
	}
	u, err := url.Parse(c.URL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("OPS_NODE_POLICY_URL must be a private HTTP(S) endpoint without embedded credentials")
	}
	if len(c.Token) < 16 || strings.ContainsAny(c.Token, " \r\n\t") {
		return fmt.Errorf("OPS_NODE_POLICY_TOKEN requires at least 16 bytes without whitespace")
	}
	if c.PrivateKeyFile == "" || !nodePolicyIdentifier(c.KeyID) || c.ChainID == 0 || !nodePolicyIdentifier(c.DeploymentID) || !nodePolicyIdentifier(c.ConsumerID) {
		return fmt.Errorf("Reth policy mode requires a signing key file, key ID, chain ID, deployment ID and consumer ID")
	}
	for _, n := range []int{c.ControlConns, c.TransactionConns, c.RecoveryConns} {
		if n < 0 || n > maxNodePolicyLaneConns { // 0: the default
			return fmt.Errorf("OPS_NODE_POLICY_CONTROL_CONNS, OPS_NODE_POLICY_TRANSACTION_CONNS and OPS_NODE_POLICY_RECOVERY_CONNS must each be 1..%d", maxNodePolicyLaneConns)
		}
	}
	if c.FactTTL < time.Second || c.FactTTL > 10*time.Minute || c.IdentityTTL < time.Second || c.IdentityTTL > 10*time.Minute || c.PublishInterval <= 0 || c.PublishInterval > c.FactTTL/3 {
		return fmt.Errorf("node policy lifetimes must be 1s..10m and publish interval at most one third of fact lifetime")
	}
	return nil
}

// LaneSizes returns the control, transaction and recovery lane sizes; a zero
// field (a literal configuration without them) takes its default.
func (c NodePolicyConfig) LaneSizes() (control, transaction, recovery int) {
	pick := func(n, fallback int) int {
		if n == 0 {
			return fallback
		}
		return n
	}
	return pick(c.ControlConns, defaultNodePolicyControlConns), pick(c.TransactionConns, defaultNodePolicyTransactionConns), pick(c.RecoveryConns, defaultNodePolicyRecoveryConns)
}

func nodePolicyIdentifier(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for _, r := range value {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("-_.:", r)) {
			return false
		}
	}
	return true
}
