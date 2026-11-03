package config

import (
	"fmt"
	"math"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type NodePolicyConfig struct {
	Mode string
	URL  string
	// ControlURL (optional) is the node's control listener; fact publication
	// and node status use it instead of URL.
	ControlURL      string
	Token           string
	PrivateKeyFile  string
	KeyID           string
	ChainID         uint64
	DeploymentID    string
	ConsumerID      string
	FactTTL         time.Duration
	PublishInterval time.Duration
	// IdentityTTL is the lifetime of simulation identities.
	IdentityTTL time.Duration
	// TransactionIdentityTTL is the lease of a transaction identity, renewed
	// by the lease keeper while the transaction is pending (plan §4.8.2);
	// MaxAge bounds how long after admission it is renewed at all.
	TransactionIdentityTTL time.Duration
	MaxAge                 time.Duration
	// Congestion renewal and the pending-work limits (plan §4.8.2): the
	// lease keeper's renewal budget (renewals per second), the reorg depth
	// and block gas limit that size the reorg headroom, the expected rate and
	// inclusion bound the admitted work must cover, and the per-principal and
	// per-organization caps (0: the admission limit minus the admission
	// floor). RenewalPlan derives the rest.
	RenewalBudget         int
	MaxReorgDepth         int
	BlockGasLimit         uint64
	ExpectedTPS           int
	InclusionBound        time.Duration
	PrincipalPendingLimit int64
	OrgPendingLimit       int64
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
	c := NodePolicyConfig{Mode: value("OPS_NODE_POLICY_MODE", "legacy"), URL: value("OPS_NODE_POLICY_URL", ""), ControlURL: value("OPS_NODE_POLICY_CONTROL_URL", ""), Token: value("OPS_NODE_POLICY_TOKEN", ""), PrivateKeyFile: value("OPS_NODE_POLICY_PRIVATE_KEY_FILE", ""), KeyID: value("OPS_NODE_POLICY_KEY_ID", ""), DeploymentID: value("OPS_NODE_POLICY_DEPLOYMENT_ID", ""), ConsumerID: value("OPS_NODE_POLICY_CONSUMER_ID", "producer")}
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
		{"OPS_NODE_POLICY_TRANSACTION_IDENTITY_TTL", "300s", &c.TransactionIdentityTTL}, {"OPS_NODE_POLICY_MAX_AGE", "10m", &c.MaxAge},
		{"OPS_NODE_POLICY_INCLUSION_BOUND", "1500ms", &c.InclusionBound},
	} {
		*duration.dst, err = time.ParseDuration(value(duration.key, duration.fallback))
		if err != nil {
			c.parseError = fmt.Errorf("%s must be a duration", duration.key)
		}
	}
	if c.InclusionBound <= 0 && c.parseError == nil {
		c.parseError = fmt.Errorf("OPS_NODE_POLICY_INCLUSION_BOUND must be %s..%s", minInclusionBound, maxInclusionBound)
	}
	for _, number := range []struct {
		key      string
		fallback int64
		min, max int64
		dst      func(int64)
	}{
		{"OPS_NODE_POLICY_RENEWAL_BUDGET", defaultRenewalBudget, 1, maxRenewalBudget, func(v int64) { c.RenewalBudget = int(v) }},
		{"OPS_NODE_POLICY_MAX_REORG_DEPTH", defaultMaxReorgDepth, 0, maxReorgDepth, func(v int64) { c.MaxReorgDepth = int(v) }},
		{"OPS_NODE_POLICY_BLOCK_GAS_LIMIT", defaultBlockGasLimit, minTransactionGas, 1 << 62, func(v int64) { c.BlockGasLimit = uint64(v) }},
		{"OPS_NODE_POLICY_EXPECTED_TPS", defaultExpectedTPS, 1, 1_000_000, func(v int64) { c.ExpectedTPS = int(v) }},
		{"OPS_NODE_POLICY_PRINCIPAL_PENDING_LIMIT", 0, 1, 1 << 40, func(v int64) { c.PrincipalPendingLimit = v }},
		{"OPS_NODE_POLICY_ORG_PENDING_LIMIT", 0, 1, 1 << 40, func(v int64) { c.OrgPendingLimit = v }},
	} {
		raw := value(number.key, "")
		if raw == "" {
			number.dst(number.fallback) // 0 for the caps: derived
			continue
		}
		v, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || v < number.min || v > number.max {
			c.parseError = fmt.Errorf("%s must be an integer in %d..%d", number.key, number.min, number.max)
			continue
		}
		number.dst(v)
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
	if c.ControlURL != "" {
		u, err := url.Parse(c.ControlURL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
			return fmt.Errorf("OPS_NODE_POLICY_CONTROL_URL must be a private HTTP(S) endpoint without embedded credentials")
		}
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
	ttl, maxAge := c.TransactionLease()
	if ttl < MinTransactionIdentityTTL || ttl > MaxTransactionIdentityTTL {
		return fmt.Errorf("OPS_NODE_POLICY_TRANSACTION_IDENTITY_TTL must be %s..%s", MinTransactionIdentityTTL, MaxTransactionIdentityTTL)
	}
	if maxAge < ttl || maxAge > MaxNodePolicyMaxAge {
		return fmt.Errorf("OPS_NODE_POLICY_MAX_AGE must be at least OPS_NODE_POLICY_TRANSACTION_IDENTITY_TTL and at most %s", MaxNodePolicyMaxAge)
	}
	if _, err := c.RenewalPlan(); err != nil {
		return err
	}
	return nil
}

// Congestion-renewal defaults and bounds (plan §4.8.2).
const (
	defaultRenewalBudget  = 500
	maxRenewalBudget      = 2000
	defaultMaxReorgDepth  = 2
	maxReorgDepth         = 64
	defaultBlockGasLimit  = 200_000_000
	defaultExpectedTPS    = 2000
	minTransactionGas     = 21_000
	minInclusionBound     = 100 * time.Millisecond
	maxInclusionBound     = 60 * time.Second
	defaultInclusionBound = 1500 * time.Millisecond
)

// KeeperTiming is the lease keeper's cadence and per-step bounds; the server
// runs the keeper with DefaultKeeperTiming, and startup validates the renewal
// arithmetic against the same values.
type KeeperTiming struct {
	// Tick is the keeper's (and the reconciler's) pass interval.
	Tick time.Duration
	// Recheck bounds one renewal's admission and compliance re-check.
	Recheck time.Duration
	// Delivery bounds one renewal's delivery to the node, including the
	// node's own wait for policy facts.
	Delivery time.Duration
}

// DefaultKeeperTiming is the timing the server uses.
var DefaultKeeperTiming = KeeperTiming{Tick: time.Second, Recheck: 5 * time.Second, Delivery: 5 * time.Second}

// RenewalPlan is the derived congestion-renewal arithmetic (plan §4.8.2).
type RenewalPlan struct {
	TTL time.Duration
	// Margin is R = TTL/4: a renewal must land before a lease has less than
	// R left. WindowOpens is TTL/2: a pending transaction whose lease has at
	// most this much left may be renewed.
	Margin, WindowOpens time.Duration
	MaxAge              time.Duration
	// Budget is the keeper's renewals per second.
	Budget int
	// RenewLimit (L_renew = Budget × (TTL/2 − R)) is the renewable work the
	// budget can renew inside the window; ReorgHeadroom is what a reorg of
	// the configured depth can return to pending; AdmitLimit (L_admit) is
	// where new admissions get backpressure; AdmitFloor is the work the
	// expected rate needs (2 × rate × inclusion bound).
	RenewLimit, ReorgHeadroom, AdmitLimit, AdmitFloor int64
	// PrincipalLimit and OrgLimit cap one principal's and one
	// organization's pending work.
	PrincipalLimit, OrgLimit int64
}

// RenewalPlan derives and checks the congestion-renewal arithmetic for the
// server's keeper timing.
func (c NodePolicyConfig) RenewalPlan() (RenewalPlan, error) {
	return c.renewalPlan(DefaultKeeperTiming)
}

func (c NodePolicyConfig) renewalPlan(timing KeeperTiming) (RenewalPlan, error) {
	ttl, maxAge := c.TransactionLease()
	pick := func(v, fallback int64) int64 {
		if v == 0 {
			return fallback
		}
		return v
	}
	budget := pick(int64(c.RenewalBudget), defaultRenewalBudget)
	gas := pick(int64(c.BlockGasLimit), defaultBlockGasLimit)
	tps := pick(int64(c.ExpectedTPS), defaultExpectedTPS)
	inclusion := c.InclusionBound
	if inclusion == 0 {
		inclusion = defaultInclusionBound
	}
	depth := int64(c.MaxReorgDepth) // 0 is a valid depth (no reorgs)
	if budget < 1 || budget > maxRenewalBudget || depth < 0 || depth > maxReorgDepth || gas < minTransactionGas || tps < 1 || inclusion < minInclusionBound || inclusion > maxInclusionBound {
		return RenewalPlan{}, fmt.Errorf("OPS_NODE_POLICY_RENEWAL_BUDGET (1..%d), OPS_NODE_POLICY_MAX_REORG_DEPTH (0..%d), OPS_NODE_POLICY_BLOCK_GAS_LIMIT (at least %d), OPS_NODE_POLICY_EXPECTED_TPS (at least 1) and OPS_NODE_POLICY_INCLUSION_BOUND (%s..%s) are out of range", maxRenewalBudget, maxReorgDepth, minTransactionGas, minInclusionBound, maxInclusionBound)
	}
	p := RenewalPlan{TTL: ttl, Margin: ttl / 4, WindowOpens: ttl / 2, MaxAge: maxAge, Budget: int(budget)}
	p.RenewLimit = budget * int64((p.WindowOpens-p.Margin)/time.Second)
	p.ReorgHeadroom = depth * (gas / minTransactionGas)
	p.AdmitLimit = p.RenewLimit - p.ReorgHeadroom
	p.AdmitFloor = int64(math.Ceil(2 * float64(tps) * inclusion.Seconds()))
	if p.AdmitLimit <= 0 || p.AdmitLimit < p.AdmitFloor {
		return p, fmt.Errorf("node policy renewal arithmetic is infeasible: the renewal budget renews at most %d pending transactions per window (OPS_NODE_POLICY_RENEWAL_BUDGET × OPS_NODE_POLICY_TRANSACTION_IDENTITY_TTL / 4); minus a reorg headroom of %d that leaves an admission limit of %d, below the %d that OPS_NODE_POLICY_EXPECTED_TPS and OPS_NODE_POLICY_INCLUSION_BOUND need; raise the budget or the lease, or lower the reorg depth or block gas limit", p.RenewLimit, p.ReorgHeadroom, p.AdmitLimit, p.AdmitFloor)
	}
	if timing.Tick <= 0 || timing.Tick > p.Margin/10 {
		return p, fmt.Errorf("node policy lease keeper tick %s exceeds a tenth of the renewal margin %s", timing.Tick, p.Margin)
	}
	if p.Margin-(timing.Tick+timing.Recheck+timing.Delivery) <= 0 {
		return p, fmt.Errorf("node policy renewal margin %s does not cover a keeper tick, a re-check and a delivery (%s)", p.Margin, timing.Tick+timing.Recheck+timing.Delivery)
	}
	// The per-principal and per-organization caps leave the admission floor
	// to everyone else: one principal, or all principals of one organization,
	// can never push the others below the work the expected rate needs, and
	// on its own it can still carry that rate.
	share := p.AdmitLimit - p.AdmitFloor
	alone := int64(math.Ceil(float64(tps) * inclusion.Seconds()))
	for _, limit := range []struct {
		setting  string
		explicit int64
		dst      *int64
	}{{"OPS_NODE_POLICY_PRINCIPAL_PENDING_LIMIT", c.PrincipalPendingLimit, &p.PrincipalLimit}, {"OPS_NODE_POLICY_ORG_PENDING_LIMIT", c.OrgPendingLimit, &p.OrgLimit}} {
		*limit.dst = limit.explicit
		if limit.explicit == 0 {
			*limit.dst = share
			if share < alone {
				return p, fmt.Errorf("node policy pending-work limit %d leaves one tenant %d after the %d every other keeps, below the %d needed at OPS_NODE_POLICY_EXPECTED_TPS; raise the renewal budget or the lease, or set %s explicitly", p.AdmitLimit, share, p.AdmitFloor, alone, limit.setting)
			}
		}
		if *limit.dst < 1 || *limit.dst > p.AdmitLimit {
			return p, fmt.Errorf("%s must be 1..%d (the admission limit)", limit.setting, p.AdmitLimit)
		}
	}
	return p, nil
}

// Transaction-identity lease bounds (plan §4.8.2): the node's wire allows
// identities of up to ten minutes; the maximum age stays within the raw
// transaction retention of the execution-tracking database.
const (
	MinTransactionIdentityTTL     = 120 * time.Second
	MaxTransactionIdentityTTL     = 600 * time.Second
	DefaultTransactionIdentityTTL = 300 * time.Second
	DefaultNodePolicyMaxAge       = 10 * time.Minute
	MaxNodePolicyMaxAge           = 60 * time.Minute
)

// TransactionLease returns the transaction-identity lease and the maximum
// age; a zero field (a literal configuration without them) takes its default.
func (c NodePolicyConfig) TransactionLease() (ttl, maxAge time.Duration) {
	ttl, maxAge = c.TransactionIdentityTTL, c.MaxAge
	if ttl == 0 {
		ttl = DefaultTransactionIdentityTTL
	}
	if maxAge == 0 {
		maxAge = DefaultNodePolicyMaxAge
	}
	return ttl, maxAge
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
