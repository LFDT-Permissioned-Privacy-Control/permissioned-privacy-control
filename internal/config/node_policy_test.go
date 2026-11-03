package config

import (
	"testing"
	"time"
)

func TestNodePolicyModeRequiresCompleteBoundedConfiguration(t *testing.T) {
	if err := (NodePolicyConfig{}).Validate(); err != nil {
		t.Fatal(err)
	}
	env := map[string]string{"OPS_NODE_POLICY_MODE": "reth", "OPS_NODE_POLICY_URL": "http://reth:8555", "OPS_NODE_POLICY_TOKEN": "private-test-token", "OPS_NODE_POLICY_PRIVATE_KEY_FILE": "/run/secrets/ops-node-key", "OPS_NODE_POLICY_KEY_ID": "ops-a", "OPS_NODE_POLICY_CHAIN_ID": "31337", "OPS_NODE_POLICY_DEPLOYMENT_ID": "stack-a"}
	get := func(key string) string { return env[key] }
	c := loadNodePolicy(get)
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	if c.Mode != "reth" || c.FactTTL.String() != "30s" || c.PublishInterval.String() != "1s" || c.IdentityTTL.String() != "1m0s" {
		t.Fatalf("unexpected defaults %+v", c)
	}
	for _, key := range []string{"OPS_NODE_POLICY_URL", "OPS_NODE_POLICY_TOKEN", "OPS_NODE_POLICY_PRIVATE_KEY_FILE", "OPS_NODE_POLICY_KEY_ID", "OPS_NODE_POLICY_CHAIN_ID", "OPS_NODE_POLICY_DEPLOYMENT_ID"} {
		old := env[key]
		delete(env, key)
		if err := loadNodePolicy(get).Validate(); err == nil {
			t.Errorf("missing %s accepted", key)
		}
		env[key] = old
	}
	env["OPS_NODE_POLICY_CONTROL_URL"] = "http://reth:8556"
	if c := loadNodePolicy(get); c.Validate() != nil || c.ControlURL != "http://reth:8556" {
		t.Fatalf("control URL %+v", c)
	}
	delete(env, "OPS_NODE_POLICY_CONTROL_URL")
	for _, pair := range [][2]string{{"OPS_NODE_POLICY_CONTROL_URL", "http://user:pw@reth:8556"}, {"OPS_NODE_POLICY_MODE", "besu"}, {"OPS_NODE_POLICY_FACT_TTL", "0s"}, {"OPS_NODE_POLICY_FACT_TTL", "11m"}, {"OPS_NODE_POLICY_PUBLISH_INTERVAL", "11s"}, {"OPS_NODE_POLICY_IDENTITY_TTL", "invalid"}, {"OPS_NODE_POLICY_CHAIN_ID", "not-a-number"}, {"OPS_NODE_POLICY_URL", "http://user:password@reth:8555"}} {
		old, exists := env[pair[0]]
		env[pair[0]] = pair[1]
		if err := loadNodePolicy(get).Validate(); err == nil {
			t.Errorf("invalid %v accepted", pair)
		}
		if exists {
			env[pair[0]] = old
		} else {
			delete(env, pair[0])
		}
	}
}

// RD-1410: the private-node connection lanes default to 4/64/16
// (84 per instance, inside a node limit of 128) and are bounded.
func TestNodePolicyConnectionLanes(t *testing.T) {
	env := map[string]string{"OPS_NODE_POLICY_MODE": "reth", "OPS_NODE_POLICY_URL": "http://reth:8555", "OPS_NODE_POLICY_TOKEN": "private-test-token", "OPS_NODE_POLICY_PRIVATE_KEY_FILE": "/run/secrets/ops-node-key", "OPS_NODE_POLICY_KEY_ID": "ops-a", "OPS_NODE_POLICY_CHAIN_ID": "31337", "OPS_NODE_POLICY_DEPLOYMENT_ID": "stack-a"}
	get := func(key string) string { return env[key] }
	c := loadNodePolicy(get)
	if err := c.Validate(); err != nil || c.ControlConns != 4 || c.TransactionConns != 64 || c.RecoveryConns != 16 {
		t.Fatalf("defaults %d/%d/%d %v", c.ControlConns, c.TransactionConns, c.RecoveryConns, err)
	}
	env["OPS_NODE_POLICY_TRANSACTION_CONNS"] = "200"
	if c := loadNodePolicy(get); c.Validate() != nil || c.TransactionConns != 200 {
		t.Fatalf("override %+v", c)
	}
	for _, pair := range [][2]string{{"OPS_NODE_POLICY_CONTROL_CONNS", "0"}, {"OPS_NODE_POLICY_TRANSACTION_CONNS", "5000"}, {"OPS_NODE_POLICY_RECOVERY_CONNS", "many"}} {
		env[pair[0]] = pair[1]
		if err := loadNodePolicy(get).Validate(); err == nil {
			t.Errorf("invalid %v accepted", pair)
		}
		delete(env, pair[0])
	}
}

// RD-1410 plan §4.8.2: transaction identities get their own lease (default
// 300 s, 120..600 s, the node's wire maximum) and a maximum age (default
// 10 min, at least the lease, at most 60 min) after which the lease keeper
// stops renewing; simulations keep OPS_NODE_POLICY_IDENTITY_TTL.
func TestNodePolicyTransactionLeaseAndMaxAge(t *testing.T) {
	env := map[string]string{"OPS_NODE_POLICY_MODE": "reth", "OPS_NODE_POLICY_URL": "http://reth:8555", "OPS_NODE_POLICY_TOKEN": "private-test-token", "OPS_NODE_POLICY_PRIVATE_KEY_FILE": "/run/secrets/ops-node-key", "OPS_NODE_POLICY_KEY_ID": "ops-a", "OPS_NODE_POLICY_CHAIN_ID": "31337", "OPS_NODE_POLICY_DEPLOYMENT_ID": "stack-a"}
	get := func(key string) string { return env[key] }
	c := loadNodePolicy(get)
	if ttl, maxAge := c.TransactionLease(); c.Validate() != nil || ttl.String() != "5m0s" || maxAge.String() != "10m0s" {
		t.Fatalf("defaults %s %s %v", ttl, maxAge, c.Validate())
	}
	env["OPS_NODE_POLICY_TRANSACTION_IDENTITY_TTL"], env["OPS_NODE_POLICY_MAX_AGE"] = "600s", "60m"
	if ttl, maxAge := loadNodePolicy(get).TransactionLease(); loadNodePolicy(get).Validate() != nil || ttl.String() != "10m0s" || maxAge.String() != "1h0m0s" {
		t.Fatalf("override %s %s", ttl, maxAge)
	}
	for _, pair := range [][2]string{{"OPS_NODE_POLICY_TRANSACTION_IDENTITY_TTL", "119s"}, {"OPS_NODE_POLICY_TRANSACTION_IDENTITY_TTL", "601s"}, {"OPS_NODE_POLICY_MAX_AGE", "4m"}, {"OPS_NODE_POLICY_MAX_AGE", "61m"}, {"OPS_NODE_POLICY_MAX_AGE", "soon"}} {
		env["OPS_NODE_POLICY_TRANSACTION_IDENTITY_TTL"], env["OPS_NODE_POLICY_MAX_AGE"] = "300s", "10m"
		env[pair[0]] = pair[1]
		if err := loadNodePolicy(get).Validate(); err == nil {
			t.Errorf("invalid %v accepted", pair)
		}
	}
}

func rethEnv() map[string]string {
	return map[string]string{"OPS_NODE_POLICY_MODE": "reth", "OPS_NODE_POLICY_URL": "http://reth:8555", "OPS_NODE_POLICY_TOKEN": "private-test-token", "OPS_NODE_POLICY_PRIVATE_KEY_FILE": "/run/secrets/ops-node-key", "OPS_NODE_POLICY_KEY_ID": "ops-a", "OPS_NODE_POLICY_CHAIN_ID": "31337", "OPS_NODE_POLICY_DEPLOYMENT_ID": "stack-a"}
}

// G25 (plan §4.8.2): the renewal window, budget and pending-work limits are
// derived from the lease and checked at startup. Defaults: R = TTL/4 = 75 s,
// L_renew = budget × TTL/4 = 37,500, reorg headroom = 2 blocks × ⌊200M/21,000⌋
// = 19,046, L_admit = 18,454, admission floor 2 × 2,000/s × 1.5 s = 6,000,
// per-principal cap L_admit − floor = 12,454 (the floor stays for everyone
// else; one principal alone keeps ≥ 2,000/s × 1.5 s).
func TestConfigRejectsInfeasibleTTLWindowBudget(t *testing.T) {
	env := rethEnv()
	get := func(key string) string { return env[key] }
	c := loadNodePolicy(get)
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	plan, err := c.RenewalPlan()
	if err != nil {
		t.Fatal(err)
	}
	want := RenewalPlan{TTL: 300 * time.Second, Margin: 75 * time.Second, WindowOpens: 150 * time.Second, MaxAge: 10 * time.Minute, Budget: 500, RenewLimit: 37500, ReorgHeadroom: 19046, AdmitLimit: 18454, PrincipalLimit: 12454, OrgLimit: 12454, AdmitFloor: 6000}
	if plan != want {
		t.Fatalf("plan\n got %+v\nwant %+v", plan, want)
	}
	// Overrides that keep the arithmetic feasible.
	for _, ok := range []map[string]string{
		{"OPS_NODE_POLICY_TRANSACTION_IDENTITY_TTL": "600s", "OPS_NODE_POLICY_MAX_AGE": "60m"},
		{"OPS_NODE_POLICY_TRANSACTION_IDENTITY_TTL": "120s", "OPS_NODE_POLICY_RENEWAL_BUDGET": "935"}, // the operator docs' minimum at 120 s
		{"OPS_NODE_POLICY_MAX_REORG_DEPTH": "0", "OPS_NODE_POLICY_RENEWAL_BUDGET": "120"},             // L_admit 9,000 = floor + one principal
		{"OPS_NODE_POLICY_PRINCIPAL_PENDING_LIMIT": "18454"},
		{"OPS_NODE_POLICY_RENEWAL_BUDGET": "370", "OPS_NODE_POLICY_PRINCIPAL_PENDING_LIMIT": "2000", "OPS_NODE_POLICY_ORG_PENDING_LIMIT": "4000"}, // explicit caps below one tenant's rate
		{"OPS_NODE_POLICY_ORG_PENDING_LIMIT": "18454"},
		{"OPS_NODE_POLICY_PRINCIPAL_PENDING_LIMIT": "1"},
	} {
		env = rethEnv()
		for k, v := range ok {
			env[k] = v
		}
		if err := loadNodePolicy(get).Validate(); err != nil {
			t.Errorf("feasible %v refused: %v", ok, err)
		}
	}
	if p, err := loadNodePolicy(get).RenewalPlan(); err != nil || p.PrincipalLimit != 1 {
		t.Fatalf("explicit per-principal limit: %+v %v", p, err)
	}
	// Infeasible or malformed configurations are refused at startup.
	for _, bad := range []map[string]string{
		{"OPS_NODE_POLICY_TRANSACTION_IDENTITY_TTL": "120s"}, // L_renew 15,000 < headroom 19,046
		{"OPS_NODE_POLICY_TRANSACTION_IDENTITY_TTL": "120s", "OPS_NODE_POLICY_RENEWAL_BUDGET": "934"},
		{"OPS_NODE_POLICY_RENEWAL_BUDGET": "250"},            // L_admit = 18,750 - 19,046 < 0
		{"OPS_NODE_POLICY_RENEWAL_BUDGET": "300"},            // L_admit 3,454 < 2 × 2,000 × 1.5 s
		{"OPS_NODE_POLICY_EXPECTED_TPS": "10000"},            // floor 30,000 > L_admit
		{"OPS_NODE_POLICY_INCLUSION_BOUND": "10s"},           // floor 40,000 > L_admit
		{"OPS_NODE_POLICY_BLOCK_GAS_LIMIT": "400000000"},     // headroom 38,094 > L_renew
		{"OPS_NODE_POLICY_PRINCIPAL_PENDING_LIMIT": "18455"}, // above L_admit
		{"OPS_NODE_POLICY_PRINCIPAL_PENDING_LIMIT": "0"},
		{"OPS_NODE_POLICY_ORG_PENDING_LIMIT": "0"},
		{"OPS_NODE_POLICY_ORG_PENDING_LIMIT": "18455"},
		{"OPS_NODE_POLICY_RENEWAL_BUDGET": "370", "OPS_NODE_POLICY_PRINCIPAL_PENDING_LIMIT": "2000"}, // the derived organization cap is still too low
		{"OPS_NODE_POLICY_RENEWAL_BUDGET": "370"},                                                    // L_admit 8,704: the default cap 2,704 < 3,000 one principal needs
		{"OPS_NODE_POLICY_RENEWAL_BUDGET": "0"},
		{"OPS_NODE_POLICY_RENEWAL_BUDGET": "2001"},
		{"OPS_NODE_POLICY_RENEWAL_BUDGET": "fast"},
		{"OPS_NODE_POLICY_MAX_REORG_DEPTH": "-1"},
		{"OPS_NODE_POLICY_MAX_REORG_DEPTH": "65"},
		{"OPS_NODE_POLICY_BLOCK_GAS_LIMIT": "20999"},
		{"OPS_NODE_POLICY_EXPECTED_TPS": "0"},
		{"OPS_NODE_POLICY_INCLUSION_BOUND": "0s"},
		{"OPS_NODE_POLICY_INCLUSION_BOUND": "61s"},
	} {
		env = rethEnv()
		for k, v := range bad {
			env[k] = v
		}
		if err := loadNodePolicy(get).Validate(); err == nil {
			t.Errorf("infeasible %v accepted", bad)
		}
	}
	// The deadline and tick checks: the renewal margin must cover a keeper
	// tick, a re-check and a delivery, and the tick must be at most R/10.
	for _, timing := range []KeeperTiming{
		{Tick: 4 * time.Second, Recheck: time.Second, Delivery: time.Second},       // tick > R/10 at TTL 120 s (R = 30 s)
		{Tick: time.Second, Recheck: 20 * time.Second, Delivery: 10 * time.Second}, // 1 + 20 + 10 > 30
	} {
		env = rethEnv()
		env["OPS_NODE_POLICY_TRANSACTION_IDENTITY_TTL"], env["OPS_NODE_POLICY_RENEWAL_BUDGET"] = "120s", "1000"
		if _, err := loadNodePolicy(get).renewalPlan(timing); err == nil {
			t.Errorf("timing %+v accepted at TTL 120 s", timing)
		}
	}
	env = rethEnv()
	if _, err := loadNodePolicy(get).renewalPlan(DefaultKeeperTiming); err != nil {
		t.Fatalf("default timing at defaults: %v", err)
	}
}
