package config

import "testing"

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
