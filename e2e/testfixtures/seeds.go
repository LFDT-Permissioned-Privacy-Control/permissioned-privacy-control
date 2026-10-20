package testfixtures

import (
	"context"
	"testing"

	"privacy-proxy/internal/db"
	"privacy-proxy/internal/rbac"
)

// SeedRBACDefaults re-applies the migration 001 default-org seed and
// the migration 044 anonymous-group seed. setupE2E (proxy_test.go)
// calls ResetTestDatabase which wipes both, but the JSON-RPC auth
// flow (EnsureUserExists in internal/rbac/access.go) attaches new
// users to DefaultGroupID — so any test that mints a JWT through
// /auth/verify must re-seed first.
//
// Idempotent: CreateX returns an error if the row exists, which we
// swallow (the test cares about the row being present, not who
// created it).
func SeedRBACDefaults(t *testing.T, database *db.DB) {
	t.Helper()
	ctx := context.Background()

	// Default org + group (migration 001).
	_ = database.CreateOrganization(ctx, &rbac.Organization{
		ID:       rbac.DefaultOrgID,
		Slug:     "default",
		Name:     "Default Organization",
		Settings: map[string]any{},
	})
	_ = database.CreateGroup(ctx, &rbac.Group{
		ID:    rbac.DefaultGroupID,
		OrgID: rbac.DefaultOrgID,
		Slug:  "default",
		Name:  "Default Group",
		Depth: 0,
		Path:  "default",
	})
	_ = database.CreateGroupAccess(ctx, &rbac.GroupAccess{
		ID:      rbac.DefaultGroupID,
		GroupID: rbac.DefaultGroupID,
		// Broad enough to cover the common read methods existing tests
		// exercise. Tests that need a narrower group create their own.
		AllowedMethods: []string{
			"eth_call", "eth_getBalance", "eth_blockNumber", "eth_chainId",
			"eth_estimateGas", "eth_gasPrice", "eth_getCode", "eth_getLogs",
			"eth_getStorageAt", "eth_getTransactionByHash",
			"eth_getTransactionCount", "eth_getTransactionReceipt",
			"eth_sendRawTransaction", "net_version",
		},
		Claims: []rbac.Claim{},
	})

	// Anonymous org + group (migration 044).
	_ = database.CreateOrganization(ctx, &rbac.Organization{
		ID:       rbac.AnonymousOrgID,
		Slug:     "anonymous",
		Name:     "Anonymous",
		Settings: map[string]any{},
	})
	_ = database.CreateGroup(ctx, &rbac.Group{
		ID:    rbac.AnonymousGroupID,
		OrgID: rbac.AnonymousOrgID,
		Slug:  "anonymous",
		Name:  "Anonymous",
		Depth: 0,
		Path:  "anonymous",
	})
	_ = database.CreateGroupAccess(ctx, &rbac.GroupAccess{
		ID:      rbac.AnonymousGroupID,
		GroupID: rbac.AnonymousGroupID,
		AllowedMethods: []string{
			"eth_blockNumber", "eth_chainId", "eth_gasPrice",
			"net_version", "net_listening", "web3_clientVersion",
		},
		Claims: []rbac.Claim{},
	})
}
