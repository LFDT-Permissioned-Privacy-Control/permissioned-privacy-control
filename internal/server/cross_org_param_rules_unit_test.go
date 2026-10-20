package server

import (
	"context"
	"testing"

	"privacy-proxy/internal/rbac"

	"github.com/stretchr/testify/assert"
)

// mockAddressOrgResolver implements addressOrgResolver for unit tests.
type mockAddressOrgResolver struct {
	// contractOwners maps lowercase address -> orgID
	contractOwners map[string]string
	// eoaOrgs maps lowercase address -> []orgID
	eoaOrgs map[string][]string
}

func (m *mockAddressOrgResolver) GetContractOwnerOrgID(_ context.Context, address string) (string, error) {
	return m.contractOwners[address], nil
}

func (m *mockAddressOrgResolver) GetOrgIDsForEthAddress(_ context.Context, address string) ([]string, error) {
	return m.eoaOrgs[address], nil
}

func TestValidateCrossOrgParamRules(t *testing.T) {
	const orgA = "org-a"
	const orgB = "org-b"

	store := &mockAddressOrgResolver{
		contractOwners: map[string]string{
			"0xaaaa000000000000000000000000000000000001": orgA,
			"0xbbbb000000000000000000000000000000000001": orgB,
		},
		eoaOrgs: map[string][]string{
			"0x1111111111111111111111111111111111111111": {orgA},       // same-org EOA
			"0x2222222222222222222222222222222222222222": {orgB},       // cross-org EOA
			"0x3333333333333333333333333333333333333333": {orgA, orgB}, // multi-org EOA
		},
	}

	tests := []struct {
		name    string
		orgID   string
		rules   []rbac.EventRule
		abiJSON string
		wantErr string // substring of expected error, "" = no error
	}{
		{
			name:    "self constraint — no cross-org check",
			orgID:   orgA,
			abiJSON: erc20ABI,
			rules: []rbac.EventRule{
				{Topic0: transferTopic0, Name: "Transfer", ParamRules: []rbac.ParamRule{
					{Index: 0, MustBe: "self"},
				}},
			},
			wantErr: "",
		},
		{
			name:    "same-org contract address — allowed",
			orgID:   orgA,
			abiJSON: erc20ABI,
			rules: []rbac.EventRule{
				{Topic0: transferTopic0, Name: "Transfer", ParamRules: []rbac.ParamRule{
					{Index: 0, MustBe: "0xaaaa000000000000000000000000000000000001"},
				}},
			},
			wantErr: "",
		},
		{
			name:    "cross-org contract address — rejected",
			orgID:   orgA,
			abiJSON: erc20ABI,
			rules: []rbac.EventRule{
				{Topic0: transferTopic0, Name: "Transfer", ParamRules: []rbac.ParamRule{
					{Index: 0, MustBe: "0xbbbb000000000000000000000000000000000001"},
				}},
			},
			wantErr: "different organization",
		},
		{
			name:    "same-org EOA — allowed",
			orgID:   orgA,
			abiJSON: erc20ABI,
			rules: []rbac.EventRule{
				{Topic0: transferTopic0, Name: "Transfer", ParamRules: []rbac.ParamRule{
					{Index: 0, MustBe: "0x1111111111111111111111111111111111111111"},
				}},
			},
			wantErr: "",
		},
		{
			name:    "cross-org EOA — rejected",
			orgID:   orgA,
			abiJSON: erc20ABI,
			rules: []rbac.EventRule{
				{Topic0: transferTopic0, Name: "Transfer", ParamRules: []rbac.ParamRule{
					{Index: 0, MustBe: "0x2222222222222222222222222222222222222222"},
				}},
			},
			wantErr: "different organization",
		},
		{
			name:    "multi-org EOA in same org — allowed",
			orgID:   orgA,
			abiJSON: erc20ABI,
			rules: []rbac.EventRule{
				{Topic0: transferTopic0, Name: "Transfer", ParamRules: []rbac.ParamRule{
					{Index: 0, MustBe: "0x3333333333333333333333333333333333333333"},
				}},
			},
			wantErr: "",
		},
		{
			name:    "unregistered address — rejected (fail-closed)",
			orgID:   orgA,
			abiJSON: erc20ABI,
			rules: []rbac.EventRule{
				{Topic0: transferTopic0, Name: "Transfer", ParamRules: []rbac.ParamRule{
					{Index: 0, MustBe: "0x9999999999999999999999999999999999999999"},
				}},
			},
			wantErr: "unregistered address",
		},
		{
			name:    "non-address param (uint256) — skips cross-org check",
			orgID:   orgA,
			abiJSON: erc20ABI,
			rules: []rbac.EventRule{
				{Topic0: transferTopic0, Name: "Transfer", ParamRules: []rbac.ParamRule{
					// index 2 = "value" (uint256)
					{Index: 2, MustBe: "0x0000000000000000000000000000000000000000000000000000000000000064"},
				}},
			},
			wantErr: "",
		},
		{
			name:    "event not in ABI — skips check (cannot determine param types)",
			orgID:   orgA,
			abiJSON: erc20ABI,
			rules: []rbac.EventRule{
				{Topic0: "0x0000000000000000000000000000000000000000000000000000000000000000", Name: "Unknown", ParamRules: []rbac.ParamRule{
					{Index: 0, MustBe: "0xbbbb000000000000000000000000000000000001"},
				}},
			},
			wantErr: "",
		},
		{
			name:    "no param rules — no check needed",
			orgID:   orgA,
			abiJSON: erc20ABI,
			rules:   []rbac.EventRule{{Topic0: transferTopic0, Name: "Transfer"}},
			wantErr: "",
		},
		{
			name:    "no ABI — skips check (custom hex already rejected upstream)",
			orgID:   orgA,
			abiJSON: "",
			rules: []rbac.EventRule{
				{Topic0: transferTopic0, Name: "Transfer", ParamRules: []rbac.ParamRule{
					{Index: 0, MustBe: "0xbbbb000000000000000000000000000000000001"},
				}},
			},
			wantErr: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errMsg := validateCrossOrgParamRules(context.Background(), store, tt.orgID, tt.rules, tt.abiJSON)
			if tt.wantErr == "" {
				assert.Empty(t, errMsg, "expected no error")
			} else {
				assert.Contains(t, errMsg, tt.wantErr)
			}
		})
	}
}
