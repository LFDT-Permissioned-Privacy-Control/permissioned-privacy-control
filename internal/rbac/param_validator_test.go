package rbac

import (
	"math/big"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
)

const testABI = `[{"inputs":[{"name":"account","type":"address"}],"name":"balanceOf","outputs":[{"name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[{"name":"to","type":"address"},{"name":"amount","type":"uint256"}],"name":"transfer","outputs":[{"name":"","type":"bool"}],"stateMutability":"nonpayable","type":"function"}]`

// buildCalldata is a helper that packs function call data using the test ABI.
func buildCalldata(t *testing.T, methodName string, args ...interface{}) []byte {
	t.Helper()
	parsedABI, err := abi.JSON(strings.NewReader(testABI))
	if err != nil {
		t.Fatalf("failed to parse test ABI: %v", err)
	}
	calldata, err := parsedABI.Pack(methodName, args...)
	if err != nil {
		t.Fatalf("failed to pack %s calldata: %v", methodName, err)
	}
	return calldata
}

func TestValidateParamRules(t *testing.T) {
	ownAddr := common.HexToAddress("0x1111111111111111111111111111111111111111")
	otherAddr := common.HexToAddress("0x2222222222222222222222222222222222222222")

	balanceOfOwn := buildCalldata(t, "balanceOf", ownAddr)
	balanceOfOther := buildCalldata(t, "balanceOf", otherAddr)
	transferOwn := buildCalldata(t, "transfer", ownAddr, big.NewInt(1000))

	tests := []struct {
		name          string
		rule          *FunctionRule
		calldata      []byte
		contractABI   string
		userAddresses []string
		wantErr       bool
		errContains   string
	}{
		{
			name:          "nil rule",
			rule:          nil,
			calldata:      balanceOfOwn,
			contractABI:   testABI,
			userAddresses: []string{ownAddr.Hex()},
			wantErr:       false,
		},
		{
			name: "no param rules",
			rule: &FunctionRule{
				Selector:   "0x70a08231",
				ParamRules: nil,
			},
			calldata:      balanceOfOwn,
			contractABI:   testABI,
			userAddresses: []string{ownAddr.Hex()},
			wantErr:       false,
		},
		{
			name: "self constraint passes",
			rule: &FunctionRule{
				Selector:   "0x70a08231",
				ParamRules: []ParamRule{{Index: 0, MustBe: "self"}},
			},
			calldata:      balanceOfOwn,
			contractABI:   testABI,
			userAddresses: []string{ownAddr.Hex()},
			wantErr:       false,
		},
		{
			name: "self constraint fails",
			rule: &FunctionRule{
				Selector:   "0x70a08231",
				ParamRules: []ParamRule{{Index: 0, MustBe: "self"}},
			},
			calldata:      balanceOfOther,
			contractABI:   testABI,
			userAddresses: []string{ownAddr.Hex()},
			wantErr:       true,
			errContains:   "is not a linked address",
		},
		{
			name: "missing ABI",
			rule: &FunctionRule{
				Selector:   "0x70a08231",
				ParamRules: []ParamRule{{Index: 0, MustBe: "self"}},
			},
			calldata:      balanceOfOwn,
			contractABI:   "",
			userAddresses: []string{ownAddr.Hex()},
			wantErr:       true,
			errContains:   "contract ABI required",
		},
		{
			name: "no linked addresses",
			rule: &FunctionRule{
				Selector:   "0x70a08231",
				ParamRules: []ParamRule{{Index: 0, MustBe: "self"}},
			},
			calldata:      balanceOfOwn,
			contractABI:   testABI,
			userAddresses: nil,
			wantErr:       true,
			errContains:   "ETH address linking required",
		},
		{
			name: "index out of range",
			rule: &FunctionRule{
				Selector:   "0x70a08231",
				ParamRules: []ParamRule{{Index: 5, MustBe: "self"}},
			},
			calldata:      balanceOfOwn,
			contractABI:   testABI,
			userAddresses: []string{ownAddr.Hex()},
			wantErr:       true,
			errContains:   "parameter index 5 out of range",
		},
		{
			name: "transfer with self on param 0",
			rule: &FunctionRule{
				Selector:   "0xa9059cbb",
				ParamRules: []ParamRule{{Index: 0, MustBe: "self"}},
			},
			calldata:      transferOwn,
			contractABI:   testABI,
			userAddresses: []string{ownAddr.Hex()},
			wantErr:       false,
		},
		{
			name: "case-insensitive match",
			rule: &FunctionRule{
				Selector:   "0x70a08231",
				ParamRules: []ParamRule{{Index: 0, MustBe: "self"}},
			},
			calldata:    balanceOfOwn,
			contractABI: testABI,
			// Store lowercase version; ownAddr.Hex() returns checksummed mixed-case
			userAddresses: []string{strings.ToLower(ownAddr.Hex())},
			wantErr:       false,
		},
		{
			name: "unknown constraint type",
			rule: &FunctionRule{
				Selector:   "0x70a08231",
				ParamRules: []ParamRule{{Index: 0, MustBe: "admin_only"}},
			},
			calldata:      balanceOfOwn,
			contractABI:   testABI,
			userAddresses: []string{ownAddr.Hex()},
			wantErr:       true,
			errContains:   "unknown constraint type: admin_only",
		},
		{
			name: "calldata too short",
			rule: &FunctionRule{
				Selector:   "0x70a08231",
				ParamRules: []ParamRule{{Index: 0, MustBe: "self"}},
			},
			calldata:      []byte{0x70, 0xa0},
			contractABI:   testABI,
			userAddresses: []string{ownAddr.Hex()},
			wantErr:       true,
			errContains:   "calldata too short",
		},
		{
			name: "selector mismatch between rule and calldata",
			rule: &FunctionRule{
				Selector:   "0x70a08231", // balanceOf selector
				ParamRules: []ParamRule{{Index: 0, MustBe: "self"}},
			},
			calldata:      transferOwn,   // transfer calldata (selector 0xa9059cbb)
			contractABI:   testABI,
			userAddresses: []string{ownAddr.Hex()},
			wantErr:       true,
			errContains:   "does not match rule selector",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateParamRules(tt.rule, tt.calldata, tt.contractABI, tt.userAddresses)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.errContains)
				}
				if !strings.Contains(err.Error(), tt.errContains) {
					t.Fatalf("expected error containing %q, got %q", tt.errContains, err.Error())
				}
			} else {
				if err != nil {
					t.Fatalf("expected no error, got %v", err)
				}
			}
		})
	}
}
