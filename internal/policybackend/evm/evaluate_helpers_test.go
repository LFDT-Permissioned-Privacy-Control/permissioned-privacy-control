package evm

import (
	"math/big"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"

	. "privacy-proxy/internal/policycore"
)

var (
	signerAddr   = common.HexToAddress("0xAAAA000000000000000000000000000000000001")
	linkedAddr   = common.HexToAddress("0xBBBB000000000000000000000000000000000002")
	strangerAddr = common.HexToAddress("0xCCCC000000000000000000000000000000000003")
)

// packCalldata builds real calldata so the evaluator is exercised against bytes
// an EVM would actually see.
func packCalldata(t testing.TB, abiText, method string, args ...any) []byte {
	t.Helper()
	parsed, err := abi.JSON(strings.NewReader(abiText))
	if err != nil {
		t.Fatalf("fixture ABI does not parse: %v", err)
	}
	data, err := parsed.Pack(method, args...)
	if err != nil {
		t.Fatalf("packing %s calldata: %v", method, err)
	}
	return data
}

func transferCalldata(t testing.TB, to common.Address, amount *big.Int) []byte {
	t.Helper()
	return packCalldata(t, vaultABI, "transfer", to, amount)
}

func balanceOfCalldata(t testing.TB, owner common.Address) []byte {
	t.Helper()
	return packCalldata(t, vaultABI, "balanceOf", owner)
}

// validatedWith builds a Validated from one binding's rules.
func validatedWith(t *testing.T, rules ...FrameRule) *Validated {
	t.Helper()
	return validatedFrom(t, []Binding{{Group: groupID, Allow: rules}})
}

func validatedFrom(t *testing.T, bindings []Binding) *Validated {
	t.Helper()
	p := &Policy{
		APIVersion:  APIVersion,
		Kind:        Kind,
		Org:         orgID,
		NestedCalls: NestedCallsRequireOwnRule,
		Bindings:    bindings,
	}
	v, err := Validate(p, testCatalog(t))
	if err != nil {
		t.Fatalf("fixture policy failed validation: %v", err)
	}
	return v
}

func plainRule(t *testing.T, selector string, args ...ArgConstraint) FrameRule {
	t.Helper()
	return FrameRule{
		StorageAddress: vaultAddr,
		Selector:       selector,
		ABIDigest:      abiDigest(t, vaultABI),
		Args:           args,
	}
}

func delegateRule(t *testing.T, callType CallType, args ...ArgConstraint) FrameRule {
	t.Helper()
	return FrameRule{
		StorageAddress: vaultAddr,
		CodeAddress:    libraryAddr.Hex(),
		Selector:       selTransfer,
		ABIDigest:      abiDigest(t, libraryABI),
		CallTypes:      []CallType{callType},
		Args:           args,
	}
}

func memberCtx() Context {
	return Context{
		Org:             orgID,
		Groups:          []string{groupID},
		Signer:          signerAddr,
		LinkedAddresses: []common.Address{signerAddr, linkedAddr},
	}
}

func vaultCall(data []byte) Frame {
	return Frame{
		CodeOrg: orgID, StorageOrg: orgID,
		CallType:       CallTypeCall,
		StorageAddress: common.HexToAddress(vaultAddr),
		CodeAddress:    common.HexToAddress(vaultAddr),
		Calldata:       data,
	}
}

func delegateFrame(callType CallType, code common.Address, data []byte) Frame {
	return Frame{
		CodeOrg: orgID, StorageOrg: orgID,
		CallType:       callType,
		StorageAddress: common.HexToAddress(vaultAddr),
		CodeAddress:    code,
		Calldata:       data,
	}
}

func basePolicy(t *testing.T) *Policy {
	t.Helper()
	return &Policy{
		APIVersion:  APIVersion,
		Kind:        Kind,
		Org:         orgID,
		NestedCalls: NestedCallsRequireOwnRule,
		Bindings: []Binding{{
			Group: groupID,
			Allow: []FrameRule{{
				StorageAddress: vaultAddr,
				Selector:       selTransfer,
				ABIDigest:      abiDigest(t, vaultABI),
			}},
		}},
	}
}
