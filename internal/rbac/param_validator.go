package rbac

import (
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
)

// ValidateParamRules checks that function call parameters satisfy the constraints
// defined in a FunctionRule. For example, a "self" constraint requires that the
// address parameter matches one of the caller's linked ETH addresses.
//
// Returns nil if all constraints pass, or an error describing the first violation.
func ValidateParamRules(rule *FunctionRule, calldata []byte, contractABI string, userAddresses []string) error {
	if rule == nil || len(rule.ParamRules) == 0 {
		return nil
	}

	if contractABI == "" {
		return fmt.Errorf("contract ABI required for parameter constraints")
	}

	if len(userAddresses) == 0 {
		return fmt.Errorf("ETH address linking required for parameter constraints")
	}

	parsedABI, err := abi.JSON(strings.NewReader(contractABI))
	if err != nil {
		return fmt.Errorf("failed to parse contract ABI: %w", err)
	}

	if len(calldata) < 4 {
		return fmt.Errorf("calldata too short: need at least 4 bytes for function selector")
	}

	method, err := parsedABI.MethodById(calldata[:4])
	if err != nil {
		return fmt.Errorf("failed to find method by selector: %w", err)
	}

	// Verify calldata selector matches the rule's selector (defense in depth).
	// Both currently derive from the same calldata, but this guards against future
	// refactors where req.FunctionSelector might come from a different source.
	calldataSelector := "0x" + hex.EncodeToString(calldata[:4])
	if !strings.EqualFold(calldataSelector, rule.Selector) {
		return fmt.Errorf("calldata selector %s does not match rule selector %s", calldataSelector, rule.Selector)
	}

	args, err := method.Inputs.Unpack(calldata[4:])
	if err != nil {
		return fmt.Errorf("failed to unpack arguments: %w", err)
	}

	for _, pr := range rule.ParamRules {
		if pr.Index < 0 || pr.Index >= len(args) {
			return fmt.Errorf("parameter index %d out of range (function has %d parameters)", pr.Index, len(args))
		}

		switch pr.MustBe {
		case "self":
			addr, ok := args[pr.Index].(common.Address)
			if !ok {
				return fmt.Errorf("parameter %d: expected address type, got %T", pr.Index, args[pr.Index])
			}

			if !addressMatchesAny(addr, userAddresses) {
				return fmt.Errorf("parameter %d: address %s is not a linked address", pr.Index, addr.Hex())
			}
		default:
			return fmt.Errorf("unknown constraint type: %s", pr.MustBe)
		}
	}

	return nil
}

// addressMatchesAny checks if the given address matches any of the provided
// addresses (case-insensitive comparison).
func addressMatchesAny(addr common.Address, userAddresses []string) bool {
	addrHex := strings.ToLower(addr.Hex())
	for _, ua := range userAddresses {
		if strings.ToLower(ua) == addrHex {
			return true
		}
	}
	return false
}
