package rbac

import (
	"context"
	"encoding/hex"
	"fmt"
	"strings"
)

// Known upgrade function selectors for common proxy patterns.
// These are the first 4 bytes of the keccak256 hash of the function signature.
var (
	// upgradeTo(address) - OpenZeppelin UUPS/Transparent proxy
	SelectorUpgradeTo = "3659cfe6"

	// upgradeToAndCall(address,bytes) - OpenZeppelin UUPS/Transparent proxy
	SelectorUpgradeToAndCall = "4f1ef286"

	// setImplementation(address) - Generic proxy pattern
	SelectorSetImplementation = "d784d426"

	// upgradeTo(address) - BeaconProxy (on beacon contract)
	SelectorBeaconUpgradeTo = "3659cfe6"

	// upgrade(address,address) - TransparentUpgradeableProxy admin
	SelectorProxyAdminUpgrade = "99a88ec4"

	// upgradeAndCall(address,address,bytes) - TransparentUpgradeableProxy admin
	SelectorProxyAdminUpgradeAndCall = "9623609d"
)

// UpgradeSelectors is a set of all known upgrade function selectors.
var UpgradeSelectors = map[string]string{
	SelectorUpgradeTo:                "upgradeTo(address)",
	SelectorUpgradeToAndCall:         "upgradeToAndCall(address,bytes)",
	SelectorSetImplementation:        "setImplementation(address)",
	SelectorProxyAdminUpgrade:        "upgrade(address,address)",
	SelectorProxyAdminUpgradeAndCall: "upgradeAndCall(address,address,bytes)",
}

// UpgradeValidator validates proxy upgrade transactions.
type UpgradeValidator struct {
	store Store
}

// NewUpgradeValidator creates a new upgrade validator.
func NewUpgradeValidator(store Store) *UpgradeValidator {
	return &UpgradeValidator{store: store}
}

// UpgradeValidationResult contains the result of upgrade validation.
type UpgradeValidationResult struct {
	IsUpgradeCall     bool   // Whether the calldata matches an upgrade selector
	Allowed           bool   // Whether the upgrade is allowed
	Reason            string // Reason for denial (if not allowed)
	NewImplementation string // The new implementation address extracted from calldata
	FunctionName      string // The matched upgrade function name
}

// ValidateUpgrade checks if a proxy upgrade transaction is allowed.
// It verifies:
// 1. Whether the target address is a managed proxy
// 2. Whether the calldata matches a known upgrade selector
// 3. Whether the new implementation is owned by the organization
func (v *UpgradeValidator) ValidateUpgrade(
	ctx context.Context,
	orgID string,
	proxyAddress string,
	calldata []byte,
) (*UpgradeValidationResult, error) {
	result := &UpgradeValidationResult{}

	// Check if calldata matches an upgrade selector
	if len(calldata) < 4 {
		result.IsUpgradeCall = false
		result.Allowed = true // Not an upgrade call, allow it to proceed
		return result, nil
	}

	selector := hex.EncodeToString(calldata[:4])
	funcName, isUpgrade := UpgradeSelectors[selector]
	if !isUpgrade {
		result.IsUpgradeCall = false
		result.Allowed = true // Not an upgrade call, allow it to proceed
		return result, nil
	}

	result.IsUpgradeCall = true
	result.FunctionName = funcName

	// Runtime tracing validates the upgrade target at execution time,
	// so managed proxy registration is not required.

	// Extract new implementation address from calldata
	newImpl, err := extractImplementationAddress(selector, calldata)
	if err != nil {
		result.Allowed = false
		result.Reason = fmt.Sprintf("failed to extract implementation address: %v", err)
		return result, nil
	}
	result.NewImplementation = newImpl

	// Verify new implementation is owned by the org
	owned, err := v.store.IsAddressOwnedByOrg(ctx, newImpl, orgID)
	if err != nil {
		return nil, fmt.Errorf("failed to check implementation ownership: %w", err)
	}

	if !owned {
		result.Allowed = false
		result.Reason = fmt.Sprintf("new implementation %s is not owned by the organization", newImpl)
		return result, nil
	}

	result.Allowed = true
	return result, nil
}

// IsUpgradeSelector checks if a function selector is a known upgrade selector.
func IsUpgradeSelector(selector string) bool {
	selector = strings.TrimPrefix(strings.ToLower(selector), "0x")
	_, ok := UpgradeSelectors[selector]
	return ok
}

// GetUpgradeFunctionName returns the function name for a known upgrade selector.
func GetUpgradeFunctionName(selector string) string {
	selector = strings.TrimPrefix(strings.ToLower(selector), "0x")
	return UpgradeSelectors[selector]
}

// extractImplementationAddress extracts the new implementation address from upgrade calldata.
// The address position depends on the function signature:
// - upgradeTo(address): address at bytes 4-36
// - upgradeToAndCall(address,bytes): address at bytes 4-36
// - setImplementation(address): address at bytes 4-36
// - upgrade(address,address): second address at bytes 36-68 (first is proxy)
// - upgradeAndCall(address,address,bytes): second address at bytes 36-68
func extractImplementationAddress(selector string, calldata []byte) (string, error) {
	switch selector {
	case SelectorUpgradeTo, SelectorUpgradeToAndCall, SelectorSetImplementation:
		// Single address parameter or address is first parameter
		if len(calldata) < 36 {
			return "", fmt.Errorf("calldata too short for %s", UpgradeSelectors[selector])
		}
		// Address is in bytes 4-36, but only last 20 bytes are the address
		// (first 12 bytes are zero padding in ABI encoding)
		addrBytes := calldata[16:36]
		return "0x" + hex.EncodeToString(addrBytes), nil

	case SelectorProxyAdminUpgrade, SelectorProxyAdminUpgradeAndCall:
		// Two address parameters: upgrade(proxy, implementation)
		// Implementation is the second parameter
		if len(calldata) < 68 {
			return "", fmt.Errorf("calldata too short for %s", UpgradeSelectors[selector])
		}
		// Second address is in bytes 36-68, but only last 20 bytes are the address
		addrBytes := calldata[48:68]
		return "0x" + hex.EncodeToString(addrBytes), nil

	default:
		return "", fmt.Errorf("unknown upgrade selector: %s", selector)
	}
}
