package precompile

import (
	"strings"
)

// PrecompileAddresses maps Ethereum precompiled contract addresses to their names.
// These are special addresses (0x01-0x09) that provide cryptographic functions
// implemented natively in the EVM for gas efficiency.
var PrecompileAddresses = map[string]string{
	"0x0000000000000000000000000000000000000001": "ecrecover",
	"0x0000000000000000000000000000000000000002": "sha256",
	"0x0000000000000000000000000000000000000003": "ripemd160",
	"0x0000000000000000000000000000000000000004": "identity",
	"0x0000000000000000000000000000000000000005": "modexp",
	"0x0000000000000000000000000000000000000006": "ecAdd",
	"0x0000000000000000000000000000000000000007": "ecMul",
	"0x0000000000000000000000000000000000000008": "ecPairing",
	"0x0000000000000000000000000000000000000009": "blake2f",
}

// IsPrecompileAddress returns true if the given address is a precompiled contract.
// It handles both full 40-character hex addresses and short forms (e.g., "0x1").
func IsPrecompileAddress(addr string) bool {
	normalizedAddr := normalizeAddress(addr)
	_, exists := PrecompileAddresses[normalizedAddr]
	return exists
}

// GetPrecompileName returns the name of the precompile at the given address,
// or an empty string if the address is not a precompiled contract.
func GetPrecompileName(addr string) string {
	normalizedAddr := normalizeAddress(addr)
	return PrecompileAddresses[normalizedAddr]
}

// normalizeAddress converts an address to lowercase with full 40-character hex + 0x prefix.
// This ensures consistent lookup regardless of input format.
func normalizeAddress(addr string) string {
	addr = strings.ToLower(strings.TrimPrefix(addr, "0x"))
	// Pad to 40 characters (20 bytes)
	for len(addr) < 40 {
		addr = "0" + addr
	}
	return "0x" + addr
}
