package auth

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"privacy-proxy/internal/walletproof"
)

// GenerateNonce creates a cryptographically secure random nonce for signing
func GenerateNonce() (string, error) {
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("failed to generate nonce: %w", err)
	}
	return hex.EncodeToString(nonce), nil
}

// GenerateLinkMessage creates the message to be signed for linking an ETH address to a DID
// Format follows EIP-191 personal_sign conventions with clear human-readable text
func GenerateLinkMessage(did, nonce string) string {
	return fmt.Sprintf(`Link Ethereum address to DID

I authorize linking this Ethereum address to my decentralized identity.

DID: %s
Nonce: %s

This signature proves ownership of this Ethereum address.`, did, nonce)
}

// HashMessage creates a hash of the message using Ethereum's personal_sign prefix
// This implements EIP-191: "\x19Ethereum Signed Message:\n" + len(message) + message
func HashMessage(message string) []byte {
	return walletproof.HashMessage(message)
}

// VerifySignature recovers the Ethereum address from a signed message
// Returns the recovered address or an error if verification fails
func VerifySignature(message string, signatureHex string) (common.Address, error) {
	return walletproof.RecoverLegacy(message, signatureHex)
}

// VerifyAddressOwnership verifies that the signature was created by the claimed address
// Returns nil if verification succeeds, error otherwise
func VerifyAddressOwnership(claimedAddress, message, signatureHex string) error {
	// Parse the claimed address
	if !common.IsHexAddress(claimedAddress) {
		return fmt.Errorf("invalid Ethereum address format")
	}
	claimed := common.HexToAddress(claimedAddress)

	// Recover the address from the signature
	recovered, err := VerifySignature(message, signatureHex)
	if err != nil {
		return fmt.Errorf("signature verification failed: %w", err)
	}

	// Compare addresses (case-insensitive)
	if !strings.EqualFold(claimed.Hex(), recovered.Hex()) {
		return fmt.Errorf("address mismatch: claimed %s, recovered %s", claimed.Hex(), recovered.Hex())
	}

	return nil
}

// NormalizeAddress converts an Ethereum address to lowercase checksum format.
// Returns lowercase address even if invalid (caller should validate first).
func NormalizeAddress(address string) string {
	if !common.IsHexAddress(address) {
		return strings.ToLower(address)
	}
	return strings.ToLower(common.HexToAddress(address).Hex())
}

// IsValidAddress checks if a string is a valid Ethereum address.
// A valid address is a 40 hex character string with 0x prefix (42 total chars).
func IsValidAddress(address string) bool {
	return common.IsHexAddress(address)
}

// MessageHashHex returns the hex-encoded hash of the signed message
func MessageHashHex(message string) string {
	hash := HashMessage(message)
	return hexutil.Encode(hash)
}
