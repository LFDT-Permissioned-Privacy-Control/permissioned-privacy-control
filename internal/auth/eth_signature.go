package auth

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
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
	return accounts.TextHash([]byte(message))
}

// VerifySignature recovers the Ethereum address from a signed message
// Returns the recovered address or an error if verification fails
func VerifySignature(message string, signatureHex string) (common.Address, error) {
	// Remove 0x prefix if present
	sig := strings.TrimPrefix(signatureHex, "0x")

	// Decode signature
	sigBytes, err := hex.DecodeString(sig)
	if err != nil {
		return common.Address{}, fmt.Errorf("invalid signature encoding: %w", err)
	}

	// Signature must be 65 bytes (32 R + 32 S + 1 V)
	if len(sigBytes) != 65 {
		return common.Address{}, fmt.Errorf("invalid signature length: expected 65 bytes, got %d", len(sigBytes))
	}

	// EIP-155: If V is 27 or 28, subtract 27 to get 0 or 1
	// MetaMask and most wallets use 27/28, while go-ethereum expects 0/1
	if sigBytes[64] >= 27 {
		sigBytes[64] -= 27
	}

	// Hash the message with Ethereum prefix (EIP-191)
	messageHash := HashMessage(message)

	// Recover the public key from the signature
	pubKey, err := crypto.SigToPub(messageHash, sigBytes)
	if err != nil {
		return common.Address{}, fmt.Errorf("failed to recover public key: %w", err)
	}

	// Derive the address from the public key
	recoveredAddr := crypto.PubkeyToAddress(*pubKey)
	return recoveredAddr, nil
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
