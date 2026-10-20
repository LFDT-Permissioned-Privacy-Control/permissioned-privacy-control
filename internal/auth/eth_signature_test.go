package auth

import (
	"crypto/ecdsa"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

func TestGenerateNonce(t *testing.T) {
	tests := []struct {
		name string
	}{
		{"should generate nonce"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nonce1, err := GenerateNonce()
			if err != nil {
				t.Fatalf("GenerateNonce() error = %v", err)
			}

			// Verify nonce is hex string
			if _, err := hex.DecodeString(nonce1); err != nil {
				t.Errorf("GenerateNonce() returned non-hex string: %s", nonce1)
			}

			// Verify nonce length (16 bytes = 32 hex chars)
			if len(nonce1) != 32 {
				t.Errorf("GenerateNonce() length = %d, want 32", len(nonce1))
			}

			// Generate another nonce and verify uniqueness
			nonce2, err := GenerateNonce()
			if err != nil {
				t.Fatalf("GenerateNonce() second call error = %v", err)
			}

			if nonce1 == nonce2 {
				t.Error("GenerateNonce() generated duplicate nonces")
			}
		})
	}
}

func TestGenerateLinkMessage(t *testing.T) {
	tests := []struct {
		name     string
		did      string
		nonce    string
		wantSubs []string
	}{
		{
			name:  "valid DID and nonce",
			did:   "did:polygonid:polygon:main:user123",
			nonce: "abc123",
			wantSubs: []string{
				"Link Ethereum address to DID",
				"I authorize linking this Ethereum address",
				"DID: did:polygonid:polygon:main:user123",
				"Nonce: abc123",
				"This signature proves ownership",
			},
		},
		{
			name:  "different DID format",
			did:   "did:ethr:0x1234",
			nonce: "xyz789",
			wantSubs: []string{
				"DID: did:ethr:0x1234",
				"Nonce: xyz789",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			message := GenerateLinkMessage(tt.did, tt.nonce)

			for _, sub := range tt.wantSubs {
				if !strings.Contains(message, sub) {
					t.Errorf("GenerateLinkMessage() missing substring %q in message:\n%s", sub, message)
				}
			}
		})
	}
}

func TestHashMessage(t *testing.T) {
	tests := []struct {
		name    string
		message string
	}{
		{
			name:    "simple message",
			message: "Hello World",
		},
		{
			name:    "link message",
			message: GenerateLinkMessage("did:test:123", "nonce123"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash := HashMessage(tt.message)

			// Verify hash length (32 bytes for Keccak256)
			if len(hash) != 32 {
				t.Errorf("HashMessage() length = %d, want 32", len(hash))
			}

			// Verify same input produces same hash
			hash2 := HashMessage(tt.message)
			if !bytesEqual(hash, hash2) {
				t.Error("HashMessage() not deterministic")
			}

			// Verify different input produces different hash
			hash3 := HashMessage(tt.message + "x")
			if bytesEqual(hash, hash3) {
				t.Error("HashMessage() same hash for different inputs")
			}
		})
	}
}

func TestVerifySignature(t *testing.T) {
	// Generate test keypair
	privateKey, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	address := crypto.PubkeyToAddress(privateKey.PublicKey)
	message := GenerateLinkMessage("did:test:user", "testnonce123")

	// Create valid signature
	signature := signMessage(t, privateKey, message)

	tests := []struct {
		name        string
		message     string
		signature   string
		wantAddress common.Address
		wantErr     bool
	}{
		{
			name:        "valid signature",
			message:     message,
			signature:   signature,
			wantAddress: address,
			wantErr:     false,
		},
		{
			name:        "valid signature with 0x prefix",
			message:     message,
			signature:   "0x" + signature,
			wantAddress: address,
			wantErr:     false,
		},
		{
			name:      "invalid signature encoding",
			message:   message,
			signature: "not-hex",
			wantErr:   true,
		},
		{
			name:      "signature too short",
			message:   message,
			signature: "abcd1234",
			wantErr:   true,
		},
		{
			name:      "empty signature",
			message:   message,
			signature: "",
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			recovered, err := VerifySignature(tt.message, tt.signature)

			if (err != nil) != tt.wantErr {
				t.Errorf("VerifySignature() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				if recovered != tt.wantAddress {
					t.Errorf("VerifySignature() = %v, want %v", recovered.Hex(), tt.wantAddress.Hex())
				}
			}
		})
	}
}

func TestVerifySignatureWithV27V28(t *testing.T) {
	// Generate test keypair
	privateKey, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	address := crypto.PubkeyToAddress(privateKey.PublicKey)
	message := "Test message for V normalization"

	// Create signature with V=0 or V=1
	hash := HashMessage(message)
	sigBytes, err := crypto.Sign(hash, privateKey)
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}

	// Test with V=27 (Ethereum standard)
	sigV27 := make([]byte, 65)
	copy(sigV27, sigBytes)
	sigV27[64] = sigBytes[64] + 27

	recovered, err := VerifySignature(message, hex.EncodeToString(sigV27))
	if err != nil {
		t.Fatalf("VerifySignature() with V=27 error = %v", err)
	}
	if recovered != address {
		t.Errorf("VerifySignature() with V=27 = %v, want %v", recovered.Hex(), address.Hex())
	}

	// Test with V=28
	sigV28 := make([]byte, 65)
	copy(sigV28, sigBytes)
	sigV28[64] = 1 + 27 // V=28

	// This may or may not match depending on the signature's actual recovery ID
	_, err = VerifySignature(message, hex.EncodeToString(sigV28))
	// We don't check the error here as V=28 might be invalid for this signature
}

func TestVerifyAddressOwnership(t *testing.T) {
	// Generate test keypair
	privateKey, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	address := crypto.PubkeyToAddress(privateKey.PublicKey)
	message := GenerateLinkMessage("did:test:user", "testnonce123")
	signature := signMessage(t, privateKey, message)

	tests := []struct {
		name           string
		claimedAddress string
		message        string
		signature      string
		wantErr        bool
	}{
		{
			name:           "valid ownership proof",
			claimedAddress: address.Hex(),
			message:        message,
			signature:      signature,
			wantErr:        false,
		},
		{
			name:           "lowercase address",
			claimedAddress: strings.ToLower(address.Hex()),
			message:        message,
			signature:      signature,
			wantErr:        false,
		},
		{
			name:           "uppercase address",
			claimedAddress: strings.ToUpper(address.Hex()),
			message:        message,
			signature:      signature,
			wantErr:        false,
		},
		{
			name:           "wrong address",
			claimedAddress: "0x1234567890123456789012345678901234567890",
			message:        message,
			signature:      signature,
			wantErr:        true,
		},
		{
			name:           "invalid address format",
			claimedAddress: "not-an-address",
			message:        message,
			signature:      signature,
			wantErr:        true,
		},
		{
			name:           "invalid signature",
			claimedAddress: address.Hex(),
			message:        message,
			signature:      "invalid",
			wantErr:        true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := VerifyAddressOwnership(tt.claimedAddress, tt.message, tt.signature)

			if (err != nil) != tt.wantErr {
				t.Errorf("VerifyAddressOwnership() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestNormalizeAddress(t *testing.T) {
	tests := []struct {
		name     string
		address  string
		expected string
	}{
		{
			name:     "checksummed address",
			address:  "0xABCDef1234567890abcdef1234567890ABCDef12",
			expected: "0xabcdef1234567890abcdef1234567890abcdef12",
		},
		{
			name:     "lowercase address",
			address:  "0xabcdef1234567890abcdef1234567890abcdef12",
			expected: "0xabcdef1234567890abcdef1234567890abcdef12",
		},
		{
			name:     "uppercase address",
			address:  "0XABCDEF1234567890ABCDEF1234567890ABCDEF12",
			expected: "0xabcdef1234567890abcdef1234567890abcdef12",
		},
		{
			name:     "without 0x prefix",
			address:  "abcdef1234567890abcdef1234567890abcdef12",
			expected: "0xabcdef1234567890abcdef1234567890abcdef12",
		},
		{
			name:     "invalid address returns lowercase",
			address:  "not-valid",
			expected: "not-valid",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := NormalizeAddress(tt.address)
			if result != tt.expected {
				t.Errorf("NormalizeAddress(%q) = %q, want %q", tt.address, result, tt.expected)
			}
		})
	}
}

func TestMessageHashHex(t *testing.T) {
	message := "Test message"
	hashHex := MessageHashHex(message)

	// Verify it starts with 0x
	if !strings.HasPrefix(hashHex, "0x") {
		t.Errorf("MessageHashHex() doesn't start with 0x: %s", hashHex)
	}

	// Verify length (0x + 64 hex chars = 66)
	if len(hashHex) != 66 {
		t.Errorf("MessageHashHex() length = %d, want 66", len(hashHex))
	}

	// Verify deterministic
	hashHex2 := MessageHashHex(message)
	if hashHex != hashHex2 {
		t.Error("MessageHashHex() not deterministic")
	}
}

// Helper functions

func signMessage(t *testing.T, privateKey *ecdsa.PrivateKey, message string) string {
	t.Helper()

	hash := HashMessage(message)
	sig, err := crypto.Sign(hash, privateKey)
	if err != nil {
		t.Fatalf("Failed to sign message: %v", err)
	}

	// Convert V to Ethereum format (27/28)
	if sig[64] < 27 {
		sig[64] += 27
	}

	return hex.EncodeToString(sig)
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
