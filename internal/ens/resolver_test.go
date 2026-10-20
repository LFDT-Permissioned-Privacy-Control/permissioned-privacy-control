package ens

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
)

// Test vectors from ENS documentation
// https://docs.ens.domains/resolution/names#namehash
func TestNamehash(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "empty name",
			input:    "",
			expected: "0000000000000000000000000000000000000000000000000000000000000000",
		},
		{
			name:     "eth",
			input:    "eth",
			expected: "93cdeb708b7545dc668eb9280176169d1c33cfd8ed6f04690a0bcc88a93fc4ae",
		},
		{
			name:     "foo.eth",
			input:    "foo.eth",
			expected: "de9b09fd7c5f901e23a3f19fecc54828e9c848539801e86591bd9801b019f84f",
		},
		{
			name:     "alice.eth",
			input:    "alice.eth",
			expected: "787192fc5378cc32aa956ddfdedbf26b24e8d78e40109add0eea2c1a012c3dec",
		},
		{
			name:     "addr.reverse",
			input:    "addr.reverse",
			expected: "91d1777781884d03a6757a803996e38de2a42967fb37eeaca72729271025a9e2",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := namehash(tc.input)
			resultHex := hex.EncodeToString(result[:])
			assert.Equal(t, tc.expected, resultHex, "namehash(%q)", tc.input)
		})
	}
}

func TestKeccak256(t *testing.T) {
	// Test vector: keccak256("eth") should be a known value
	result := keccak256([]byte("eth"))
	resultHex := hex.EncodeToString(result[:])

	// keccak256("eth") = 0x4f5b812789fc606be1b3b16908db13fc7a9adf7ca72641f84d75b47069d3d7f0
	expected := "4f5b812789fc606be1b3b16908db13fc7a9adf7ca72641f84d75b47069d3d7f0"
	assert.Equal(t, expected, resultHex)
}

// TestNamehashReverseNode tests the reverse node construction used in reverse resolution
func TestNamehashReverseNode(t *testing.T) {
	// For address 0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045 (vitalik.eth)
	// The reverse name would be: d8da6bf26964af9d7eed9e03e53415d37aa96045.addr.reverse
	reverseName := "d8da6bf26964af9d7eed9e03e53415d37aa96045.addr.reverse"
	result := namehash(reverseName)

	// The result should be a valid 32-byte hash
	assert.Len(t, result, 32)

	// Ensure it's not all zeros (empty name case)
	allZeros := [32]byte{}
	assert.NotEqual(t, allZeros, result)
}

// TestNamehashDeterministic verifies that namehash always produces the same result
func TestNamehashDeterministic(t *testing.T) {
	input := "test.eth"
	result1 := namehash(input)
	result2 := namehash(input)

	assert.Equal(t, result1, result2, "namehash should be deterministic")
}

// TestNamehashCaseSensitivity tests that namehash is case-sensitive
// (ENS names are normalized to lowercase before hashing)
func TestNamehashCaseSensitivity(t *testing.T) {
	lowercase := namehash("test.eth")
	uppercase := namehash("TEST.ETH")
	mixedcase := namehash("Test.Eth")

	// All should be different because namehash doesn't normalize
	// (normalization should happen before calling namehash)
	assert.NotEqual(t, lowercase, uppercase)
	assert.NotEqual(t, lowercase, mixedcase)
	assert.NotEqual(t, uppercase, mixedcase)
}
