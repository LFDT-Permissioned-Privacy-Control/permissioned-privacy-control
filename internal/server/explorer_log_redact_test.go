package server

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEthAddressPattern(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "lowercase address in path",
			input:    "/api/v1/explorer/addresses/0x1234567890abcdef1234567890abcdef12345678/transactions",
			expected: "/api/v1/explorer/addresses/0x[REDACTED]/transactions",
		},
		{
			name:     "checksummed address in path",
			input:    "/api/v1/explorer/addresses/0xABCDEF1234567890ABCDEF1234567890ABCDEF12/stats",
			expected: "/api/v1/explorer/addresses/0x[REDACTED]/stats",
		},
		{
			name:     "multiple addresses in path and query",
			input:    "/api/v1/explorer/addresses/0x1111111111111111111111111111111111111111/transactions?wallet=0x2222222222222222222222222222222222222222",
			expected: "/api/v1/explorer/addresses/0x[REDACTED]/transactions?wallet=0x[REDACTED]",
		},
		{
			name:     "no address in path",
			input:    "/api/v1/explorer/blocks/123/transactions",
			expected: "/api/v1/explorer/blocks/123/transactions",
		},
		{
			name:     "short hex not matched",
			input:    "/api/v1/explorer/blocks/hash/0xabcdef1234",
			expected: "/api/v1/explorer/blocks/hash/0xabcdef1234",
		},
		{
			name:     "token address",
			input:    "/api/v1/explorer/tokens/0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef/holders",
			expected: "/api/v1/explorer/tokens/0x[REDACTED]/holders",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ethAddressPattern.ReplaceAllString(tt.input, "0x[REDACTED]")
			assert.Equal(t, tt.expected, result)
		})
	}
}
