package precompile

import "testing"

func TestIsPrecompileAddress(t *testing.T) {
	tests := []struct {
		name     string
		addr     string
		expected bool
	}{
		{"ecrecover full", "0x0000000000000000000000000000000000000001", true},
		{"ecrecover short", "0x1", true},
		{"sha256", "0x0000000000000000000000000000000000000002", true},
		{"ripemd160", "0x0000000000000000000000000000000000000003", true},
		{"identity", "0x0000000000000000000000000000000000000004", true},
		{"modexp", "0x0000000000000000000000000000000000000005", true},
		{"ecAdd", "0x0000000000000000000000000000000000000006", true},
		{"ecMul", "0x0000000000000000000000000000000000000007", true},
		{"ecPairing", "0x0000000000000000000000000000000000000008", true},
		{"blake2f", "0x0000000000000000000000000000000000000009", true},
		{"blake2f short", "0x9", true},
		{"not precompile 0x0a", "0x000000000000000000000000000000000000000a", false},
		{"not precompile 0x10", "0x0000000000000000000000000000000000000010", false},
		{"regular address", "0x1234567890123456789012345678901234567890", false},
		{"zero address", "0x0000000000000000000000000000000000000000", false},
		{"uppercase address", "0x0000000000000000000000000000000000000001", true},
		{"mixed case", "0x0000000000000000000000000000000000000001", true},
		{"no prefix short", "1", true},
		{"no prefix full", "0000000000000000000000000000000000000001", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsPrecompileAddress(tt.addr); got != tt.expected {
				t.Errorf("IsPrecompileAddress(%s) = %v, want %v", tt.addr, got, tt.expected)
			}
		})
	}
}

func TestGetPrecompileName(t *testing.T) {
	tests := []struct {
		name     string
		addr     string
		expected string
	}{
		{"ecrecover short", "0x1", "ecrecover"},
		{"ecrecover full", "0x0000000000000000000000000000000000000001", "ecrecover"},
		{"sha256", "0x0000000000000000000000000000000000000002", "sha256"},
		{"ripemd160", "0x3", "ripemd160"},
		{"identity", "0x4", "identity"},
		{"modexp", "0x5", "modexp"},
		{"ecAdd", "0x6", "ecAdd"},
		{"ecMul", "0x7", "ecMul"},
		{"ecPairing", "0x8", "ecPairing"},
		{"blake2f", "0x9", "blake2f"},
		{"regular address", "0x1234567890123456789012345678901234567890", ""},
		{"zero address", "0x0000000000000000000000000000000000000000", ""},
		{"not precompile", "0x0a", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := GetPrecompileName(tt.addr); got != tt.expected {
				t.Errorf("GetPrecompileName(%s) = %v, want %v", tt.addr, got, tt.expected)
			}
		})
	}
}

func TestNormalizeAddress(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"short address", "0x1", "0x0000000000000000000000000000000000000001"},
		{"full address", "0x0000000000000000000000000000000000000001", "0x0000000000000000000000000000000000000001"},
		{"no prefix", "1", "0x0000000000000000000000000000000000000001"},
		{"uppercase", "0xABCD", "0x000000000000000000000000000000000000abcd"},
		{"mixed case", "0xAbCd", "0x000000000000000000000000000000000000abcd"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := normalizeAddress(tt.input); got != tt.expected {
				t.Errorf("normalizeAddress(%s) = %v, want %v", tt.input, got, tt.expected)
			}
		})
	}
}
