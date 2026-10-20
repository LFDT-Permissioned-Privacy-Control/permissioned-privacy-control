package rbac

import (
	"testing"
)

func TestExpandClaims(t *testing.T) {
	tests := []struct {
		name     string
		input    []Claim
		expected []Claim
	}{
		{
			name:     "admin expands to deploy and upgrade",
			input:    []Claim{ClaimAdmin},
			expected: []Claim{ClaimAdmin, ClaimDeploy, ClaimUpgrade},
		},
		{
			name:     "deploy does not expand",
			input:    []Claim{ClaimDeploy},
			expected: []Claim{ClaimDeploy},
		},
		{
			name:     "upgrade does not expand",
			input:    []Claim{ClaimUpgrade},
			expected: []Claim{ClaimUpgrade},
		},
		{
			name:     "deploy and upgrade stay as-is",
			input:    []Claim{ClaimDeploy, ClaimUpgrade},
			expected: []Claim{ClaimDeploy, ClaimUpgrade},
		},
		{
			name:     "empty input returns empty",
			input:    []Claim{},
			expected: []Claim{},
		},
		{
			name:     "already expanded input is idempotent",
			input:    []Claim{ClaimAdmin, ClaimDeploy, ClaimUpgrade},
			expected: []Claim{ClaimAdmin, ClaimDeploy, ClaimUpgrade},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ExpandClaims(tt.input)
			if len(result) != len(tt.expected) {
				t.Fatalf("expected %v, got %v", tt.expected, result)
			}
			for i, claim := range result {
				if claim != tt.expected[i] {
					t.Fatalf("expected %v at index %d, got %v (full result: %v)", tt.expected[i], i, claim, result)
				}
			}
		})
	}
}

