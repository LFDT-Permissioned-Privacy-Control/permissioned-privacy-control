package rbac

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetBuiltInABI_ERC20(t *testing.T) {
	abi := GetBuiltInABI("ERC20")
	require.NotEmpty(t, abi, "ERC20 ABI should not be empty")

	events, err := ExtractEventSignatures(abi)
	require.NoError(t, err, "ERC20 ABI should parse without error")

	// Should have Transfer and Approval events
	eventNames := make(map[string]string) // name -> topic0
	for _, ev := range events {
		eventNames[ev.Name] = ev.Topic0
	}

	assert.Contains(t, eventNames, "Transfer", "ERC20 ABI should contain Transfer event")
	assert.Contains(t, eventNames, "Approval", "ERC20 ABI should contain Approval event")

	// Verify known topic0 values
	assert.Equal(t,
		"0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef",
		eventNames["Transfer"],
		"Transfer topic0 mismatch",
	)
	assert.Equal(t,
		"0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925",
		eventNames["Approval"],
		"Approval topic0 mismatch",
	)

	// Verify Transfer event has correct inputs
	for _, ev := range events {
		if ev.Name == "Transfer" {
			require.Len(t, ev.Inputs, 3, "Transfer should have 3 inputs")
			assert.Equal(t, "address", ev.Inputs[0].Type)
			assert.Equal(t, "from", ev.Inputs[0].Name)
			assert.True(t, ev.Inputs[0].Indexed)
			assert.Equal(t, "address", ev.Inputs[1].Type)
			assert.Equal(t, "to", ev.Inputs[1].Name)
			assert.True(t, ev.Inputs[1].Indexed)
			assert.Equal(t, "uint256", ev.Inputs[2].Type)
			assert.Equal(t, "value", ev.Inputs[2].Name)
			assert.False(t, ev.Inputs[2].Indexed)
		}
	}
}

func TestGetBuiltInABI_ERC721(t *testing.T) {
	abi := GetBuiltInABI("ERC721")
	require.NotEmpty(t, abi, "ERC721 ABI should not be empty")

	events, err := ExtractEventSignatures(abi)
	require.NoError(t, err, "ERC721 ABI should parse without error")

	eventNames := make(map[string]bool)
	for _, ev := range events {
		eventNames[ev.Name] = true
	}

	assert.True(t, eventNames["Transfer"], "ERC721 ABI should contain Transfer event")
	assert.True(t, eventNames["Approval"], "ERC721 ABI should contain Approval event")
	assert.True(t, eventNames["ApprovalForAll"], "ERC721 ABI should contain ApprovalForAll event")
	assert.Len(t, events, 3, "ERC721 should have exactly 3 events")

	// Verify ERC721 Transfer has different param types than ERC20 Transfer
	// ERC721: Transfer(address,address,uint256) — but tokenId is indexed (all 3 indexed)
	for _, ev := range events {
		if ev.Name == "Transfer" {
			require.Len(t, ev.Inputs, 3)
			assert.True(t, ev.Inputs[2].Indexed, "ERC721 Transfer tokenId should be indexed")
		}
	}
}

func TestGetBuiltInABI_Unknown(t *testing.T) {
	assert.Empty(t, GetBuiltInABI("unknown"), "unknown type should return empty string")
	assert.Empty(t, GetBuiltInABI(""), "empty type should return empty string")
}

// Lookups are case-insensitive (and tolerate surrounding whitespace) so
// admins setting metadata.token_type = "erc20" or " ERC20 " resolve the
// same as the canonical "ERC20".
func TestGetBuiltInABI_CaseInsensitive(t *testing.T) {
	canonical := GetBuiltInABI("ERC20")
	if canonical == "" {
		t.Fatal("ERC20 should resolve to a non-empty ABI")
	}
	assert.Equal(t, canonical, GetBuiltInABI("erc20"))
	assert.Equal(t, canonical, GetBuiltInABI("Erc20"))
	assert.Equal(t, canonical, GetBuiltInABI(" ERC20 "))

	canonical721 := GetBuiltInABI("ERC721")
	if canonical721 == "" {
		t.Fatal("ERC721 should resolve to a non-empty ABI")
	}
	assert.Equal(t, canonical721, GetBuiltInABI("erc721"))
}
