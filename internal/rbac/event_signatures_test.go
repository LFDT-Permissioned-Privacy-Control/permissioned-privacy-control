package rbac

import (
	"testing"
)

func TestExtractEventSignatures(t *testing.T) {
	// Standard ERC20 ABI with Transfer and Approval events.
	erc20ABI := `[
		{
			"anonymous": false,
			"inputs": [
				{"indexed": true, "name": "from", "type": "address"},
				{"indexed": true, "name": "to", "type": "address"},
				{"indexed": false, "name": "value", "type": "uint256"}
			],
			"name": "Transfer",
			"type": "event"
		},
		{
			"anonymous": false,
			"inputs": [
				{"indexed": true, "name": "owner", "type": "address"},
				{"indexed": true, "name": "spender", "type": "address"},
				{"indexed": false, "name": "value", "type": "uint256"}
			],
			"name": "Approval",
			"type": "event"
		},
		{
			"inputs": [{"name": "to", "type": "address"}, {"name": "amount", "type": "uint256"}],
			"name": "transfer",
			"outputs": [{"name": "", "type": "bool"}],
			"type": "function"
		}
	]`

	sigs, err := ExtractEventSignatures(erc20ABI)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(sigs) != 2 {
		t.Fatalf("expected 2 event signatures, got %d", len(sigs))
	}

	// Find Transfer
	var transferSig *EventSignature
	for i := range sigs {
		if sigs[i].Name == "Transfer" {
			transferSig = &sigs[i]
			break
		}
	}
	if transferSig == nil {
		t.Fatal("Transfer event not found")
	}

	// Check topic0 for Transfer(address,address,uint256)
	// keccak256("Transfer(address,address,uint256)") = 0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef
	expectedTopic0 := "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
	if transferSig.Topic0 != expectedTopic0 {
		t.Errorf("expected topic0 %s, got %s", expectedTopic0, transferSig.Topic0)
	}

	if len(transferSig.Inputs) != 3 {
		t.Fatalf("expected 3 inputs, got %d", len(transferSig.Inputs))
	}
	if !transferSig.Inputs[0].Indexed {
		t.Error("expected from to be indexed")
	}
	if transferSig.Inputs[2].Indexed {
		t.Error("expected value to not be indexed")
	}

	// Verify DefaultParamRules: Transfer has 2 address inputs (from, to).
	if len(transferSig.DefaultParamRules) != 2 {
		t.Fatalf("expected 2 default_param_rules for Transfer, got %d", len(transferSig.DefaultParamRules))
	}
	if transferSig.DefaultParamRules[0].Index != 0 || transferSig.DefaultParamRules[0].MustBe != "self" {
		t.Errorf("default_param_rules[0] = %+v, want {Index:0, MustBe:self}", transferSig.DefaultParamRules[0])
	}
	if transferSig.DefaultParamRules[1].Index != 1 || transferSig.DefaultParamRules[1].MustBe != "self" {
		t.Errorf("default_param_rules[1] = %+v, want {Index:1, MustBe:self}", transferSig.DefaultParamRules[1])
	}
}

func TestExtractEventSignatures_EmptyABI(t *testing.T) {
	_, err := ExtractEventSignatures("")
	if err == nil {
		t.Error("expected error for empty ABI")
	}
}

func TestExtractEventSignatures_NoEvents(t *testing.T) {
	abi := `[{"inputs":[],"name":"foo","outputs":[],"type":"function"}]`
	sigs, err := ExtractEventSignatures(abi)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(sigs) != 0 {
		t.Errorf("expected 0 events, got %d", len(sigs))
	}
}

func TestExtractEventSignatures_EmptyArray(t *testing.T) {
	// U10: Empty JSON array ABI should return empty slice, nil error.
	sigs, err := ExtractEventSignatures("[]")
	if err != nil {
		t.Fatalf("unexpected error for empty array ABI: %v", err)
	}
	if len(sigs) != 0 {
		t.Errorf("expected 0 events for empty array ABI, got %d", len(sigs))
	}
}

func TestExtractEventSignatures_MalformedABI(t *testing.T) {
	// U12: Malformed ABI should return an error.
	_, err := ExtractEventSignatures("not json")
	if err == nil {
		t.Error("expected error for malformed ABI, got nil")
	}
}

func TestExtractEventSignatures_OverloadedEvents(t *testing.T) {
	// U14: Overloaded event names (same name, different param types) produce
	// different topic0 values because the canonical signature differs.
	abiJSON := `[
		{
			"anonymous": false,
			"inputs": [
				{"indexed": true, "name": "from", "type": "address"},
				{"indexed": false, "name": "value", "type": "uint256"}
			],
			"name": "Transfer",
			"type": "event"
		},
		{
			"anonymous": false,
			"inputs": [
				{"indexed": true, "name": "from", "type": "address"},
				{"indexed": true, "name": "to", "type": "address"},
				{"indexed": false, "name": "value", "type": "uint256"}
			],
			"name": "Transfer",
			"type": "event"
		}
	]`

	sigs, err := ExtractEventSignatures(abiJSON)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(sigs) != 2 {
		t.Fatalf("expected 2 event signatures for overloaded events, got %d", len(sigs))
	}

	// The two signatures must differ because the canonical forms are different:
	// Transfer(address,uint256) vs Transfer(address,address,uint256)
	if sigs[0].Topic0 == sigs[1].Topic0 {
		t.Errorf("overloaded events should have different topic0 values, both are %s", sigs[0].Topic0)
	}

	// Verify they are valid topic0 hashes.
	for i, sig := range sigs {
		if !IsValidTopic0(sig.Topic0) {
			t.Errorf("sigs[%d].Topic0 %q is not a valid topic0", i, sig.Topic0)
		}
	}
}

func TestExtractEventSignatures_ExactKeccak256(t *testing.T) {
	// U15: Verify exact topic0 computation against known keccak256 values.
	abiJSON := `[
		{
			"anonymous": false,
			"inputs": [
				{"indexed": true, "name": "owner", "type": "address"},
				{"indexed": true, "name": "spender", "type": "address"},
				{"indexed": false, "name": "value", "type": "uint256"}
			],
			"name": "Approval",
			"type": "event"
		}
	]`

	sigs, err := ExtractEventSignatures(abiJSON)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(sigs) != 1 {
		t.Fatalf("expected 1 event, got %d", len(sigs))
	}

	// keccak256("Approval(address,address,uint256)")
	expectedApprovalTopic0 := "0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925"
	if sigs[0].Topic0 != expectedApprovalTopic0 {
		t.Errorf("Approval topic0 = %s, want %s", sigs[0].Topic0, expectedApprovalTopic0)
	}
}

func TestIsValidTopic0(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{"valid", "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef", true},
		{"all zeros", "0x0000000000000000000000000000000000000000000000000000000000000000", true},
		{"too short", "0xddf252", false},
		{"no prefix", "ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef", false},
		{"invalid hex", "0xZZf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef", false},
		{"empty", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsValidTopic0(tt.input)
			if got != tt.want {
				t.Errorf("IsValidTopic0(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}
