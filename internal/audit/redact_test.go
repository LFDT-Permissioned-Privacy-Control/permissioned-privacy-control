package audit

import (
	"encoding/json"
	"testing"
)

func TestRedactParams_SendRawTransaction(t *testing.T) {
	longHex := "0xf86c0a8502540be400825208944bbeeb066ed09b7ae" +
		"d07bf39eee0460dfa26152088016345785d8a0000"
	params := []any{longHex}

	result := RedactParams("eth_sendRawTransaction", params)

	var out []any
	if err := json.Unmarshal(result, &out); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("expected 1 param, got %d", len(out))
	}

	truncated, ok := out[0].(string)
	if !ok {
		t.Fatal("expected string param")
	}

	// 20 chars + "..."
	if len(truncated) != 23 {
		t.Fatalf("expected length 23, got %d: %q", len(truncated), truncated)
	}
	if truncated != longHex[:20]+"..." {
		t.Fatalf("unexpected truncation: %q", truncated)
	}
}

func TestRedactParams_SendTransaction(t *testing.T) {
	params := []any{
		map[string]any{
			"from":  "0xabc",
			"to":    "0xdef",
			"value": "0x1",
			"gas":   "0x5208",
			"data":  "0x606060405260003411156100145760006000fd5b",
		},
	}

	result := RedactParams("eth_sendTransaction", params)

	var out []any
	if err := json.Unmarshal(result, &out); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	obj, ok := out[0].(map[string]any)
	if !ok {
		t.Fatal("expected object param")
	}

	// Safe fields preserved.
	for _, key := range []string{"from", "to", "value", "gas"} {
		if _, exists := obj[key]; !exists {
			t.Errorf("expected %q to be preserved", key)
		}
	}

	// Data truncated.
	data, ok := obj["data"].(string)
	if !ok {
		t.Fatal("expected data field")
	}
	if len(data) != 13 { // 10 + "..."
		t.Fatalf("expected truncated data length 13, got %d: %q", len(data), data)
	}
}

func TestRedactParams_EthCall(t *testing.T) {
	params := []any{
		map[string]any{
			"from":  "0xabc",
			"to":    "0xdef",
			"value": "0x0",
			"data":  "0x70a0823100000000000000000000000000000000000abc",
		},
		"latest",
	}

	result := RedactParams("eth_call", params)

	var out []any
	if err := json.Unmarshal(result, &out); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if len(out) != 2 {
		t.Fatalf("expected 2 params (object + block), got %d", len(out))
	}

	obj, ok := out[0].(map[string]any)
	if !ok {
		t.Fatal("expected object param")
	}

	// Safe fields preserved.
	for _, key := range []string{"from", "to", "value"} {
		if _, exists := obj[key]; !exists {
			t.Errorf("expected %q to be preserved", key)
		}
	}

	// Data truncated.
	data, ok := obj["data"].(string)
	if !ok {
		t.Fatal("expected data field")
	}
	if len(data) != 13 { // 10 + "..."
		t.Fatalf("expected truncated data length 13, got %d: %q", len(data), data)
	}

	// Block param preserved.
	if out[1] != "latest" {
		t.Fatalf("expected block param 'latest', got %v", out[1])
	}
}

func TestRedactParams_EstimateGas(t *testing.T) {
	params := []any{
		map[string]any{
			"from":  "0xabc",
			"to":    "0xdef",
			"data":  "0x70a0823100000000000000000000000000000000000abc",
			"input": "0x70a0823100000000000000000000000000000000000abc",
		},
	}

	result := RedactParams("eth_estimateGas", params)

	var out []any
	if err := json.Unmarshal(result, &out); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	obj, ok := out[0].(map[string]any)
	if !ok {
		t.Fatal("expected object param")
	}

	// Both data and input should be truncated.
	for _, key := range []string{"data", "input"} {
		val, ok := obj[key].(string)
		if !ok {
			t.Fatalf("expected %q field", key)
		}
		if len(val) != 13 {
			t.Fatalf("expected %q truncated to 13 chars, got %d: %q", key, len(val), val)
		}
	}
}

func TestRedactParams_UnknownMethod(t *testing.T) {
	params := []any{"arg1", 42, true}

	result := RedactParams("eth_blockNumber", params)

	var out []any
	if err := json.Unmarshal(result, &out); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if len(out) != 3 {
		t.Fatalf("expected 3 params, got %d", len(out))
	}
	if out[0] != "arg1" {
		t.Errorf("expected 'arg1', got %v", out[0])
	}
}

func TestRedactParams_EmptyParams(t *testing.T) {
	result := RedactParams("eth_blockNumber", nil)
	if result != nil {
		t.Fatalf("expected nil for empty params, got %s", result)
	}

	result = RedactParams("eth_blockNumber", []any{})
	if result != nil {
		t.Fatalf("expected nil for empty slice, got %s", result)
	}
}
