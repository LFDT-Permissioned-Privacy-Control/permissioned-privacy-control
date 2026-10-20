package server

import (
	"encoding/json"
	"testing"
)

func TestExtractAndStripVisibleTo(t *testing.T) {
	tests := []struct {
		name         string
		method       string
		params       []any
		body         string
		wantDIDs     []string
		wantStripped bool // visibleTo should be absent from params and body after call
	}{
		{
			name:   "normal: params with visibleTo returns DIDs and strips field",
			method: "eth_sendTransaction",
			params: []any{map[string]any{
				"from":      "0xaaa",
				"to":        "0xbbb",
				"data":      "0x",
				"visibleTo": []any{"did:example:alice", "did:example:bob"},
			}},
			body:         `{"jsonrpc":"2.0","method":"eth_sendTransaction","params":[{"from":"0xaaa","to":"0xbbb","data":"0x","visibleTo":["did:example:alice","did:example:bob"]}],"id":1}`,
			wantDIDs:     []string{"did:example:alice", "did:example:bob"},
			wantStripped: true,
		},
		{
			name:   "no visibleTo field returns nil and body unchanged",
			method: "eth_sendTransaction",
			params: []any{map[string]any{
				"from": "0xaaa",
				"to":   "0xbbb",
				"data": "0x",
			}},
			body:         `{"jsonrpc":"2.0","method":"eth_sendTransaction","params":[{"from":"0xaaa","to":"0xbbb","data":"0x"}],"id":1}`,
			wantDIDs:     nil,
			wantStripped: false,
		},
		{
			name:   "empty visibleTo array returns nil",
			method: "eth_sendTransaction",
			params: []any{map[string]any{
				"from":      "0xaaa",
				"to":        "0xbbb",
				"visibleTo": []any{},
			}},
			body:         `{"jsonrpc":"2.0","method":"eth_sendTransaction","params":[{"from":"0xaaa","to":"0xbbb","visibleTo":[]}],"id":1}`,
			wantDIDs:     nil,
			wantStripped: true, // field is still removed even if empty
		},
		{
			name:   "non-string items in array are skipped",
			method: "eth_sendTransaction",
			params: []any{map[string]any{
				"from":      "0xaaa",
				"visibleTo": []any{"did:example:alice", 42, nil, "", "did:example:bob"},
			}},
			body:         `{"jsonrpc":"2.0","method":"eth_sendTransaction","params":[{"from":"0xaaa","visibleTo":["did:example:alice",42,null,"","did:example:bob"]}],"id":1}`,
			wantDIDs:     []string{"did:example:alice", "did:example:bob"},
			wantStripped: true,
		},
		{
			name:     "empty params returns nil",
			method:   "eth_sendTransaction",
			params:   []any{},
			body:     `{"jsonrpc":"2.0","method":"eth_sendTransaction","params":[],"id":1}`,
			wantDIDs: nil,
		},
		{
			name:     "params[0] is not a map returns nil",
			method:   "eth_sendTransaction",
			params:   []any{"not-a-map"},
			body:     `{"jsonrpc":"2.0","method":"eth_sendTransaction","params":["not-a-map"],"id":1}`,
			wantDIDs: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &ProcessRequest{
				Method: tt.method,
				Params: tt.params,
				Body:   []byte(tt.body),
			}

			originalBody := string(req.Body)
			got := extractAndStripVisibleTo(req)

			// Check returned DIDs.
			if tt.wantDIDs == nil {
				if got != nil {
					t.Errorf("expected nil DIDs, got %v", got)
				}
			} else {
				if len(got) != len(tt.wantDIDs) {
					t.Fatalf("expected %d DIDs, got %d: %v", len(tt.wantDIDs), len(got), got)
				}
				for i, want := range tt.wantDIDs {
					if got[i] != want {
						t.Errorf("DID[%d] = %q, want %q", i, got[i], want)
					}
				}
			}

			// Check that visibleTo is stripped from params and body.
			if tt.wantStripped {
				if txObj, ok := req.Params[0].(map[string]any); ok {
					if _, exists := txObj["visibleTo"]; exists {
						t.Error("visibleTo should have been removed from params[0]")
					}
				}
				bodyStr := string(req.Body)
				if containsSubstring(bodyStr, "visibleTo") {
					t.Errorf("visibleTo should have been removed from body, got: %s", bodyStr)
				}
			} else if tt.wantDIDs == nil {
				// Body should be unchanged when nothing was extracted.
				if string(req.Body) != originalBody {
					t.Errorf("body should be unchanged\n  got:  %s\n  want: %s", string(req.Body), originalBody)
				}
			}
		})
	}
}

func TestExtractAndStripRawTxVisibleTo(t *testing.T) {
	tests := []struct {
		name       string
		params     []any
		body       string
		wantDIDs   []string
		wantParams int // expected params length after call
	}{
		{
			name: "normal: second param has visibleTo returns DIDs and trims params",
			params: []any{
				"0xf86c...",
				map[string]any{
					"visibleTo": []any{"did:example:alice"},
				},
			},
			body:       `{"jsonrpc":"2.0","method":"eth_sendRawTransaction","params":["0xf86c...",{"visibleTo":["did:example:alice"]}],"id":1}`,
			wantDIDs:   []string{"did:example:alice"},
			wantParams: 1,
		},
		{
			name:       "no second param returns nil",
			params:     []any{"0xf86c..."},
			body:       `{"jsonrpc":"2.0","method":"eth_sendRawTransaction","params":["0xf86c..."],"id":1}`,
			wantDIDs:   nil,
			wantParams: 1,
		},
		{
			name: "second param has no visibleTo returns nil",
			params: []any{
				"0xf86c...",
				map[string]any{
					"otherField": "value",
				},
			},
			body:       `{"jsonrpc":"2.0","method":"eth_sendRawTransaction","params":["0xf86c...",{"otherField":"value"}],"id":1}`,
			wantDIDs:   nil,
			wantParams: 2,
		},
		{
			name:       "second param is not a map returns nil",
			params:     []any{"0xf86c...", "not-a-map"},
			body:       `{"jsonrpc":"2.0","method":"eth_sendRawTransaction","params":["0xf86c...","not-a-map"],"id":1}`,
			wantDIDs:   nil,
			wantParams: 2,
		},
		{
			name: "multiple DIDs with non-string items",
			params: []any{
				"0xf86c...",
				map[string]any{
					"visibleTo": []any{"did:example:alice", 123, "did:example:bob"},
				},
			},
			body:       `{"jsonrpc":"2.0","method":"eth_sendRawTransaction","params":["0xf86c...",{"visibleTo":["did:example:alice",123,"did:example:bob"]}],"id":1}`,
			wantDIDs:   []string{"did:example:alice", "did:example:bob"},
			wantParams: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &ProcessRequest{
				Method: "eth_sendRawTransaction",
				Params: tt.params,
				Body:   []byte(tt.body),
			}

			got := extractAndStripRawTxVisibleTo(req)

			// Check returned DIDs.
			if tt.wantDIDs == nil {
				if got != nil {
					t.Errorf("expected nil DIDs, got %v", got)
				}
			} else {
				if len(got) != len(tt.wantDIDs) {
					t.Fatalf("expected %d DIDs, got %d: %v", len(tt.wantDIDs), len(got), got)
				}
				for i, want := range tt.wantDIDs {
					if got[i] != want {
						t.Errorf("DID[%d] = %q, want %q", i, got[i], want)
					}
				}
			}

			// Check params length.
			if len(req.Params) != tt.wantParams {
				t.Errorf("expected %d params, got %d", tt.wantParams, len(req.Params))
			}

			// When params were trimmed, body should not contain the second param.
			if tt.wantDIDs != nil {
				bodyStr := string(req.Body)
				if containsSubstring(bodyStr, "visibleTo") {
					t.Errorf("visibleTo should have been removed from body, got: %s", bodyStr)
				}
			}
		})
	}
}

func TestRebuildRequestBody(t *testing.T) {
	tests := []struct {
		name     string
		original string
		params   []any
	}{
		{
			name:     "preserves JSON-RPC envelope with new params",
			original: `{"jsonrpc":"2.0","method":"eth_sendTransaction","params":[{"from":"0xaaa","visibleTo":["did:x"]}],"id":1}`,
			params: []any{map[string]any{
				"from": "0xaaa",
			}},
		},
		{
			name:     "preserves string id",
			original: `{"jsonrpc":"2.0","method":"eth_call","params":[],"id":"req-42"}`,
			params:   []any{"0xdeadbeef"},
		},
		{
			name:     "preserves null id",
			original: `{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":null}`,
			params:   []any{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := rebuildRequestBody([]byte(tt.original), tt.params)

			// Parse the result to verify the envelope is preserved.
			var env struct {
				JSONRPC string          `json:"jsonrpc"`
				Method  string          `json:"method"`
				Params  []any           `json:"params"`
				ID      json.RawMessage `json:"id"`
			}
			if err := json.Unmarshal(result, &env); err != nil {
				t.Fatalf("failed to parse rebuilt body: %v", err)
			}

			// Parse the original to get expected envelope fields.
			var orig struct {
				JSONRPC string          `json:"jsonrpc"`
				Method  string          `json:"method"`
				ID      json.RawMessage `json:"id"`
			}
			if err := json.Unmarshal([]byte(tt.original), &orig); err != nil {
				t.Fatalf("failed to parse original: %v", err)
			}

			if env.JSONRPC != orig.JSONRPC {
				t.Errorf("jsonrpc = %q, want %q", env.JSONRPC, orig.JSONRPC)
			}
			if env.Method != orig.Method {
				t.Errorf("method = %q, want %q", env.Method, orig.Method)
			}
			if string(env.ID) != string(orig.ID) {
				t.Errorf("id = %s, want %s", string(env.ID), string(orig.ID))
			}

			// Params should reflect the new params (length check).
			if len(env.Params) != len(tt.params) {
				t.Errorf("params length = %d, want %d", len(env.Params), len(tt.params))
			}
		})
	}

	t.Run("invalid JSON returns original", func(t *testing.T) {
		original := []byte(`not valid json`)
		result := rebuildRequestBody(original, []any{})
		if string(result) != string(original) {
			t.Errorf("expected original body back on invalid JSON")
		}
	})
}

func TestExtractTxHashFromResult(t *testing.T) {
	tests := []struct {
		name string
		body string
		want string
	}{
		{
			name: "valid response with hash",
			body: `{"jsonrpc":"2.0","id":1,"result":"0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"}`,
			want: "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
		},
		{
			name: "error response returns empty string",
			body: `{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"nonce too low"}}`,
			want: "",
		},
		{
			name: "empty result returns empty string",
			body: `{"jsonrpc":"2.0","id":1,"result":""}`,
			want: "",
		},
		{
			name: "null result returns empty string",
			body: `{"jsonrpc":"2.0","id":1,"result":null}`,
			want: "",
		},
		{
			name: "invalid JSON returns empty string",
			body: `not valid json`,
			want: "",
		},
		{
			name: "missing result field returns empty string",
			body: `{"jsonrpc":"2.0","id":1}`,
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractTxHashFromResult([]byte(tt.body))
			if got != tt.want {
				t.Errorf("extractTxHashFromResult() = %q, want %q", got, tt.want)
			}
		})
	}
}

// containsSubstring is a test helper to check if s contains sub.
func containsSubstring(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(s) > 0 && stringContains(s, sub))
}

func stringContains(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
