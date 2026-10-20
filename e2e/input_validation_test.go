//go:build mockauth

package e2e

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"privacy-proxy/e2e/testfixtures"
)

// This file ports e2e/playwright/tests/security/05-input-validation.spec.ts.
//
// 20 source tests consolidate into 6 Go test functions. The
// underlying invariant for every assertion in this file is the same:
// the proxy must never respond 500 to user-controlled input. Crash =
// information leak risk + DoS surface.

// rawPost is a lower-level than testfixtures.JSONRPCPost: it lets
// the caller pass an arbitrary body (already-marshalled JSON or raw
// text) and arbitrary headers. Used by the malformed-body tests
// that deliberately violate the JSON-RPC envelope.
func rawPost(t *testing.T, baseURL string, body []byte, headers map[string]string) (int, []byte) {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(),
		http.MethodPost, baseURL+"/", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("rawPost: new request: %v", err)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		// Connection closed on an oversized body is acceptable — the
		// proxy enforces MaxRequestBodySize at io.LimitReader and may
		// drop. Callers check for this explicitly.
		return 0, []byte(err.Error())
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, respBody
}

// TestInputValidation_SQLInjectionPayloadsRejected verifies that
// classic SQL injection attempts against admin REST endpoints don't
// reach the database — they're rejected at the validation layer with
// a 400 (or 422), and never produce a 500 (which would imply a SQL
// error reached the response).
//
// Ports SQLI-001 / SQLI-002 / SQLI-003 from security/05.
func TestInputValidation_SQLInjectionPayloadsRejected(t *testing.T) {
	_, serverURL, cleanup := setupE2E(t)
	defer cleanup()

	client := testfixtures.NewAdminClient(serverURL)

	t.Run("org_slug_payloads", func(t *testing.T) {
		payloads := []string{
			"'; DROP TABLE organizations; --",
			"' OR '1'='1",
			"'; SELECT * FROM users; --",
			"1; DELETE FROM organizations WHERE 1=1; --",
			"' UNION SELECT * FROM users --",
			"admin'--",
			"${7*7}",
			"{{7*7}}",
			"'; WAITFOR DELAY '0:0:5'--",
		}
		for _, payload := range payloads {
			t.Run(payload[:min(15, len(payload))], func(t *testing.T) {
				status, body := client.DoRaw(t, http.MethodPost, "/api/v1/admin/orgs",
					map[string]any{"slug": payload, "name": "Test Org"})
				if status == http.StatusInternalServerError {
					t.Errorf("server returned 500 (possible SQL injection): %s", string(body))
				}
				bodyLower := strings.ToLower(string(body))
				for _, leak := range []string{"sql", "syntax", "postgres", "pgx"} {
					if strings.Contains(bodyLower, leak) {
						t.Errorf("response body leaks %q internals: %s", leak, string(body))
					}
				}
			})
		}
	})

	t.Run("user_id_path_payloads", func(t *testing.T) {
		// The user_id path parameter is expected to be a UUID. SQL
		// payloads in the path should ideally produce 400/404, but
		// the current handler doesn't pre-validate UUID format and
		// falls through to a DB error that surfaces as 500. The
		// Playwright spec accepted [400, 404, 500] with a TODO
		// comment; we match that — what matters is the payload
		// doesn't reach the handler (no 2xx) and no SQL/DB internals
		// leak in the response body.
		payloads := []string{"'; DROP TABLE users; --", "' OR '1'='1"}
		for _, payload := range payloads {
			status, body := client.DoRaw(t, http.MethodPut,
				"/api/v1/admin/users/"+payload,
				map[string]any{"kyc": true})
			if status >= 200 && status < 300 {
				t.Errorf("SQL payload %q reached handler (status %d): %s", payload, status, string(body))
			}
			bodyLower := strings.ToLower(string(body))
			for _, leak := range []string{"sql", "syntax", "postgres", "pgx"} {
				if strings.Contains(bodyLower, leak) {
					t.Errorf("response body leaks %q internals: %s", leak, string(body))
				}
			}
		}
	})
}

// TestInputValidation_BatchRequestRejected verifies that JSON-RPC
// batch requests (array at top level) are rejected with 400. The
// proxy chooses to disallow batching to keep request accounting
// per-request and prevent multicall-style smuggling.
//
// Ports INPUT-001 from security/05.
func TestInputValidation_BatchRequestRejected(t *testing.T) {
	_, serverURL, cleanup := setupE2E(t)
	defer cleanup()

	batchBody := []byte(`[
		{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1},
		{"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":2}
	]`)
	status, body := rawPost(t, serverURL, batchBody, map[string]string{
		"Content-Type": "application/json",
	})
	if status != http.StatusBadRequest {
		t.Errorf("expected 400 (batch rejected), got %d: %s", status, string(body))
	}
	if !strings.Contains(strings.ToLower(string(body)), "batch") {
		t.Errorf("error body should mention 'batch'; got: %s", string(body))
	}
}

// TestInputValidation_MalformedJSONRPCEnvelope verifies that broken
// JSON-RPC envelopes (missing fields, wrong version, bad types) are
// handled gracefully — never 500. Status varies (200 with error body,
// 400, 404 RBAC opaque) depending on which validation layer trips
// first; the contract is "no 500, no accepted execution".
//
// Ports INPUT-002, -003, -004, -005, -006, -007 from security/05.
func TestInputValidation_MalformedJSONRPCEnvelope(t *testing.T) {
	_, serverURL, cleanup := setupE2E(t)
	defer cleanup()

	cases := []struct {
		name string
		body string
	}{
		{"missing_jsonrpc", `{"method":"eth_blockNumber","params":[],"id":1}`},
		{"missing_method", `{"jsonrpc":"2.0","params":[],"id":1}`},
		{"wrong_version", `{"jsonrpc":"1.0","method":"eth_blockNumber","params":[],"id":1}`},
		{"negative_id", `{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":-1}`},
		{"params_string_not_array", `{"jsonrpc":"2.0","method":"eth_blockNumber","params":"invalid","id":1}`},
		{"null_method", `{"jsonrpc":"2.0","method":null,"params":[],"id":1}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			status, body := rawPost(t, serverURL, []byte(tc.body),
				map[string]string{"Content-Type": "application/json"})
			if status == http.StatusInternalServerError {
				t.Errorf("malformed envelope produced 500: %s", string(body))
			}
		})
	}
}

// TestInputValidation_OversizedAndLongInputs covers the body-size
// and long-method-name guards.
//
// The proxy enforces MaxRequestBodySize (1 MB) via io.LimitReader
// in server.go:815. Oversized requests get 400 from the
// JSON-parsing layer (read returns short body) or a connection drop.
// Long method names get 4xx or a JSON-RPC error body.
//
// Ports INPUT-008 / INPUT-009.
func TestInputValidation_OversizedAndLongInputs(t *testing.T) {
	_, serverURL, cleanup := setupE2E(t)
	defer cleanup()

	t.Run("body_over_1MB_rejected", func(t *testing.T) {
		large := strings.Repeat("x", 1024*1024+1000)
		body := []byte(`{"jsonrpc":"2.0","method":"eth_call","params":[{"data":"` + large + `"}],"id":1}`)
		status, respBody := rawPost(t, serverURL, body, map[string]string{
			"Content-Type": "application/json",
		})
		// Allowed: connection-drop (status=0 from rawPost), 400, or 413.
		if status == http.StatusInternalServerError {
			t.Errorf("oversized body returned 500: %s", string(respBody))
		}
		if status != 0 && status != http.StatusBadRequest && status != http.StatusRequestEntityTooLarge && status != http.StatusOK {
			t.Errorf("oversized body returned unexpected status %d: %s", status, string(respBody))
		}
	})

	t.Run("very_long_method_name_rejected", func(t *testing.T) {
		longMethod := "eth_" + strings.Repeat("x", 10000)
		res := testfixtures.JSONRPCPost(t, serverURL, longMethod, []any{}, nil)
		if res.Status == http.StatusInternalServerError {
			t.Errorf("long method name returned 500: %s", string(res.Body))
		}
		// Acceptable: any 4xx, or 200 with an error body. Not acceptable: 2xx with a result.
		if res.Status >= 200 && res.Status < 300 && !strings.Contains(string(res.Body), "error") {
			t.Errorf("long method name was accepted (no error in body): status=%d body=%s", res.Status, string(res.Body))
		}
	})
}

// TestInputValidation_AddressFormatHandling verifies the proxy
// safely handles invalid address formats in JSON-RPC params: never
// 500, regardless of garbage input. Also confirms checksummed vs
// lowercase address representations are both accepted (normalised
// internally).
//
// Ports ADDR-001 / ADDR-002.
func TestInputValidation_AddressFormatHandling(t *testing.T) {
	_, serverURL, cleanup := setupE2E(t)
	defer cleanup()

	t.Run("invalid_address_formats", func(t *testing.T) {
		cases := []string{
			"not-an-address",
			"0x",
			"0x123",                              // too short
			"0x" + strings.Repeat("g", 40),        // invalid hex
			"0x" + strings.Repeat("1", 41),        // too long
			"",                                    // empty
		}
		for _, addr := range cases {
			t.Run(addr+"_", func(t *testing.T) {
				res := testfixtures.JSONRPCPost(t, serverURL, "eth_getBalance",
					[]any{addr, "latest"}, nil)
				if res.Status == http.StatusInternalServerError {
					t.Errorf("invalid address %q returned 500: %s", addr, string(res.Body))
				}
			})
		}
	})

	t.Run("case_insensitive_address", func(t *testing.T) {
		lowercase := "0xd8da6bf26964af9d7eed9e03e53415d37aa96045"
		checksummed := "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"
		for _, addr := range []string{lowercase, checksummed} {
			res := testfixtures.JSONRPCPost(t, serverURL, "eth_getBalance",
				[]any{addr, "latest"}, nil)
			if res.Status == http.StatusInternalServerError {
				t.Errorf("address %q returned 500: %s", addr, string(res.Body))
			}
		}
	})
}

// TestInputValidation_SpecialCharactersAndContentType covers the
// tail of security/05: null bytes, RTL override, control chars,
// missing/wrong/mismatched Content-Type. The proxy must not crash.
//
// Ports SPECIAL-001/-002/-003 and CONTENT-001/-002/-003.
func TestInputValidation_SpecialCharactersAndContentType(t *testing.T) {
	_, serverURL, cleanup := setupE2E(t)
	defer cleanup()

	t.Run("null_byte_in_method", func(t *testing.T) {
		body := []byte(`{"jsonrpc":"2.0","method":"eth_blockNumber` + "\x00" + `","params":[],"id":1}`)
		status, respBody := rawPost(t, serverURL, body,
			map[string]string{"Content-Type": "application/json"})
		if status == http.StatusInternalServerError {
			t.Errorf("null byte in method returned 500: %s", string(respBody))
		}
	})

	t.Run("rtl_override_in_method", func(t *testing.T) {
		body := []byte(`{"jsonrpc":"2.0","method":"eth_blockNumber‮","params":[],"id":1}`)
		status, respBody := rawPost(t, serverURL, body,
			map[string]string{"Content-Type": "application/json"})
		if status == http.StatusInternalServerError {
			t.Errorf("RTL override returned 500: %s", string(respBody))
		}
	})

	t.Run("missing_content_type", func(t *testing.T) {
		body := []byte(`{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}`)
		status, respBody := rawPost(t, serverURL, body, nil)
		if status == http.StatusInternalServerError {
			t.Errorf("missing Content-Type returned 500: %s", string(respBody))
		}
		// Allowed: any of 200, 400, 415.
		if status != http.StatusOK && status != http.StatusBadRequest && status != http.StatusUnsupportedMediaType {
			// 404 also acceptable since unauthenticated anonymous flow
			// will hit method routing.
			if status != http.StatusNotFound {
				t.Errorf("missing Content-Type: status %d unexpected", status)
			}
		}
	})

	t.Run("wrong_content_type_text_plain", func(t *testing.T) {
		body := []byte(`{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}`)
		status, respBody := rawPost(t, serverURL, body,
			map[string]string{"Content-Type": "text/plain"})
		if status == http.StatusInternalServerError {
			t.Errorf("text/plain CT returned 500: %s", string(respBody))
		}
	})

	t.Run("xml_payload_with_json_ct", func(t *testing.T) {
		body := []byte(`<?xml version="1.0"?><request><method>eth_blockNumber</method></request>`)
		status, respBody := rawPost(t, serverURL, body,
			map[string]string{"Content-Type": "application/json"})
		// Must reject as bad JSON; expect 400.
		if status != http.StatusBadRequest {
			t.Errorf("expected 400 for XML-as-JSON, got %d: %s", status, string(respBody))
		}
	})
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
