package testfixtures

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

// JSONRPCResult is the parsed envelope returned by JSONRPCPost.
type JSONRPCResult struct {
	Status int
	Body   []byte
}

// JSONRPCPost issues a JSON-RPC 2.0 request against baseURL/ with
// the given headers. Returns status code + raw body so tests can
// assert on the envelope (including error cases) without coupling
// to a specific result shape.
//
// Pass nil headers for the no-auth case. The function always sets
// Content-Type: application/json.
func JSONRPCPost(t *testing.T, baseURL, method string, params []any, headers map[string]string) JSONRPCResult {
	return JSONRPCPostAt(t, baseURL, "/", method, params, headers)
}

// JSONRPCPostAt is like JSONRPCPost but lets the caller choose the
// path (e.g. "/rpc/<org_id>" for org-scoped authenticated calls).
func JSONRPCPostAt(t *testing.T, baseURL, path, method string, params []any, headers map[string]string) JSONRPCResult {
	t.Helper()
	body, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"method":  method,
		"params":  params,
		"id":      1,
	})
	if err != nil {
		t.Fatalf("JSONRPCPost: marshal: %v", err)
	}
	req, err := http.NewRequestWithContext(context.Background(),
		http.MethodPost, baseURL+path, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("JSONRPCPost: new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		t.Fatalf("JSONRPCPost: %v", err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	return JSONRPCResult{Status: resp.StatusCode, Body: respBody}
}

// AssertOpaqueErrorBody mirrors e2e.assertOpaqueErrorBody (the one
// already defined in param_constraints_test.go). Verifies the body
// contains the generic "method not found" envelope and does not leak
// any of the forbidden substrings.
func AssertOpaqueErrorBody(t *testing.T, body []byte, forbiddenSubstrings ...string) {
	t.Helper()
	bodyStr := strings.ToLower(string(body))
	if !strings.Contains(bodyStr, "method not found") {
		t.Errorf("response body should contain generic 'method not found' message; got: %s", string(body))
	}
	if strings.Contains(bodyStr, "access denied") {
		t.Errorf("response body must not leak access denial details: %s", string(body))
	}
	if strings.Contains(bodyStr, "forbidden") {
		t.Errorf("response body must not leak forbidden status: %s", string(body))
	}
	for _, s := range forbiddenSubstrings {
		if strings.Contains(bodyStr, strings.ToLower(s)) {
			t.Errorf("response body must not leak %q: %s", s, string(body))
		}
	}
}
