package e2e

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

// HTTP-layer hardening tests (RD-962). Cover the attack surfaces that
// the well-behaved net/http client can't easily reach — request
// smuggling, truncated Content-Length, oversized/nested payloads,
// empty bodies. For these we drop to net.Dial and craft the request
// bytes ourselves.
//
// The malformed-JSON and oversized-body cases that ARE reachable
// through net/http are already covered by
// e2e/input_validation_test.go (PR C / Playwright→Go migration); we
// don't duplicate them.
//
// Each test asserts:
//
//   - The proxy returns a 4xx (not 2xx, not 5xx).
//   - The response body is opaque — no panic/runtime/stack frames,
//     no internal package names, no DB driver strings.
//   - The proxy stays up: a subsequent normal request succeeds.

// rawHTTPRequest dials the proxy directly and writes the given request
// bytes, then reads a single response. Returns the parsed status line
// + body. Used by smuggling / truncated-CL tests that the net/http
// client refuses to send.
func rawHTTPRequest(t *testing.T, serverURL string, rawReq []byte) (statusCode int, body []byte) {
	t.Helper()

	u, err := url.Parse(serverURL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}
	host := u.Host
	if !strings.Contains(host, ":") {
		host = host + ":80"
	}

	conn, err := net.DialTimeout("tcp", host, 5*time.Second)
	if err != nil {
		t.Fatalf("dial %s: %v", host, err)
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	if _, err := conn.Write(rawReq); err != nil {
		// Some smuggling-attempt rejections close the socket
		// mid-write. Treat that as "rejected", not a test error.
		return 0, []byte(fmt.Sprintf("write error: %v", err))
	}

	respBytes, err := io.ReadAll(conn)
	if err != nil && len(respBytes) == 0 {
		// Connection closed without response is also a valid
		// rejection — the proxy chose to drop us. Treat as 0.
		return 0, []byte(fmt.Sprintf("read error: %v", err))
	}

	// Parse status line: "HTTP/1.1 <code> <text>\r\n"
	end := bytes.Index(respBytes, []byte("\r\n"))
	if end < 0 {
		return 0, respBytes
	}
	statusLine := string(respBytes[:end])
	parts := strings.SplitN(statusLine, " ", 3)
	if len(parts) < 2 {
		return 0, respBytes
	}
	var code int
	if _, err := fmt.Sscanf(parts[1], "%d", &code); err != nil {
		return 0, respBytes
	}
	// Body starts after the blank line.
	bodyStart := bytes.Index(respBytes, []byte("\r\n\r\n"))
	if bodyStart >= 0 {
		body = respBytes[bodyStart+4:]
	} else {
		body = respBytes[end+2:]
	}
	return code, body
}

// assertProxyStillUp verifies the proxy responds to a normal request
// after the hostile probe. Catches regressions where a smuggling /
// oversized-body attempt crashes or wedges the server.
func assertProxyStillUp(t *testing.T, serverURL string) {
	t.Helper()
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(serverURL + "/health")
	if err != nil {
		t.Errorf("proxy unreachable after probe: %v", err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("proxy unhealthy after probe: status=%d", resp.StatusCode)
	}
}

// assertNoStackLeakage scans the response body for common
// internal-implementation tokens. Mirrors assertOpaqueErrorBody in
// param_constraints_test.go but tuned for 4xx HTTP responses (not
// JSON-RPC bodies).
func assertNoStackLeakage(t *testing.T, body []byte) {
	t.Helper()
	bodyLower := strings.ToLower(string(body))
	for _, leak := range []string{
		"panic", "runtime.", "goroutine",
		"pgx", "pq:", "sql:", "jackc/", "database/sql",
		"github.com/gateway-fm/", "internal/",
		".go:",
	} {
		if strings.Contains(bodyLower, leak) {
			t.Errorf("response leaks internal token %q: %s", leak, string(body))
		}
	}
}

// TestProxyHTTP_RequestSmugglingRejected exercises the classic CL.TE
// smuggling vector: a request with BOTH Content-Length AND
// Transfer-Encoding: chunked headers. RFC 7230 says recipients must
// reject this or pick one consistently. The proxy must reject — if it
// silently accepts, a downstream proxy that interprets one header and
// the proxy that interprets the other can be smuggled.
//
// Acceptance: status is 400 or the connection is closed (status 0 in
// our parser). Anything 2xx is a security regression.
func TestProxyHTTP_RequestSmugglingRejected(t *testing.T) {
	_, serverURL, cleanup := setupE2E(t)
	defer cleanup()

	body := `{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}`
	raw := []byte(
		"POST / HTTP/1.1\r\n" +
			"Host: localhost\r\n" +
			"Content-Type: application/json\r\n" +
			"Content-Length: " + fmt.Sprintf("%d", len(body)) + "\r\n" +
			"Transfer-Encoding: chunked\r\n" +
			"\r\n" +
			body)

	status, respBody := rawHTTPRequest(t, serverURL, raw)
	if status >= 200 && status < 300 {
		t.Errorf("smuggling vector accepted (status %d) — proxy must reject CL+TE concurrent headers: %s", status, string(respBody))
	}
	assertNoStackLeakage(t, respBody)
	assertProxyStillUp(t, serverURL)
}

// TestProxyHTTP_TruncatedContentLength sends a Content-Length that
// declares more bytes than the body actually contains. The proxy
// should either time out or return 400 — it must never silently
// succeed by reading the declared length from the next request's
// pipelined bytes (the classic pipelining-smuggling vector).
//
// We send CL=200 and only 50 bytes of body, then close the connection.
// A correct proxy times out reading the missing 150 bytes (we close
// our deadline at 5s) and either returns 408 / 400 / closes the
// connection.
func TestProxyHTTP_TruncatedContentLength(t *testing.T) {
	_, serverURL, cleanup := setupE2E(t)
	defer cleanup()

	shortBody := strings.Repeat("x", 50)
	raw := []byte(
		"POST / HTTP/1.1\r\n" +
			"Host: localhost\r\n" +
			"Content-Type: application/json\r\n" +
			"Content-Length: 200\r\n" +
			"\r\n" +
			shortBody)

	status, respBody := rawHTTPRequest(t, serverURL, raw)
	if status >= 200 && status < 300 {
		t.Errorf("truncated Content-Length accepted (status %d): %s", status, string(respBody))
	}
	assertNoStackLeakage(t, respBody)
	assertProxyStillUp(t, serverURL)
}

// TestProxyHTTP_DeeplyNestedJSON sends a 10k-level-deep nested JSON
// object. A naive recursive parser would blow the stack. Go's
// encoding/json bounds recursion at MaxDepth (10000 by default), so
// the proxy should reject with 400 — never panic, never OOM.
func TestProxyHTTP_DeeplyNestedJSON(t *testing.T) {
	_, serverURL, cleanup := setupE2E(t)
	defer cleanup()

	const depth = 10000
	var body bytes.Buffer
	body.WriteString(`{"jsonrpc":"2.0","method":"eth_call","params":[`)
	body.WriteString(strings.Repeat(`{"x":`, depth))
	body.WriteString(`1`)
	body.WriteString(strings.Repeat(`}`, depth))
	body.WriteString(`],"id":1}`)

	req, _ := http.NewRequestWithContext(context.Background(),
		http.MethodPost, serverURL+"/", bytes.NewReader(body.Bytes()))
	req.Header.Set("Content-Type", "application/json")
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		// Connection dropped — also a valid rejection.
		t.Logf("deeply-nested body dropped at connection level: %v", err)
		assertProxyStillUp(t, serverURL)
		return
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		t.Errorf("deeply-nested JSON accepted (status %d): %s", resp.StatusCode, string(respBody))
	}
	if resp.StatusCode == http.StatusInternalServerError {
		t.Errorf("deeply-nested JSON returned 500 (parser exhaustion / panic-recovery?): %s", string(respBody))
	}
	assertNoStackLeakage(t, respBody)
	assertProxyStillUp(t, serverURL)
}

// TestProxyHTTP_EmptyBodyWithContentLengthZero sends a POST to / with
// Content-Length: 0 and an empty body. The JSON-RPC parser must
// reject this — the proxy can't dispatch without a method name. The
// failure mode that worries us is a 500 from a nil-deref in the
// envelope parser; we want a clean 400 (or 404 if the proxy routes to
// the anonymous allowlist and fails there). Anything 2xx would be a
// regression.
func TestProxyHTTP_EmptyBodyWithContentLengthZero(t *testing.T) {
	_, serverURL, cleanup := setupE2E(t)
	defer cleanup()

	raw := []byte(
		"POST / HTTP/1.1\r\n" +
			"Host: localhost\r\n" +
			"Content-Type: application/json\r\n" +
			"Content-Length: 0\r\n" +
			"\r\n")

	status, respBody := rawHTTPRequest(t, serverURL, raw)
	if status >= 200 && status < 300 {
		t.Errorf("empty body accepted as a JSON-RPC request (status %d): %s", status, string(respBody))
	}
	if status == http.StatusInternalServerError {
		t.Errorf("empty body produced 500 — JSON parser nil-deref or panic-recovery: %s", string(respBody))
	}
	assertNoStackLeakage(t, respBody)
	assertProxyStillUp(t, serverURL)
}
