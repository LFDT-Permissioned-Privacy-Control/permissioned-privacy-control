// RD-934. Opacity tests for the respond*AndLog helpers.
//
// The helpers are the leverage point of the audit — every fix in the
// 155-site sweep replaces a raw err.Error() echo with one of these
// calls. The contract is asymmetric:
//
//   * The CLIENT receives only the opaque clientMsg (which the helper
//     forwards to the corresponding respond* helper).
//   * The OPERATOR receives the structured slog entry with the full
//     err and any caller-supplied identifiers, at the appropriate
//     level (Warn for client-driven bad-request, Info for handled
//     denials, Error for unexpected failures).
//
// These tests pin the contract by:
//   1. Invoking each helper with a structured "synthetic" err that
//      contains a sentinel substring (an attacker-aiding string we
//      don't want on the wire).
//   2. Asserting the HTTP response body NEVER contains the sentinel.
//   3. Asserting the slog output DOES contain the sentinel — that's
//      the operator's diagnostic source.

package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

// sentinel is the string we want NEVER to appear in the wire response
// body. In production the equivalent string is something like a `pq.PQError`
// containing constraint names, sample row values, or file paths — see the
// RD-934 issue body for the leak categories.
const sentinel = "INTERNAL-DB-LEAK-SENTINEL-49ec1a3f"

// withCapturedSlog redirects the default slog logger to a buffer for
// the duration of the test, then restores the previous default. Returns
// the buffer for assertions on operator output.
func withCapturedSlog(t *testing.T) *bytes.Buffer {
	t.Helper()
	buf := &bytes.Buffer{}
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return buf
}

// fixture builds a gin context + recorder pair so the helper can be
// invoked the same way production handlers invoke it.
func fixture() (*gin.Context, *httptest.ResponseRecorder) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPost, "/test", nil)
	return c, w
}

// requireOpaqueResponse asserts the body is the canonical opaque JSON
// shape (`{"error": clientMsg}`) and contains no leak of the sentinel.
func requireOpaqueResponse(t *testing.T, w *httptest.ResponseRecorder, wantStatus int, wantClientMsg string) {
	t.Helper()
	if w.Code != wantStatus {
		t.Fatalf("status: got %d, want %d (body=%s)", w.Code, wantStatus, w.Body.String())
	}
	var resp map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("response not JSON: %v (body=%s)", err, w.Body.String())
	}
	if resp["error"] != wantClientMsg {
		t.Fatalf("client message: got %q, want %q", resp["error"], wantClientMsg)
	}
	if strings.Contains(w.Body.String(), sentinel) {
		t.Fatalf("LEAK: sentinel %q appears in client response body: %s", sentinel, w.Body.String())
	}
}

// requireOperatorSawSentinel asserts the slog buffer captured the
// sentinel — the operator-side guarantee that the helper actually
// logged the error rather than silently dropping it.
func requireOperatorSawSentinel(t *testing.T, buf *bytes.Buffer) {
	t.Helper()
	if !strings.Contains(buf.String(), sentinel) {
		t.Fatalf("operator slog did not capture sentinel; the helper must log the err. got=%s", buf.String())
	}
}

func TestRD934_RespondInternalErrorAndLog_OpaqueWire_SlogCarriesErr(t *testing.T) {
	buf := withCapturedSlog(t)
	c, w := fixture()
	err := errors.New(sentinel + ": wrapped chain with table=secret_users")

	respondInternalErrorAndLog(c, "failed to process",
		"handler: db op failed", "ctx_key", "ctx_val", "err", err)

	requireOpaqueResponse(t, w, http.StatusInternalServerError, "failed to process")
	requireOperatorSawSentinel(t, buf)
}

func TestRD934_RespondBadRequestAndLog_OpaqueWire_SlogCarriesErr(t *testing.T) {
	buf := withCapturedSlog(t)
	c, w := fixture()
	err := errors.New(sentinel + ": validator: field=admin_org_ids[2] invalid uuid")

	respondBadRequestAndLog(c, "invalid request body",
		"handler: invalid body", "err", err)

	requireOpaqueResponse(t, w, http.StatusBadRequest, "invalid request body")
	requireOperatorSawSentinel(t, buf)
}

func TestRD934_RespondNotFoundAndLog_OpaqueWire_SlogCarriesErr(t *testing.T) {
	buf := withCapturedSlog(t)
	c, w := fixture()
	err := errors.New(sentinel + ": no rows in result set (org_id=foo)")

	respondNotFoundAndLog(c, "not found", "handler: lookup miss", "err", err)

	requireOpaqueResponse(t, w, http.StatusNotFound, "not found")
	requireOperatorSawSentinel(t, buf)
}

func TestRD934_RespondConflictAndLog_OpaqueWire_SlogCarriesErr(t *testing.T) {
	buf := withCapturedSlog(t)
	c, w := fixture()
	err := errors.New(sentinel + ": duplicate key value violates unique constraint")

	respondConflictAndLog(c, "already exists",
		"handler: conflict", "err", err)

	requireOpaqueResponse(t, w, http.StatusConflict, "already exists")
	requireOperatorSawSentinel(t, buf)
}

func TestRD934_RespondBadGatewayAndLog_OpaqueWire_SlogCarriesErr(t *testing.T) {
	buf := withCapturedSlog(t)
	c, w := fixture()
	err := errors.New(sentinel + ": upstream dial tcp 10.0.0.5:5432 i/o timeout")

	respondBadGatewayAndLog(c, "upstream unavailable",
		"handler: upstream failed", "err", err)

	requireOpaqueResponse(t, w, http.StatusBadGateway, "upstream unavailable")
	requireOperatorSawSentinel(t, buf)
}

func TestRD934_RespondServiceUnavailableAndLog_OpaqueWire_SlogCarriesErr(t *testing.T) {
	buf := withCapturedSlog(t)
	c, w := fixture()
	err := errors.New(sentinel + ": circuit-breaker open since 2026-05-19T12:34:56Z")

	respondServiceUnavailableAndLog(c, "service degraded",
		"handler: breaker open", "err", err)

	requireOpaqueResponse(t, w, http.StatusServiceUnavailable, "service degraded")
	requireOperatorSawSentinel(t, buf)
}

// TestRD934_NoEchoOfClientMsgInWireUnlessAsked asserts the opaque
// clientMsg is exactly what hits the wire — no concatenation, no
// templating, no "[INFO] " prefix bleeding from slog into the body.
// Defends against a future "helpful" change that decides to enrich
// the client message with the slog context.
func TestRD934_NoEchoOfClientMsgInWireUnlessAsked(t *testing.T) {
	_ = withCapturedSlog(t)
	c, w := fixture()
	respondInternalErrorAndLog(c, "exact opaque",
		"handler: anything", "secret_field", "secret_value", "err", errors.New(sentinel))

	if w.Body.String() != `{"error":"exact opaque"}` {
		t.Fatalf("body must be exactly the opaque payload; got %q", w.Body.String())
	}
}
