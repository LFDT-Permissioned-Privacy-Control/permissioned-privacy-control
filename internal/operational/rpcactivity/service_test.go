package rpcactivity

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"privacy-proxy/internal/activitylog"
	"privacy-proxy/internal/rpcengine"
)

func TestPeerAbsenceMappedAndScopedIP(t *testing.T) {
	for input, want := range map[string]string{"192.0.2.1:80": "192.0.2.1", "[::ffff:192.0.2.1]:80": "192.0.2.1", "[2001:db8::1]:80": "2001:db8::1", "[fe80::1%en0]:80": "", "invalid": "", "": ""} {
		if got := peer(input); got != want {
			t.Fatal(input, got, want)
		}
	}
}
func TestCompletionUsesActualClassAndDetachedRPCCode(t *testing.T) {
	code := int32(-32001)
	c, err := completion(rpcengine.OperationMetadata{Method: rpcengine.EthCall, Class: rpcengine.DeniedCompletion, RPCErrorCode: &code}, "invalid")
	if err != nil || c.Outcome != activitylog.Denied || c.HTTPStatus != 200 || c.TrustedIP != "" || *c.RPCErrorCode != -32001 {
		t.Fatal(c, err)
	}
	if _, err := completion(rpcengine.OperationMetadata{PolicyDigest: "not-a-digest"}, ""); err == nil {
		t.Fatal("invalid policy metadata accepted")
	}
}
func TestUnsupportedResponseControllerDoesNotReadBodyOrReserve(t *testing.T) {
	// The failure is BEFORE recorder dereference or Engine/node work. A weak
	// httptest writer must never silently qualify production deadline behavior.
	s := &Service{slots: make(chan struct{}, 1)}
	body := &countReader{}
	r := httptest.NewRequest("POST", "https://ops.test", body)
	w := httptest.NewRecorder()
	s.serve(w, r, "")
	if w.Code != 503 || body.reads != 0 || len(s.slots) != 0 || strings.Contains(w.Body.String(), "result") {
		t.Fatal(w.Code, body.reads)
	}
}

type countReader struct{ reads int }

func (c *countReader) Read(p []byte) (int, error) {
	c.reads++
	panic("body read before deadline support")
}

func TestBusySupportedWriterGetsOriginalWriteDeadlineBeforeResponse(t *testing.T) {
	s := &Service{slots: make(chan struct{}, 1)}
	s.slots <- struct{}{}
	until := time.Now().Add(time.Second)
	ctx, cancel := context.WithDeadline(t.Context(), until)
	defer cancel()
	body := &countReader{}
	r := httptest.NewRequest("POST", "https://ops.test", body).WithContext(ctx)
	w := &deadlineWriter{t: t, header: make(http.Header), expected: until}
	s.serve(w, r, "")
	if w.status != 503 || w.writes != 1 || w.writeDeadline.IsZero() || !w.writeDeadline.Equal(until) || w.readCalls != 0 || body.reads != 0 || len(s.slots) != 1 {
		t.Fatal("busy rejection escaped deadline/admission boundary", w.status, w.writeDeadline, w.readCalls, body.reads)
	}
}

type deadlineWriter struct {
	t                         *testing.T
	header                    http.Header
	expected, writeDeadline   time.Time
	readCalls, writes, status int
}

func (w *deadlineWriter) Header() http.Header                 { return w.header }
func (w *deadlineWriter) SetWriteDeadline(at time.Time) error { w.writeDeadline = at; return nil }
func (w *deadlineWriter) SetReadDeadline(at time.Time) error  { w.readCalls++; return nil }
func (w *deadlineWriter) WriteHeader(status int) {
	if w.writeDeadline.IsZero() || !w.writeDeadline.Equal(w.expected) {
		w.t.Error("response before original write deadline")
	}
	w.status = status
}
func (w *deadlineWriter) Write(b []byte) (int, error) {
	if w.writeDeadline.IsZero() {
		w.t.Error("unbounded overloaded write")
	}
	w.writes++
	return len(b), nil
}
