package accesslog

import (
	"bytes"
	"context"
	"errors"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	a "privacy-proxy/internal/activitylog"
	"privacy-proxy/internal/activitymethoddata"
	f "privacy-proxy/internal/disclosuretest"
)

type stubReader struct {
	calls    int
	snapshot *stubSnapshot
}

func (r *stubReader) OpenAdmin(context.Context, string, int64) (Snapshot, error) {
	r.calls++
	if r.snapshot == nil {
		return nil, ErrUnavailable
	}
	return r.snapshot, nil
}

type stubSnapshot struct {
	cut      Cut
	rows     []a.Envelope
	end      bool
	checks   int
	onRead   func()
	onCheck  func()
	checkErr error
	closed   bool
}

func (s *stubSnapshot) Cut() Cut { return s.cut }
func (s *stubSnapshot) ReadOrgPage(context.Context, string, Query, *Position) ([]a.Envelope, bool, error) {
	if s.onRead != nil {
		s.onRead()
	}
	return s.rows, s.end, nil
}
func (s *stubSnapshot) Close() { s.closed = true }
func (s *stubSnapshot) CheckCurrent(context.Context) error {
	s.checks++
	if s.onCheck != nil {
		s.onCheck()
	}
	return s.checkErr
}
func expected() a.StoreMetadata {
	return a.StoreMetadata{NetworkKey: a.Digest{1}, SourceID: f.Org, Generation: f.OtherOrg, Configuration: a.Digest{2}, Format: a.Format()}
}
func TestCurrentAdminBeforeSourceAndAgainBeforePublication(t *testing.T) {
	bundle := f.Snapshot(t, nil)
	now := time.Unix(f.Now, 0)
	r := &stubReader{}
	s, e := New(Config{Snapshot: bundle, Reader: r, Expected: expected(), Clock: func() time.Time { return now }, Keys: Keys{Active: Key{"k", bytes.Repeat([]byte{4}, 32)}}})
	if e != nil {
		t.Fatal(e)
	}
	q := Query{FromMicros: 0, ToMicros: a.MaxObservedMicros, Limit: 2}
	for _, roles := range [][]string{{"Local"}, {"Foreign"}, {"Auditor"}} {
		if _, e = s.Read(t.Context(), f.Token(t, bundle, f.Subject, roles...), f.Org, q, ""); !errors.Is(e, ErrForbidden) {
			t.Fatal("role", roles, e)
		}
	}
	if r.calls != 0 {
		t.Fatal("denied before source", r.calls)
	}
	r.snapshot = &stubSnapshot{cut: Cut{Metadata: expected(), Reference: "sha256:" + strings.Repeat("a", 64), Coverage: "sha256:" + strings.Repeat("b", 64), Population: activitymethoddata.PopulationRequests, AsOfMicros: f.Now * 1000000}, end: true}
	for _, role := range []string{"Admin", "Readonly"} {
		response, e := s.Read(t.Context(), f.Token(t, bundle, f.Subject, role), f.Org, q, "")
		if e != nil {
			t.Fatal(role, e)
		}
		var out bytes.Buffer
		if _, e = response.WriteTo(&out); e != nil || !strings.Contains(out.String(), `"items":[]`) {
			t.Fatal(role, out.String(), e)
		}
	}
	response, e := s.Read(t.Context(), f.Token(t, bundle, f.Subject, "Admin"), f.Org, q, "")
	if e != nil {
		t.Fatal(e)
	}
	now = now.Add(301 * time.Second)
	var out bytes.Buffer
	if _, e = response.WriteTo(&out); !errors.Is(e, ErrUnauthorized) || out.Len() != 0 {
		t.Fatal("expired output released", e, out.String())
	}
	now = time.Unix(f.Now, 0)
	response, e = s.Read(t.Context(), f.Token(t, bundle, f.Subject, "Admin"), f.Org, q, "")
	if e != nil {
		t.Fatal(e)
	}
	r.snapshot.onCheck = func() { now = now.Add(301 * time.Second) }
	out.Reset()
	if _, e = response.WriteTo(&out); !errors.Is(e, ErrUnauthorized) || out.Len() != 0 {
		t.Fatal("expiry during final source check released output", e, out.String())
	}
	r.snapshot.onCheck = nil
	now = time.Unix(f.Now, 0)
	r.snapshot.onRead = func() { now = now.Add(301 * time.Second) }
	if _, e = s.Read(t.Context(), f.Token(t, bundle, f.Subject, "Admin"), f.Org, q, ""); !errors.Is(e, ErrUnauthorized) {
		t.Fatal("expired during read", e)
	}
}
func TestClosedQueryAndMicrosecondHalfOpenNormalization(t *testing.T) {
	base := "from=2026-01-01T00%3A00%3A00.000000001Z&to=2026-01-01T00%3A00%3A01.000000001Z"
	q, _, e := parseQuery(httptest.NewRequest("GET", "/x?"+base, nil))
	if e != nil || q.ToMicros-q.FromMicros != 1000000 || q.FromMicros%1000000 != 1 {
		t.Fatal(q, e)
	}
	for _, suffix := range []string{"&method=eth_call&method=eth_call", "&bogus=x", "&actorId=someone", "&outcome=maybe", "&method=explorer.unknown", "&requestReference=nope", "&limit=0", "&limit=101", "&limit=01", "&cursor=", "&method="} {
		if _, _, e := parseQuery(httptest.NewRequest("GET", "/x?"+base+suffix, nil)); !errors.Is(e, ErrInvalid) {
			t.Fatal(suffix, e)
		}
	}
	if _, _, e = parseQuery(httptest.NewRequest("GET", "/x?"+url.Values{"to": {"2026-01-01T00:00:00Z"}}.Encode(), nil)); !errors.Is(e, ErrInvalid) {
		t.Fatal("missing bound")
	}
}
func TestCursorSealedContextTTLDomainAndRotation(t *testing.T) {
	old := Key{"old", bytes.Repeat([]byte{1}, 32)}
	fresh := Key{"new", bytes.Repeat([]byte{2}, 32)}
	now := time.Unix(f.Now, 0)
	ring, e := newCursor(Keys{Active: old})
	if e != nil {
		t.Fatal(e)
	}
	p := cursorState{Version: 1, Actor: f.Actor(f.Subject), Profile: "azure", ProfileDigest: "profile", Bundle: "bundle", Organization: f.Org, Query: "query", Cut: Cut{Metadata: expected(), AsOfMicros: f.Now * 1000000}, Expires: now.Add(5 * time.Minute).Unix()}
	token, e := ring.seal(p)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = ring.open(token, p, now); e != nil {
		t.Fatal(e)
	}
	changed := p
	changed.Query = "new query"
	if _, e = ring.open(token, changed, now); !errors.Is(e, ErrCursor) {
		t.Fatal(e)
	}
	changed = p
	changed.ProfileDigest = "new profile"
	if _, e = ring.open(token, changed, now); !errors.Is(e, ErrCursor) {
		t.Fatal(e)
	}
	changed = p
	changed.PopulationDigest = "previous recognized population"
	if _, e = ring.open(token, changed, now); !errors.Is(e, ErrCursor) {
		t.Fatal("old population cursor was accepted", e)
	}
	if _, e = ring.open(token, p, now.Add(5*time.Minute)); !errors.Is(e, ErrExpired) {
		t.Fatal(e)
	}
	if _, e = ring.open(strings.Replace(token, "al1.", "dc1.", 1), p, now); !errors.Is(e, ErrInvalid) {
		t.Fatal("cross domain", e)
	}
	rotated, e := newCursor(Keys{Active: fresh, Previous: &old})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = rotated.open(token, p, now); e != nil {
		t.Fatal("rotation", e)
	}
	retired, _ := newCursor(Keys{Active: fresh})
	if _, e = retired.open(token, p, now); !errors.Is(e, ErrInvalid) {
		t.Fatal("retired key", e)
	}
}
