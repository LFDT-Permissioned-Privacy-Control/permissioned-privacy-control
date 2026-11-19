package accesslog

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	a "privacy-proxy/internal/activitylog"
	"privacy-proxy/internal/activitymethoddata"
	"privacy-proxy/internal/audit/buffer"
	"privacy-proxy/internal/audit/sealer"
	f "privacy-proxy/internal/disclosuretest"
	"privacy-proxy/internal/networkidentity"
)

// This store isolates the real local synced recorder and HTTP gate. SQL
// qualification is covered separately by activitysql's actual-PG tests.
type auditStore struct {
	metadata a.StoreMetadata
	next     uint64
}
type auditRun struct{ binding a.RunBinding }

func (s *auditStore) Metadata() a.StoreMetadata { return s.metadata }
func (s *auditStore) StartRun(_ context.Context, q a.RunRequest) (a.RunStore, error) {
	s.next = max(s.next, q.AllocatedThrough>>buffer.RangeShift) + 1
	base := s.next << buffer.RangeShift
	return &auditRun{a.RunBinding{Metadata: s.metadata, ProducerID: q.ProducerID, RunID: q.RunID, RangeIndex: s.next, Base: base, Top: base + (1 << buffer.RangeShift) - 1}}, nil
}
func (r *auditRun) Binding() a.RunBinding                                { return r.binding }
func (*auditRun) HighWater(context.Context) (uint64, error)              { return 0, nil }
func (*auditRun) RangeHighWater(context.Context, uint64) (uint64, error) { return 0, nil }
func (*auditRun) Verify(_ context.Context, entries []buffer.Entry) ([]sealer.Verdict, error) {
	out := make([]sealer.Verdict, len(entries))
	for i := range out {
		out[i] = sealer.Missing
	}
	return out, nil
}
func (*auditRun) SealOne(context.Context, uint64, []byte) error {
	return errors.New("fixture does not run background SQL sealing")
}
func (*auditRun) SealBatch(context.Context, []buffer.Entry) error {
	return errors.New("fixture does not run background SQL sealing")
}
func (*auditRun) Settle(_ context.Context, _ uint64, entries []buffer.Entry) (uint64, error) {
	if len(entries) > 0 {
		return entries[0].Seq, nil
	}
	return 0, nil
}

type auditFixture struct {
	service       *Service
	handler       *Handler
	recorder      *a.Recorder
	cfg           a.Config
	reader        *stubReader
	now, recorded time.Time
	onCompletion  func()
	token         string
	tokenFor      func(string) string
	policy        string
}

func newAuditFixture(t *testing.T) *auditFixture {
	t.Helper()
	bundle := f.Snapshot(t, nil)
	x := &auditFixture{now: time.Unix(f.Now, 0), recorded: time.Unix(f.Now, 0)}
	network := networkidentity.Binding{Environment: "test", ChainID: "1", GenesisHash: "0x" + strings.Repeat("0", 63) + "1", DeploymentID: "access-log-audit"}
	key, _ := network.Key()
	metadata := a.StoreMetadata{NetworkKey: a.Digest(key), SourceID: f.Org, Generation: f.OtherOrg, Configuration: a.Digest{2}, Format: a.Format()}
	x.reader = &stubReader{snapshot: &stubSnapshot{cut: Cut{Metadata: metadata, Reference: "sha256:" + strings.Repeat("a", 64), Coverage: "sha256:" + strings.Repeat("b", 64), Population: activitymethoddata.PopulationRequests, AsOfMicros: f.Now * 1000000}, end: true, rows: []a.Envelope{{Version: 1, RecordID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", ActorID: f.Actor(f.AdminSubject), DataOrg: f.Org, Method: "eth_call", ObservedMicros: f.Now * 1000000, HTTP: 200, Outcome: "success", Status: 200, Policy: strings.Repeat("3", 64), Configuration: hex.EncodeToString(metadata.Configuration[:])}}}}
	x.cfg = a.Config{Network: network, SourceID: metadata.SourceID, ProducerID: "55555555-5555-4555-8555-555555555555", ExpectedGeneration: metadata.Generation, Configuration: metadata.Configuration, Methods: []string{"eth_call", activitymethoddata.AdminAccessLogs}, BufferDirectory: t.TempDir(), Limits: a.Limits{InFlight: 1, BufferedEntries: 32, BufferedBytes: 32 * a.MaxEncodedBytes, SealBatch: 4}, Clock: func() time.Time {
		if x.onCompletion != nil {
			x.onCompletion()
		}
		return x.recorded
	}}
	var e error
	x.recorder, e = a.New(t.Context(), x.cfg, &auditStore{metadata: metadata})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		if e := x.recorder.Close(context.Background()); e != nil {
			t.Error(e)
		}
	})
	x.service, e = New(Config{Snapshot: bundle, Reader: x.reader, Expected: metadata, Clock: func() time.Time { return x.now }, Keys: Keys{Active: Key{"audit", bytes.Repeat([]byte{7}, 32)}}})
	if e != nil {
		t.Fatal(e)
	}
	x.handler, e = NewHandler(x.service, x.recorder)
	if e != nil {
		t.Fatal(e)
	}
	x.tokenFor = func(role string) string { return f.Token(t, bundle, f.Subject, role) }
	x.token = x.tokenFor("Admin")
	x.policy = strings.TrimPrefix(string(bundle.Metadata().ManifestDigest), "sha256:")
	return x
}
func (x *auditFixture) request(t *testing.T, org, token string, extra url.Values) (int, http.Header, []byte) {
	t.Helper()
	if e := x.recorder.CheckHealth(); e != nil {
		t.Fatal(e)
	}
	mux := http.NewServeMux()
	x.handler.Register(mux)
	server := httptest.NewServer(mux)
	defer server.Close()
	q := url.Values{"from": {asTime((f.Now - 10) * 1000000)}, "to": {asTime((f.Now + 10) * 1000000)}}
	for key, values := range extra {
		q[key] = values
	}
	r, e := http.NewRequestWithContext(t.Context(), "GET", server.URL+"/api/v2/orgs/"+org+"/access-logs?"+q.Encode(), nil)
	if e != nil {
		t.Fatal(e)
	}
	r.Header.Set("Authorization", "Bearer "+token)
	r.Header.Set("X-Forwarded-For", "203.0.113.77")
	r.Header.Set(a.RequestReferenceHeader, f.OtherOrg)
	out, e := server.Client().Do(r)
	if e != nil {
		t.Fatal(e)
	}
	defer out.Body.Close()
	body, e := io.ReadAll(out.Body)
	if e != nil {
		t.Fatal(e)
	}
	return out.StatusCode, out.Header, body
}
func (x *auditFixture) records(t *testing.T) []a.Envelope {
	t.Helper()
	if e := x.recorder.Close(t.Context()); e != nil {
		t.Fatal(e)
	}
	b, e := buffer.Open(x.cfg.BufferDirectory)
	if e != nil {
		t.Fatal(e)
	}
	defer b.Close()
	entries, e := b.DrainBounded(0, 32, a.MaxEncodedBytes, a.MaxBatchBytes)
	if e != nil {
		t.Fatal(e)
	}
	var out []a.Envelope
	for _, entry := range entries {
		r, e := a.DecodeSpool(entry.Data)
		if e != nil {
			t.Fatal(e)
		}
		out = append(out, r.Fields())
	}
	return out
}
func TestActualHTTPRequiresDurableTrustedInvestigationCompletion(t *testing.T) {
	for _, role := range []string{"Admin", "Readonly"} {
		t.Run(role, func(t *testing.T) {
			x := newAuditFixture(t)
			x.token = x.tokenFor(role)
			x.onCompletion = func() {
				if !x.reader.snapshot.closed {
					t.Error("append while pinned read transaction still open")
				}
			}
			status, header, body := x.request(t, f.Org, x.token, url.Values{"actorId": {f.Actor(f.AdminSubject)}, "requestReference": {"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"}})
			if status != 200 || !bytes.Contains(body, []byte(`"items":[{`)) || !a.CanonicalUUID(header.Get(a.RequestReferenceHeader)) || header.Get(a.RequestReferenceHeader) == f.OtherOrg || header.Get(a.RequestReferenceHeader) == "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa" {
				t.Fatal(status, string(body), header)
			}
			records := x.records(t)
			if len(records) != 1 {
				t.Fatal("exactly one completion", records)
			}
			got := records[0]
			if got.RecordID != header.Get(a.RequestReferenceHeader) || got.Method != activitymethoddata.AdminAccessLogs || got.ActorID != f.Actor(f.Subject) || got.DataOrg != f.Org || got.HTTP != 200 || got.Outcome != "success" || got.IP != "127.0.0.1" || got.Policy != x.policy || got.Configuration != hex.EncodeToString(x.cfg.Configuration[:]) {
				t.Fatal(got)
			}
			if got.ActorID == f.Actor(f.AdminSubject) || bytes.Contains([]byte(got.Method), []byte("?")) {
				t.Fatal("filter or caller header became audit attribution")
			}
		})
	}
}
func TestAuditConstructorAndCompletionFailuresReleaseNoProtectedBody(t *testing.T) {
	x := newAuditFixture(t)
	if _, e := NewHandler(x.service, nil); e == nil {
		t.Fatal("missing recorder admitted")
	}
	x.onCompletion = func() { x.recorded = time.Unix(-1, 0) }
	status, header, body := x.request(t, f.Org, x.token, nil)
	if status != 503 || bytes.Contains(body, []byte(`"items"`)) || header.Get(a.RequestReferenceHeader) != "" {
		t.Fatal(status, header, string(body))
	}
	x.onCompletion = nil
	x.recorded = time.Unix(f.Now, 0)
	status, _, _ = x.request(t, f.Org, x.token, nil)
	if status != 200 {
		t.Fatal("completion failure leaked admission", status)
	}
	if got := x.records(t); len(got) != 1 {
		t.Fatal("failed append invented record or retried", got)
	}
}
func TestBoundedFailuresNeverTrustARequestedOrganization(t *testing.T) {
	for _, test := range []struct {
		name, org, token string
		status           int
		query            url.Values
		actor            string
	}{
		{"foreign", f.OtherOrg, "valid", 403, nil, f.Actor(f.Subject)},
		{"invalid-token", f.Org, "invalid", 401, nil, ""},
		{"malformed", f.Org, "valid", 400, url.Values{"method": {"raw invalid query"}}, ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			x := newAuditFixture(t)
			token := test.token
			if token == "valid" {
				token = x.token
			}
			status, _, body := x.request(t, test.org, token, test.query)
			if status != test.status || bytes.Contains(body, []byte(`"items"`)) || x.reader.calls != 0 {
				t.Fatal(status, string(body), x.reader.calls)
			}
			records := x.records(t)
			if len(records) != 1 || records[0].DataOrg != "" || records[0].ActorID != test.actor {
				t.Fatal(records)
			}
		})
	}
}
func TestLateExpiryOrSourceFailureAfterDurableAppendNeverReleasesDataOrRecordsAgain(t *testing.T) {
	for _, late := range []string{"expiry", "source"} {
		t.Run(late, func(t *testing.T) {
			x := newAuditFixture(t)
			want := 503
			if late == "expiry" {
				want = 401
				x.onCompletion = func() { x.now = time.Unix(f.Now+301, 0) }
			} else {
				x.reader.snapshot.onCheck = func() {
					if x.reader.snapshot.checks == 2 {
						x.reader.snapshot.checkErr = ErrUnavailable
					}
				}
			}
			status, header, body := x.request(t, f.Org, x.token, nil)
			if status != want || bytes.Contains(body, []byte(`"items"`)) || !a.CanonicalUUID(header.Get(a.RequestReferenceHeader)) {
				t.Fatal(status, header, string(body))
			}
			records := x.records(t)
			if len(records) != 1 || records[0].HTTP != 200 || records[0].Outcome != "success" {
				t.Fatal("selected response is not delivery proof; no second completion", records)
			}
		})
	}
}

type deliveryWriter struct {
	header  http.Header
	status  int
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (w *deliveryWriter) Header() http.Header    { return w.header }
func (w *deliveryWriter) WriteHeader(status int) { w.status = status }
func (w *deliveryWriter) Write(raw []byte) (int, error) {
	if w.entered != nil {
		w.once.Do(func() { close(w.entered) })
		<-w.release
	}
	return len(raw), nil
}
func (*deliveryWriter) SetReadDeadline(time.Time) error  { return nil }
func (*deliveryWriter) SetWriteDeadline(time.Time) error { return nil }
func TestSlowDeliveryRetainsBoundedResponseWorkAndNoSlotLeaks(t *testing.T) {
	x := newAuditFixture(t)
	request := func() *http.Request {
		r := httptest.NewRequest("GET", "/api/v2/orgs/"+f.Org+"/access-logs?from="+url.QueryEscape(asTime((f.Now-10)*1000000))+"&to="+url.QueryEscape(asTime((f.Now+10)*1000000)), nil)
		r.SetPathValue("orgId", f.Org)
		r.Header.Set("Authorization", "Bearer "+x.token)
		return r
	}
	w := &deliveryWriter{header: http.Header{}, entered: make(chan struct{}), release: make(chan struct{})}
	done := make(chan struct{})
	go func() { defer close(done); x.handler.serve(w, request()) }()
	<-w.entered
	if len(x.handler.slots) != 1 || !a.CanonicalUUID(w.Header().Get(a.RequestReferenceHeader)) {
		t.Fatal("body not bounded after durable completion")
	}
	busy := &deliveryWriter{header: http.Header{}}
	x.handler.serve(busy, request())
	if busy.status != 503 || busy.header.Get(a.RequestReferenceHeader) != "" {
		t.Fatal("overload captured body/reference", busy.status)
	}
	close(w.release)
	<-done
	last := &deliveryWriter{header: http.Header{}}
	x.handler.serve(last, request())
	if last.status != 200 || len(x.handler.slots) != 0 {
		t.Fatal("response admission leaked", last.status)
	}
	if got := x.records(t); len(got) != 2 {
		t.Fatal("overload or delivery invented duplicate completions", got)
	}
}

func TestUnexpectedSourceUnwindingCompletesReservationOnce(t *testing.T) {
	x := newAuditFixture(t)
	request := func() *http.Request {
		r := httptest.NewRequest("GET", "/api/v2/orgs/"+f.Org+"/access-logs?from="+url.QueryEscape(asTime((f.Now-10)*1000000))+"&to="+url.QueryEscape(asTime((f.Now+10)*1000000)), nil)
		r.SetPathValue("orgId", f.Org)
		r.Header.Set("Authorization", "Bearer "+x.token)
		return r
	}
	x.reader.snapshot.onRead = func() { panic("public fixture source failure") }
	func() {
		defer func() {
			if recover() == nil {
				t.Error("expected source unwinding")
			}
		}()
		x.handler.serve(&deliveryWriter{header: http.Header{}}, request())
	}()
	if len(x.handler.slots) != 0 {
		t.Fatal("response capacity leaked")
	}
	x.reader.snapshot.onRead = nil
	w := &deliveryWriter{header: http.Header{}}
	x.handler.serve(w, request())
	if w.status != 200 {
		t.Fatal("recorder reservation leaked", w.status)
	}
	got := x.records(t)
	if len(got) != 2 || got[0].HTTP != 503 || got[0].Outcome != "unavailable" || got[1].HTTP != 200 {
		t.Fatal("unwinding completion was missing/repeated", got)
	}
}
