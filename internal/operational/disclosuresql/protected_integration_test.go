package disclosuresql_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	c "privacy-proxy/internal/disclosurecase"
	d "privacy-proxy/internal/disclosuredata"
	"privacy-proxy/internal/disclosurehttp"
	p "privacy-proxy/internal/disclosurepolicy"
	f "privacy-proxy/internal/disclosuretest"
	"privacy-proxy/internal/operational/disclosuresql"
	"privacy-proxy/internal/policybundle"
)

// These typed sources test the real case/SQL/HTTP boundary ONLY. They do not
// qualify an audit/history source or claim actual disclosed banking data.
type gateSources struct {
	plan        d.SourcePlan
	clock       *atomic.Int64
	opens       atomic.Int64
	reads       atomic.Int64
	beforeCheck func()
	afterArgs   chan *d.Position
}

func (s *gateSources) Plan() d.SourcePlan { return s.plan }
func (s *gateSources) Open(_ context.Context, scope d.ReadScope, refs []d.SourceRef) (d.Snapshot, error) {
	s.opens.Add(1)
	return &gateSnapshot{s: s, scope: scope}, nil
}

type gateSnapshot struct {
	s     *gateSources
	scope d.ReadScope
}

func (s *gateSnapshot) Descriptors() []d.SourceDescriptor {
	kind := d.ActivitySource
	return []d.SourceDescriptor{{Version: 1, Kind: kind, Reference: d.Digest("sha256:" + strings.Repeat("1", 64)), NetworkKey: s.s.plan.NetworkKey, Epoch: d.Digest("sha256:" + strings.Repeat("2", 64)), Generation: "33333333-3333-4333-8333-333333333333", PlanDigest: s.s.plan.PlanDigest, FormatDigest: d.Digest("sha256:" + strings.Repeat("3", 64)), CoverageDigest: d.Digest("sha256:" + strings.Repeat("4", 64)), AsOf: time.Unix(s.s.clock.Load(), 0).UTC(), Population: "RECORDED_RPC_COMPLETIONS_AS_OF_VECTOR"}}
}
func (s *gateSnapshot) Read(ctx context.Context, scope d.ReadScope, after *d.Position) (d.Facts, error) {
	s.s.reads.Add(1)
	if s.s.afterArgs != nil {
		s.s.afterArgs <- d.ClonePosition(after)
	}

	if scope.Query.Resource() == p.ActivityLogs {
		number := uint64(1)
		if after != nil {
			if after.Kind != d.ActivitySource || after.Activity == nil || after.Activity.CompletionOrdinal != "1" {
				return d.Facts{}, d.ErrUnavailable
			}
			number = 2
		}
		ordinal := d.Count(fmt.Sprint(number))
		at := time.Unix(f.Now-3+int64(number), 0).UTC()
		id := fmt.Sprintf("44444444-4444-4444-8444-%012d", number)
		fact := d.ActivityFact{Provenance: d.Provenance{Source: d.Digest("sha256:" + strings.Repeat("1", 64)), DataOrganizationID: scope.DataOrganizationID, TargetActorIDs: scope.Query.Scope().TargetActors, Kind: "AUTHENTICATED_RECORDED_REQUEST_DATA_ORG"}, ID: id, ProducerID: "55555555-5555-4555-8555-555555555555", RunID: "66666666-6666-4666-8666-666666666666", CompletionOrdinal: ordinal, ObservedAt: at, Method: "eth_call", StatusCode: 200}
		result := d.Facts{Activities: []d.ActivityFact{fact}, End: number == 2}
		if !result.End {
			result.Next = &d.Position{Kind: d.ActivitySource, Activity: &d.ActivityPosition{ObservedAtMicros: at.UnixMicro(), ProducerID: fact.ProducerID, RunID: fact.RunID, CompletionOrdinal: ordinal, RecordID: id}}
		}
		return result, nil
	}
	if scope.Query.Resource() != p.ActivitySummary {
		return d.Facts{}, d.ErrUnavailable
	}

	return d.Facts{End: true, ActivitySummary: &d.ActivityAggregate{Total: "20000", Successful: "19999", Failed: "1", Methods: []d.MethodCount{{Method: "eth_call", Total: "20000", Successful: "19999", Failed: "1"}}}}, nil
}
func (s *gateSnapshot) CheckCurrent(context.Context) error {
	if s.s.beforeCheck != nil {
		s.s.beforeCheck()
	}
	return nil
}
func (s *gateSnapshot) Close() {}
func newGateService(t *testing.T, snapshot *policybundle.CatalogSnapshot, store c.Store, clock *atomic.Int64) (*c.Service, *gateSources, c.Config, c.DataConfig) {
	t.Helper()
	network := d.NetworkBinding{Environment: "test", ChainID: "1", GenesisHash: "0x" + strings.Repeat("0", 63) + "1", DeploymentID: "gate-test"}
	key, _ := network.Key()
	sources := &gateSources{clock: clock, plan: d.SourcePlan{Version: 1, Profile: "ops.disclosure.data-sources/v1", BundleDigest: d.Digest(snapshot.Metadata().ManifestDigest), NetworkKey: d.Digest("sha256:" + hex.EncodeToString(key[:])), PlanDigest: d.Digest("sha256:" + strings.Repeat("a", 64)), Resources: []p.Resource{p.ActivityLogs, p.ActivitySummary, p.Transactions}}}
	cfg := c.Config{Snapshot: snapshot, Clock: func() time.Time { return time.Unix(clock.Load(), 0) }, Store: store, StoreEpoch: "gate-epoch", CursorKeys: c.CursorKeys{Active: c.CursorKey{ID: "admin", Key: bytes.Repeat([]byte{3}, 32)}}}
	dc := c.DataConfig{Network: network, Sources: sources, RenderKeys: d.Keys{Active: d.Key{ID: "render", Bytes: bytes.Repeat([]byte{1}, 32)}}, CursorKeys: d.Keys{Active: d.Key{ID: "data", Bytes: bytes.Repeat([]byte{2}, 32)}}}
	service, e := c.NewWithData(cfg, dc)
	if e != nil {
		t.Fatal(e)
	}
	return service, sources, cfg, dc
}
func openGateCase(t *testing.T, service *c.Service, token string, resources []p.Resource, level p.Level) c.CaseResponse {
	t.Helper()
	scope := f.Scope()
	scope.Resources = resources
	scope.Level = level
	response, e := service.Create(t.Context(), token, c.CreateRequest{RuleID: "auditor", RecipientActorID: f.Actor(f.Subject), CaseReference: "BANK-CASE", Purpose: "Approved institution review", Scope: scope, ExpiresAt: f.Now + 1200, IdempotencyKey: uuid.NewString()})
	if e != nil {
		t.Fatal(e)
	}
	var raw bytes.Buffer
	if _, e := response.WriteTo(&raw); e != nil {
		t.Fatal(e)
	}
	var opened c.CaseResponse
	if e := json.Unmarshal(raw.Bytes(), &opened); e != nil {
		t.Fatal(e)
	}
	return opened
}
func summaryQuery() d.Query { return d.Query{Version: 1, Resource: p.ActivitySummary, View: d.Report} }

type lostExposureStore struct{ c.Store }

func (s lostExposureStore) WithLockedCase(ctx context.Context, id, epoch string, version int64, callback func(c.Case) (c.Event, error)) (c.CommitReceipt, error) {
	_, e := s.Store.WithLockedCase(ctx, id, epoch, version, callback)
	if e != nil {
		return c.CommitReceipt{}, e
	}
	return c.CommitReceipt{}, c.ErrUnavailable
}
func TestActualProtectedExposureBeforeBytesAndCurrentWholeRule(t *testing.T) {
	_, app, _, owner := database(t)
	store, e := disclosuresql.Open(t.Context(), app)
	if e != nil {
		t.Fatal(e)
	}
	defer store.Close()
	rule := f.DefaultRule()
	rule.MaxLevel = p.Full
	snapshot := f.Snapshot(t, []p.RuleSource{rule})
	clock := &atomic.Int64{}
	clock.Store(f.Now)
	service, sources, cfg, dc := newGateService(t, snapshot, store, clock)
	token := f.Token(t, snapshot, f.Subject, "Auditor")
	opened := openGateCase(t, service, token, []p.Resource{p.ActivitySummary, p.Transactions}, p.Full)
	response, e := service.Read(t.Context(), token, opened.CaseID, summaryQuery())
	if e != nil {
		t.Fatal(e)
	}
	var action string
	var summary []byte
	var attempt string
	if e := owner.QueryRow(t.Context(), `SELECT action,summary::text,attempt_id::text FROM ops_v2.disclosure_events WHERE case_id=$1::uuid AND action='exposure_prepared' ORDER BY prepared_at DESC,event_id LIMIT 1`, opened.CaseID).Scan(&action, &summary, &attempt); e != nil {
		t.Fatal("no durable event before caller gets bytes", e)
	}
	var envelope struct {
		Count    int               `json:"count"`
		Exposure c.ExposureSummary `json:"exposure"`
	}
	if e := json.Unmarshal(summary, &envelope); e != nil {
		t.Fatal(e)
	}
	var raw bytes.Buffer
	if _, e := response.WriteTo(&raw); e != nil {
		t.Fatal(e)
	}
	hash := sha256.Sum256(raw.Bytes())
	if action != "exposure_prepared" || envelope.Exposure.OutputDigest != "sha256:"+hex.EncodeToString(hash[:]) || envelope.Exposure.OutputBytes != uint32(raw.Len()) || envelope.Count != 1 {
		t.Fatal("receipt did not bind exact newline output", string(summary))
	}
	var out struct {
		ReadID string `json:"readId"`
		Result struct {
			Total string `json:"total"`
		} `json:"result"`
	}
	_ = json.Unmarshal(raw.Bytes(), &out)
	if out.ReadID != attempt || out.Result.Total != "20000" {
		t.Fatal("wrong receipt or first-N aggregate", raw.String())
	}
	t.Run("metadata admin is not data recipient", func(t *testing.T) {
		admin := f.Token(t, snapshot, f.AdminSubject, "Admin")
		if _, e := service.Get(t.Context(), admin, opened.CaseID); e != nil {
			t.Fatal("metadata denied", e)
		}
		before := sources.opens.Load()
		if _, e := service.Read(t.Context(), admin, opened.CaseID, summaryQuery()); !errors.Is(e, c.ErrNotFound) || sources.opens.Load() != before {
			t.Fatal("admin bypass reached data", e)
		}
	})
	t.Run("query narrowing cannot repair whole rule", func(t *testing.T) {
		narrow := rule
		narrow.Resources = []p.Resource{p.ActivitySummary}
		current := f.Snapshot(t, []p.RuleSource{narrow})
		newService, newSources, _, _ := newGateService(t, current, store, clock)
		if _, e := newService.Read(t.Context(), f.Token(t, current, f.Subject, "Auditor"), opened.CaseID, summaryQuery()); !errors.Is(e, c.ErrNotFound) || newSources.opens.Load() != 0 {
			t.Fatal("narrow query waived original transactions scope", e)
		}
	})
	t.Run("ambiguous committed receipt releases no bytes", func(t *testing.T) {
		copyCfg := cfg
		copyCfg.Store = lostExposureStore{store}
		lost, e := c.NewWithData(copyCfg, dc)
		if e != nil {
			t.Fatal(e)
		}
		before := count(t, owner, "disclosure_events")
		got, e := lost.Read(t.Context(), token, opened.CaseID, summaryQuery())
		if got != nil || !errors.Is(e, c.ErrUnavailable) || count(t, owner, "disclosure_events") != before+1 {
			t.Fatal("unknown commit sent or lost preparation", got, e)
		}
	})
	t.Run("prepared but expired output stays unsent", func(t *testing.T) {
		prepared, e := service.Read(t.Context(), token, opened.CaseID, summaryQuery())
		if e != nil {
			t.Fatal(e)
		}
		clock.Store(f.Now + 400)
		var dst bytes.Buffer
		if _, e := prepared.WriteTo(&dst); e == nil || dst.Len() != 0 {
			t.Fatal("final expiry gate failed", e)
		}
		clock.Store(f.Now)
	})
	t.Run("strong network namespace not old metadata", func(t *testing.T) {
		old, e := c.New(cfg)
		if e != nil {
			t.Fatal(e)
		}
		if _, e := old.Get(t.Context(), token, opened.CaseID); !errors.Is(e, c.ErrNotFound) {
			t.Fatal("weak namespace promoted", e)
		}
		if _, e := disclosurehttp.New(service); e == nil {
			t.Fatal("legacy handler bypasses shared admission")
		}
	})

	t.Run("Full prelookup gate precedes malformed values", func(t *testing.T) {
		limited := openGateCase(t, service, token, []p.Resource{p.Transactions}, p.Pseudonymous)
		before := sources.opens.Load()
		q := d.Query{Version: 1, Resource: p.Transactions, View: d.Detail, TransactionHash: ptrString("malformed")}
		if _, e := service.Read(t.Context(), token, limited.CaseID, q); !errors.Is(e, c.ErrNotFound) || sources.opens.Load() != before {
			t.Fatal("lower detail touched parser/provider", e)
		}
	})
	t.Run("audit insert failure sends no bytes", func(t *testing.T) {
		_, e := owner.Exec(t.Context(), `CREATE FUNCTION ops_v2.test_fail_exposure() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN IF NEW.action='exposure_prepared' THEN RAISE EXCEPTION 'owned test failure'; END IF;RETURN NEW;END$$;CREATE TRIGGER test_fail_exposure BEFORE INSERT ON ops_v2.disclosure_events FOR EACH ROW EXECUTE FUNCTION ops_v2.test_fail_exposure()`)
		if e != nil {
			t.Fatal(e)
		}
		before := count(t, owner, "disclosure_events")
		result, e := service.Read(t.Context(), token, opened.CaseID, summaryQuery())
		if result != nil || !errors.Is(e, c.ErrUnavailable) || count(t, owner, "disclosure_events") != before {
			t.Fatal("failed audit released output or persisted partial event", result, e)
		}
		if _, e := owner.Exec(t.Context(), `DROP TRIGGER test_fail_exposure ON ops_v2.disclosure_events;DROP FUNCTION ops_v2.test_fail_exposure()`); e != nil {
			t.Fatal(e)
		}
	})
	t.Run("revoke before final exposure lock wins", func(t *testing.T) {
		other := openGateCase(t, service, token, []p.Resource{p.ActivitySummary}, p.Redacted)
		before := count(t, owner, "disclosure_events")
		sources.beforeCheck = func() {
			if _, e := service.Revoke(t.Context(), token, other.CaseID, "withdraw before exposure"); e != nil {
				t.Fatal(e)
			}
		}
		got, e := service.Read(t.Context(), token, other.CaseID, summaryQuery())
		sources.beforeCheck = nil
		if got != nil || !errors.Is(e, c.ErrConflict) || count(t, owner, "disclosure_events") != before+1 {
			t.Fatal("stale unlocked preparation crossed revoke", got, e)
		}
	})
	t.Run("revoked case fails before source", func(t *testing.T) {
		if _, e := service.Revoke(t.Context(), token, opened.CaseID, "engagement ended"); e != nil {
			t.Fatal(e)
		}
		before := sources.opens.Load()
		if _, e := service.Read(t.Context(), token, opened.CaseID, summaryQuery()); !errors.Is(e, c.ErrNotFound) || sources.opens.Load() != before {
			t.Fatal("revoked case reached data source", e)
		}
	})
}
func TestActualProtectedTLSPostReportAndLegacySummary(t *testing.T) {
	_, app, _, owner := database(t)
	store, e := disclosuresql.Open(t.Context(), app)
	if e != nil {
		t.Fatal(e)
	}
	defer store.Close()
	snapshot := f.Snapshot(t, nil)
	clock := &atomic.Int64{}
	clock.Store(f.Now)
	service, _, _, _ := newGateService(t, snapshot, store, clock)
	token := f.Token(t, snapshot, f.Subject, "Auditor")
	opened := openGateCase(t, service, token, []p.Resource{p.ActivitySummary}, p.Redacted)
	h, e := disclosurehttp.NewWithData(service)
	if e != nil {
		t.Fatal(e)
	}
	mux := http.NewServeMux()
	h.Register(mux)
	server := httptest.NewTLSServer(mux)
	defer server.Close()
	body, _ := json.Marshal(summaryQuery())
	req, _ := http.NewRequestWithContext(t.Context(), "POST", server.URL+"/api/v1/disclosure/cases/"+opened.CaseID+"/read", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, e := server.Client().Do(req)
	if e != nil {
		t.Fatal(e)
	}
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || resp.Header.Get("Content-Disposition") != `attachment; filename="ops-disclosure-report.json"` || !bytes.Contains(raw, []byte(`"total":"20000"`)) {
		t.Fatal(resp.StatusCode, resp.Header, string(raw))
	}
	if resp.Header.Get("Cache-Control") != "no-store" {
		t.Fatal("cache exposure")
	}
	for _, method := range []string{"GET", "HEAD", "OPTIONS"} {
		r, _ := http.NewRequestWithContext(t.Context(), method, req.URL.String(), nil)
		r.Header.Set("Authorization", "Bearer "+token)
		p, e := server.Client().Do(r)
		if e != nil {
			t.Fatal(e)
		}
		io.Copy(io.Discard, p.Body)
		p.Body.Close()
		if p.StatusCode < 400 {
			t.Fatal("extra report route", method, p.StatusCode)
		}
	}
	audit, e := service.Audit(t.Context(), token, opened.CaseID, "", 50)
	if e != nil {
		t.Fatal("new and legacy summaries could not be read", e)
	}
	var auditBytes bytes.Buffer
	if _, e := audit.WriteTo(&auditBytes); e != nil {
		t.Fatal(e)
	}
	if bytes.Contains(auditBytes.Bytes(), []byte("outputDigest")) || bytes.Contains(auditBytes.Bytes(), []byte("sourceSetDigest")) {
		t.Fatal("private receipt metadata leaked through audit projection")
	}
	var stored string
	if e := owner.QueryRow(t.Context(), `SELECT summary::text FROM ops_v2.disclosure_events WHERE case_id=$1::uuid AND action='case_opened'`, opened.CaseID).Scan(&stored); e != nil {
		t.Fatal(e)
	}
	if strings.Contains(stored, "exposure") {
		t.Fatal("legacy metadata summary changed", stored)
	}
}

type blockedCaseGet struct {
	c.Store
	enabled atomic.Bool
	entered chan struct{}
	release chan struct{}
	gets    atomic.Int64
}

func (s *blockedCaseGet) Get(ctx context.Context, id, epoch string) (c.Case, error) {
	s.gets.Add(1)
	if s.enabled.Load() {
		select {
		case s.entered <- struct{}{}:
		case <-ctx.Done():
			return c.Case{}, c.ErrUnavailable
		}
		select {
		case <-s.release:
		case <-ctx.Done():
			return c.Case{}, c.ErrUnavailable
		}
	}
	return s.Store.Get(ctx, id, epoch)
}
func dataTLSServer(t *testing.T, service *c.Service) *httptest.Server {
	t.Helper()
	h, e := disclosurehttp.NewWithData(service)
	if e != nil {
		t.Fatal(e)
	}
	mux := http.NewServeMux()
	h.Register(mux)
	srv := httptest.NewUnstartedServer(mux)
	srv.Config.ReadHeaderTimeout = 2 * time.Second
	srv.Config.ReadTimeout = 5 * time.Second
	srv.Config.WriteTimeout = 7 * time.Second
	srv.Config.IdleTimeout = 30 * time.Second
	srv.Config.MaxHeaderBytes = 64 << 10
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}
func TestActualProtectedSharedHTTPAdmissionAndBodyDeadline(t *testing.T) {
	_, app, _, _ := database(t)
	store, e := disclosuresql.Open(t.Context(), app)
	if e != nil {
		t.Fatal(e)
	}
	defer store.Close()
	snapshot := f.Snapshot(t, nil)
	clock := &atomic.Int64{}
	clock.Store(f.Now)
	blocked := &blockedCaseGet{Store: store, entered: make(chan struct{}, 8), release: make(chan struct{})}
	service, sources, _, _ := newGateService(t, snapshot, blocked, clock)
	token := f.Token(t, snapshot, f.Subject, "Auditor")
	opened := openGateCase(t, service, token, []p.Resource{p.ActivitySummary}, p.Redacted)
	a, b := dataTLSServer(t, service), dataTLSServer(t, service)
	body, _ := json.Marshal(summaryQuery())
	path := "/api/v1/disclosure/cases/" + opened.CaseID + "/read"
	do := func(s *httptest.Server, method, path string, raw []byte) (int, error) {
		req, e := http.NewRequestWithContext(t.Context(), method, s.URL+path, bytes.NewReader(raw))
		if e != nil {
			return 0, e
		}
		req.Header.Set("Authorization", "Bearer "+token)
		if method == "POST" {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, e := s.Client().Do(req)
		if e != nil {
			return 0, e
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		return resp.StatusCode, nil
	}
	blocked.enabled.Store(true)
	done := make(chan error, 8)
	for i := 0; i < 8; i++ {
		srv := a
		if i%2 != 0 {
			srv = b
		}
		go func() {
			code, e := do(srv, "POST", path, body)
			if e == nil && code != 200 {
				e = fmt.Errorf("admitted status %d", code)
			}
			done <- e
		}()
	}
	wait, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	for i := 0; i < 8; i++ {
		select {
		case <-blocked.entered:
		case <-wait.Done():
			close(blocked.release)
			t.Fatal("eight admitted requests did not reach held store")
		}
	}
	before := blocked.gets.Load()
	for _, row := range []struct {
		method, path string
		body         []byte
	}{{"POST", path, body}, {"GET", "/api/v1/disclosure/cases/" + opened.CaseID, nil}, {"POST", "/api/v1/disclosure/cases/" + opened.CaseID + "/revoke", []byte(`{"reason":"test"}`)}} {
		code, e := do(b, row.method, row.path, row.body)
		if e != nil || code != 503 || blocked.gets.Load() != before {
			close(blocked.release)
			t.Fatal("ninth operation escaped shared service admission", code, e)
		}
	}
	close(blocked.release)
	for i := 0; i < 8; i++ {
		if e := <-done; e != nil {
			t.Fatal(e)
		}
	}
	blocked.enabled.Store(false)
	if code, e := do(a, "GET", "/api/v1/disclosure/cases/"+opened.CaseID, nil); e != nil || code != 200 {
		t.Fatal("admission did not recover", code, e)
	}
	beforeSource := sources.opens.Load()
	beforeStore := blocked.gets.Load()
	target, _ := url.Parse(a.URL)
	conn, e := tls.Dial("tcp", target.Host, &tls.Config{InsecureSkipVerify: true})
	if e != nil {
		t.Fatal(e)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(8 * time.Second))
	start := time.Now()
	_, e = fmt.Fprintf(conn, "POST %s HTTP/1.1\r\nHost: %s\r\nAuthorization: Bearer %s\r\nContent-Type: application/json\r\nContent-Length: 1000\r\n\r\n{", path, target.Host, token)
	if e != nil {
		t.Fatal(e)
	}
	line, e := bufio.NewReader(conn).ReadString('\n')
	elapsed := time.Since(start)
	// At the shared read/write deadline the server may close TLS without
	// an error body; no write is permitted after that same deadline.
	boundedClose := e != nil && (errors.Is(e, io.EOF) || strings.Contains(e.Error(), "tls: bad record MAC") || strings.Contains(e.Error(), "connection reset") || strings.Contains(e.Error(), "closed network connection"))
	if e != nil && !boundedClose || e == nil && !strings.Contains(line, "400") && !strings.Contains(line, "503") || elapsed < 4*time.Second || elapsed > 7*time.Second || sources.opens.Load() != beforeSource || blocked.gets.Load() != beforeStore {
		t.Fatal("incomplete body not bounded before source", line, e, elapsed)
	}
	held := []func(){}
	for i := 0; i < 8; i++ {
		release, ok := service.TryAdmitHTTP()
		if !ok {
			for _, r := range held {
				r()
			}
			t.Fatal("deadline leaked an admission slot")
		}
		held = append(held, release)
	}
	for _, release := range held {
		release()
	}
}
func ptrString(s string) *string { return &s }

func TestActualProtectedCursorPassesAuthenticatedAfterWithoutClockChurn(t *testing.T) {
	_, app, _, _ := database(t)
	store, e := disclosuresql.Open(t.Context(), app)
	if e != nil {
		t.Fatal(e)
	}
	defer store.Close()
	rule := f.DefaultRule()
	rule.Resources = []p.Resource{p.ActivityLogs}
	snapshot := f.Snapshot(t, []p.RuleSource{rule})
	clock := &atomic.Int64{}
	clock.Store(f.Now)
	service, sources, _, _ := newGateService(t, snapshot, store, clock)
	sources.afterArgs = make(chan *d.Position, 2)
	token := f.Token(t, snapshot, f.Subject, "Auditor")
	opened := openGateCase(t, service, token, []p.Resource{p.ActivityLogs}, p.Redacted)
	limit := uint16(1)
	q := d.Query{Version: 1, Resource: p.ActivityLogs, View: d.List, Limit: &limit}
	first, e := service.Read(t.Context(), token, opened.CaseID, q)
	if e != nil {
		t.Fatal(e)
	}
	var raw bytes.Buffer
	first.WriteTo(&raw)
	var page struct {
		Result struct {
			Items []struct {
				ID string `json:"recordId"`
			} `json:"items"`
			Next *string `json:"nextCursor"`
		} `json:"result"`
	}
	if json.Unmarshal(raw.Bytes(), &page) != nil || page.Result.Next == nil || len(page.Result.Items) != 1 {
		t.Fatal(raw.String())
	}
	if after := <-sources.afterArgs; after != nil {
		t.Fatal("first source page got an after key")
	}
	firstID := page.Result.Items[0].ID
	clock.Store(f.Now + 1)
	q.Cursor = page.Result.Next
	second, e := service.Read(t.Context(), token, opened.CaseID, q)
	if e != nil {
		t.Fatal("unchanged facts/cuts with later AsOf failed", e)
	}
	raw.Reset()
	second.WriteTo(&raw)
	page.Result.Next = nil
	if e := json.Unmarshal(raw.Bytes(), &page); e != nil {
		t.Fatal(e)
	}
	after := <-sources.afterArgs
	if after == nil || after.Activity == nil || after.Activity.CompletionOrdinal != "1" || after.Activity.RecordID != firstID || page.Result.Next != nil || len(page.Result.Items) != 1 || page.Result.Items[0].ID == firstID {
		t.Fatal("authenticated resume key lost/duplicated", after, raw.String())
	}
}
