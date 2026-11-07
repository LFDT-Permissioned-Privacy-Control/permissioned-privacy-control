package activitysql_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	a "privacy-proxy/internal/activitylog"
	"privacy-proxy/internal/audit/buffer"
	c "privacy-proxy/internal/disclosurecase"
	d "privacy-proxy/internal/disclosuredata"
	"privacy-proxy/internal/disclosurehttp"
	p "privacy-proxy/internal/disclosurepolicy"
	f "privacy-proxy/internal/disclosuretest"
	"privacy-proxy/internal/operational/activitysource"
	s "privacy-proxy/internal/operational/activitysql"
	"privacy-proxy/internal/operational/disclosuresql"
)

func attributed(t *testing.T, entry buffer.Entry, method string, success bool) buffer.Entry {
	t.Helper()
	record, err := a.DecodeSpool(entry.Data)
	if err != nil {
		t.Fatal(err)
	}
	e := record.Fields()
	e.ActorID = f.Actor(f.Subject)
	e.DataOrg = f.Org
	e.Method = method
	e.BufferSeq = "1"
	if success {
		e.Outcome = string(a.Success)
		e.Status = 200
		e.HTTP = 200
		e.RPCError = nil
	}
	raw, _ := json.Marshal(e)
	entry.Data = append(append([]byte{}, raw[:len(raw)-len(`,"b":"1"}`)]...), '}')
	if _, err := a.DecodeSpool(entry.Data); err != nil {
		t.Fatal(err)
	}
	return entry
}
func readQuery(from, through int64, limit int) s.ReadQuery {
	return s.ReadQuery{Organization: f.Org, Actors: []string{f.Actor(f.Subject)}, FromMicros: from, ThroughMicros: through, Limit: limit}
}
func TestActualReaderImmutableHeadOrderingTimeAndWholeAggregate(t *testing.T) {
	x := setupDatabase(t)
	ctx := t.Context()
	writer, err := s.OpenWriter(ctx, x.writer, x.scope)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	reader, err := s.OpenReader(ctx, x.reader, x.scope)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	zero, err := reader.Open(ctx, "", 0)
	if err != nil {
		t.Fatal(err)
	}
	emptyRef := zero.Cut().Reference
	page, end, err := zero.ReadPage(ctx, readQuery(0, a.MaxObservedMicros, 2), nil)
	if err != nil || !end || len(page) != 0 {
		t.Fatal("explicit zero SQL prefix", page, end, err)
	}
	zero.Close()
	producer := uuid.NewString()
	low, err := writer.StartRun(ctx, a.RunRequest{ProducerID: producer, RunID: uuid.NewString()})
	if err != nil {
		t.Fatal(err)
	}
	high, err := writer.StartRun(ctx, a.RunRequest{ProducerID: uuid.NewString(), RunID: uuid.NewString()})
	if err != nil {
		t.Fatal(err)
	}
	const at = int64(1700000000000000)
	entries := []buffer.Entry{attributed(t, testEntry(t, high.Binding(), 1, at), "eth_call", true), attributed(t, testEntry(t, high.Binding(), 2, at+1000000), "eth_call", false), attributed(t, testEntry(t, high.Binding(), 3, at+1000001), "eth_sendRawTransaction", true)}
	if err := high.SealBatch(ctx, entries); err != nil {
		t.Fatal(err)
	}
	cut, err := reader.Open(ctx, "", at)
	if err != nil {
		t.Fatal(err)
	}
	reference := cut.Cut().Reference
	cut.Close()
	// A lower range sealing LATER must allocate larger chain IDs and cannot
	// appear below an already named immutable head.
	if err := low.SealOne(ctx, low.Binding().Base+1, attributed(t, testEntry(t, low.Binding(), 1, at), "eth_call", true).Data); err != nil {
		t.Fatal(err)
	}
	pinned, err := reader.Open(ctx, reference, at)
	if err != nil {
		t.Fatal(err)
	}
	first, end, err := pinned.ReadPage(ctx, readQuery(at, at+1000000, 1), nil)
	if err != nil || end || len(first) != 1 {
		t.Fatal(first, end, err)
	}
	e := first[0].Envelope
	pinned.Close()
	resume, err := reader.Open(ctx, reference, at)
	if err != nil {
		t.Fatal(err)
	}
	second, end, err := resume.ReadPage(ctx, readQuery(at, at+1000000, 1), &s.PageKey{ObservedMicros: e.ObservedMicros, ProducerID: e.ProducerID, RunID: e.RunID, Ordinal: 1, RecordID: e.RecordID})
	if err != nil || !end || len(second) != 1 || second[0].Envelope.ObservedMicros != at+1000000 {
		t.Fatal("authenticated after/inclusive exact end", second, end, err)
	}
	resume.Close()
	if err := resume.CheckCurrent(ctx); err != nil {
		t.Fatal("later head growth invalidated old cut", err)
	}
	oldEmpty, err := reader.Open(ctx, emptyRef, 0)
	if err != nil {
		t.Fatal(err)
	}
	empty, end, err := oldEmpty.ReadPage(ctx, readQuery(0, a.MaxObservedMicros, 2), nil)
	oldEmpty.Close()
	if err != nil || !end || len(empty) != 0 {
		t.Fatal("old explicit zero grew", empty, end, err)
	}
	// More than10k rows over a month are counted by the actual same-scope
	// aggregate, without a first-N sample or per-day/block splitting.
	for base := int64(4); base < 10020; base += 512 {
		n := min(int64(512), 10020-base)
		batch := make([]buffer.Entry, 0, n)
		for i := int64(0); i < n; i++ {
			ordinal := base + i
			batch = append(batch, attributed(t, testEntry(t, high.Binding(), ordinal, at+2000000), "eth_call", ordinal%2 == 0))
		}
		if err := high.SealBatch(ctx, batch); err != nil {
			t.Fatal("bounded aggregate fixture batch", base, err)
		}
	}
	report, err := reader.Open(ctx, "", at-31*86400*1000000)
	if err != nil {
		t.Fatal(err)
	}
	methods, err := report.Summary(ctx, readQuery(at-31*86400*1000000, at+3000000, 0))
	report.Close()
	var total uint64
	for _, m := range methods {
		total += m.Total
	}
	if err != nil || total != 10020 {
		t.Fatal("whole month SEALED aggregate", total, methods, err)
	}
	oldReport, err := reader.Open(ctx, reference, at)
	if err != nil {
		t.Fatal(err)
	}
	methods, err = oldReport.Summary(ctx, readQuery(at, at+1000000, 0))
	oldReport.Close()
	if err != nil || len(methods) != 1 || methods[0].Total != 2 || methods[0].Successful != 1 || methods[0].Failed != 1 {
		t.Fatal("old head/end+1us/HTTP200RPCerror", methods, err)
	}
	for base := int64(10020); base < 10533; base += 512 {
		n := min(int64(512), 10533-base)
		batch := make([]buffer.Entry, 0, n)
		for i := int64(0); i < n; i++ {
			ordinal := base + i
			batch = append(batch, attributed(t, testEntry(t, high.Binding(), ordinal, at+2000000), "method"+strconv.FormatInt(ordinal, 10), true))
		}
		if err := high.SealBatch(ctx, batch); err != nil {
			t.Fatal(err)
		}
	}
	tooMany, err := reader.Open(ctx, "", at)
	if err != nil {
		t.Fatal(err)
	}
	_, err = tooMany.Summary(ctx, readQuery(at, at+3000000, 0))
	tooMany.Close()
	if !errors.Is(err, a.ErrTooBroad) {
		t.Fatal("513-group sentinel silently truncated", err)
	}
}

func TestActualActivitySourceCaseSQLTLSAuditBeforeProtectedBytes(t *testing.T) {
	x := setupDatabase(t)
	ctx := t.Context()
	writer, err := s.OpenWriter(ctx, x.writer, x.scope)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	run, err := writer.StartRun(ctx, a.RunRequest{ProducerID: uuid.NewString(), RunID: uuid.NewString()})
	if err != nil {
		t.Fatal(err)
	}
	entries := []buffer.Entry{attributed(t, testEntry(t, run.Binding(), 1, (f.Now-2)*1000000), "eth_call", true), attributed(t, testEntry(t, run.Binding(), 2, (f.Now-1)*1000000), "eth_call", false)}
	if err := run.SealBatch(ctx, entries); err != nil {
		t.Fatal(err)
	}
	reader, err := s.OpenReader(ctx, x.reader, x.scope)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	for _, role := range []string{"case_app", "case_retention"} {
		if _, err := x.owner.Exec(ctx, `CREATE ROLE `+pgx.Identifier{role}.Sanitize()+` LOGIN PASSWORD 'activity-public-test-only'`); err != nil {
			t.Fatal(err)
		}
	}
	// Cases and the lean activity audit population are separate named DBs on
	// this owned server. Neither runtime role gains the other's permissions.
	if _, err := x.owner.Exec(ctx, `CREATE DATABASE activity_cases`); err != nil {
		t.Fatal(err)
	}
	caseURL, _ := url.Parse(x.dsn)
	caseURL.Path = "/activity_cases"
	caseDSN := caseURL.String()
	caseOwner, err := pgx.Connect(ctx, caseDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer caseOwner.Close(ctx)
	if err := disclosuresql.Migrate(ctx, caseDSN, "case_app", "case_retention"); err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(caseDSN)
	u.User = url.UserPassword("case_app", "activity-public-test-only")
	store, err := disclosuresql.Open(ctx, u.String())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	rule := f.DefaultRule()
	rule.Resources = []p.Resource{p.ActivityLogs, p.ActivitySummary}
	rule.MaxLevel = p.Full
	snapshot := f.Snapshot(t, []p.RuleSource{rule})
	network, _ := x.registration.Network.Key()
	plan := d.SourcePlan{Version: 1, Profile: "ops.disclosure.data-sources/v1", BundleDigest: d.Digest(snapshot.Metadata().ManifestDigest), NetworkKey: d.Digest("sha256:" + hex.EncodeToString(network[:])), PlanDigest: d.Digest("sha256:" + strings.Repeat("a", 64)), Resources: []p.Resource{p.ActivityLogs, p.ActivitySummary}}
	source, err := activitysource.New(reader, plan)
	if err != nil {
		t.Fatal(err)
	}
	clock := time.Unix(f.Now, 0).UTC()
	service, err := c.NewWithData(c.Config{Snapshot: snapshot, Clock: func() time.Time { return clock }, Store: store, StoreEpoch: "activity-cases", CursorKeys: c.CursorKeys{Active: c.CursorKey{ID: "admin", Key: bytes.Repeat([]byte{3}, 32)}}}, c.DataConfig{Network: x.registration.Network, Sources: source, RenderKeys: d.Keys{Active: d.Key{ID: "render", Bytes: bytes.Repeat([]byte{1}, 32)}}, CursorKeys: d.Keys{Active: d.Key{ID: "data", Bytes: bytes.Repeat([]byte{2}, 32)}}})
	if err != nil {
		t.Fatal(err)
	}
	token := f.Token(t, snapshot, f.Subject, "Auditor")
	scope := f.Scope()
	scope.Resources = rule.Resources
	scope.Level = p.Full
	created, err := service.Create(ctx, token, c.CreateRequest{RuleID: "auditor", RecipientActorID: f.Actor(f.Subject), CaseReference: "SEALED-TEST", Purpose: "Institution-approved metadata review", Scope: scope, ExpiresAt: f.Now + 1200, IdempotencyKey: uuid.NewString()})
	if err != nil {
		t.Fatal(err)
	}
	var opened c.CaseResponse
	var body bytes.Buffer
	if _, err := created.WriteTo(&body); err != nil {
		t.Fatal(err)
	}
	if json.Unmarshal(body.Bytes(), &opened) != nil {
		t.Fatal(body.String())
	}
	handler, err := disclosurehttp.NewWithData(service)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	handler.Register(mux)
	server := httptest.NewTLSServer(mux)
	defer server.Close()
	request := func(q d.Query) (int, []byte) {
		raw, _ := json.Marshal(q)
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, server.URL+"/api/v1/disclosure/cases/"+opened.CaseID+"/read", bytes.NewReader(raw))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		response, err := server.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		out, err := io.ReadAll(io.LimitReader(response.Body, 2<<20))
		if err != nil {
			t.Fatal(err)
		}
		if response.StatusCode == 200 && response.Header.Get("Cache-Control") != "no-store" {
			t.Fatal("missing no-store")
		}
		return response.StatusCode, out
	}
	code, out := request(d.Query{Version: 1, Resource: p.ActivitySummary, View: d.Report})
	if code != 200 {
		t.Fatal(code, string(out))
	}
	var summary struct {
		Exposure *c.ExposureSummary `json:"exposure"`
	}
	var audit []byte
	if caseOwner.QueryRow(ctx, `SELECT summary::text FROM ops_v2.disclosure_events WHERE case_id=$1::uuid AND action='exposure_prepared' ORDER BY prepared_at DESC,event_id DESC LIMIT 1`, opened.CaseID).Scan(&audit) != nil || json.Unmarshal(audit, &summary) != nil || summary.Exposure == nil {
		t.Fatal("durable audit missing", string(audit))
	}
	hash := sha256.Sum256(out)
	if summary.Exposure.OutputDigest != "sha256:"+hex.EncodeToString(hash[:]) || summary.Exposure.OutputBytes != uint32(len(out)) {
		t.Fatal("audit did not bind exact actual-source bytes", string(audit))
	}
	var rendered struct {
		Result struct {
			Total string `json:"total"`
		}
	}
	if json.Unmarshal(out, &rendered) != nil || rendered.Result.Total != "2" {
		t.Fatal("wrong complete SEALED population", string(out))
	}
	limit := uint16(1)
	code, first := request(d.Query{Version: 1, Resource: p.ActivityLogs, View: d.List, Limit: &limit})
	if code != 200 {
		t.Fatal(code, string(first))
	}
	var firstPage struct {
		Result struct {
			Items []json.RawMessage `json:"items"`
			Next  *string           `json:"nextCursor"`
		}
	}
	if json.Unmarshal(first, &firstPage) != nil || firstPage.Result.Next == nil || len(firstPage.Result.Items) != 1 {
		t.Fatal(string(first))
	}
	clock = clock.Add(time.Second)
	code, second := request(d.Query{Version: 1, Resource: p.ActivityLogs, View: d.List, Limit: &limit, Cursor: firstPage.Result.Next})
	if code != 200 {
		t.Fatal("later AsOf broke cursor", code, string(second))
	}
	// Real case audit INSERT failure must expose no protected result body.
	if _, err := caseOwner.Exec(ctx, `CREATE FUNCTION ops_v2.fail_activity_exposure() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN IF NEW.action='exposure_prepared' THEN RAISE EXCEPTION 'public test failure';END IF;RETURN NEW;END$$;CREATE TRIGGER fail_activity_exposure BEFORE INSERT ON ops_v2.disclosure_events FOR EACH ROW EXECUTE FUNCTION ops_v2.fail_activity_exposure()`); err != nil {
		t.Fatal(err)
	}
	code, out = request(d.Query{Version: 1, Resource: p.ActivitySummary, View: d.Report})
	if code < 400 || bytes.Contains(out, []byte(`"total"`)) {
		t.Fatal("protected bytes leaked without committed receipt", code, string(out))
	}
}
