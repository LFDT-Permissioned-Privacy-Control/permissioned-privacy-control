package activitysql_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"privacy-proxy/internal/accesslog"
	a "privacy-proxy/internal/activitylog"
	"privacy-proxy/internal/activitymethoddata"
	"privacy-proxy/internal/audit/buffer"
	f "privacy-proxy/internal/disclosuretest"
	"privacy-proxy/internal/operational/activitysource"
	s "privacy-proxy/internal/operational/activitysql"
)

func TestAdminActualHTTPAuditAppendPreservesCutAndLegacyRollback(t *testing.T) {
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
	run, err := writer.StartRun(ctx, a.RunRequest{ProducerID: uuid.NewString(), RunID: uuid.NewString()})
	if err != nil {
		t.Fatal(err)
	}
	var original []buffer.Entry
	for number := 1; number <= 3; number++ {
		original = append(original, adminEnvelope(t, testEntry(t, run.Binding(), int64(number), (f.Now+int64(number))*1000000), f.Org, f.Actor(f.Subject), "eth_call", false))
	}
	if err = run.SealBatch(ctx, original); err != nil {
		t.Fatal(err)
	}
	bundle := f.Snapshot(t, nil)
	clock := func() time.Time { return time.Unix(f.Now, 0) }
	metadata := reader.Metadata()
	recorder, err := a.New(ctx, a.Config{Network: x.registration.Network, SourceID: metadata.SourceID, ProducerID: uuid.NewString(), ExpectedGeneration: metadata.Generation, Configuration: metadata.Configuration, Methods: []string{"eth_call", activitymethoddata.AdminAccessLogs}, Clock: clock, BufferDirectory: t.TempDir(), Limits: a.DefaultLimits()}, writer)
	if err != nil {
		t.Fatal(err)
	}
	runctx, cancel := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- recorder.Run(runctx) }()
	closed := false
	closeRecorder := func() {
		if closed {
			return
		}
		closed = true
		cancel()
		stopctx, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		if err := recorder.Close(stopctx); err != nil {
			t.Error(err)
		}
		<-done
	}
	defer closeRecorder()
	service, err := accesslog.New(accesslog.Config{Snapshot: bundle, Reader: activitysource.AdminReader{Store: reader}, Expected: metadata, Clock: clock, Keys: accesslog.Keys{Active: accesslog.Key{ID: "audit", Bytes: bytes.Repeat([]byte{9}, 32)}}})
	if err != nil {
		t.Fatal(err)
	}
	handler, err := accesslog.NewHandler(service, recorder)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	handler.Register(mux)
	server := httptest.NewServer(mux)
	defer server.Close()
	query := url.Values{"from": {time.Unix(f.Now-10, 0).UTC().Format(time.RFC3339Nano)}, "to": {time.Unix(f.Now+10, 0).UTC().Format(time.RFC3339Nano)}, "limit": {"1"}}
	token := f.Token(t, bundle, f.Subject, "Admin")
	call := func(q url.Values) (accesslog.Page, string) {
		t.Helper()
		req, err := http.NewRequestWithContext(ctx, "GET", server.URL+"/api/v2/orgs/"+f.Org+"/access-logs?"+q.Encode(), nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+token)
		response, err := server.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		raw, err := io.ReadAll(io.LimitReader(response.Body, 193<<10))
		if err != nil || response.StatusCode != 200 {
			t.Fatal(response.StatusCode, string(raw), err)
		}
		var page accesslog.Page
		if err = json.Unmarshal(raw, &page); err != nil {
			t.Fatal(err)
		}
		reference := response.Header.Get(a.RequestReferenceHeader)
		if !a.CanonicalUUID(reference) {
			t.Fatal("missing durable completion reference")
		}
		return page, reference
	}
	waitSealed := func(reference string) {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for {
			var present bool
			if err := x.owner.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM ops_activity_v1.qualified_logs WHERE correlation_id=$1 AND method=$2)`, reference, activitymethoddata.AdminAccessLogs).Scan(&present); err != nil {
				t.Fatal(err)
			}
			if present {
				return
			}
			if time.Now().After(deadline) {
				t.Fatal("audit completion did not seal")
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	first, reference := call(query)
	if len(first.Items) != 1 || first.Next == nil {
		t.Fatal(first)
	}
	waitSealed(reference)
	originalCut := first.Source.HeadReference
	count := 1
	next := first.Next
	for next != nil {
		if count >= 3 {
			t.Fatal("self-audit append created infinite pagination")
		}
		q := cloneQuery(query)
		q.Set("cursor", *next)
		page, reference := call(q)
		if page.Source.HeadReference != originalCut || len(page.Items) != 1 || page.Items[0].Method != "eth_call" {
			t.Fatal("self-created source-cut drift", page)
		}
		waitSealed(reference)
		count++
		next = page.Next
	}
	if count != 3 {
		t.Fatal("original rows skipped", count)
	}
	q := cloneQuery(query)
	q.Set("method", activitymethoddata.AdminAccessLogs)
	q.Set("limit", "100")
	newPage, lastReference := call(q)
	if len(newPage.Items) != 3 || newPage.Source.HeadReference == originalCut {
		t.Fatal("fresh investigation omitted sealed read completions", newPage)
	}
	for _, item := range newPage.Items {
		if item.RequestReference == lastReference || item.Method != activitymethoddata.AdminAccessLogs || item.ActorID != f.Actor(f.Subject) || item.OrganizationID != f.Org || item.HTTPStatus != 200 || item.Reason != "not_recorded" {
			t.Fatal("self-audit attribution or cut", item)
		}
	}
	waitSealed(lastReference)
	// Both list and summary of the RPC-only population exclude the operational
	// completion, while the recognized-request reader includes its exact label.
	rpc, err := reader.Open(ctx, "", (f.Now-10)*1000000)
	if err != nil {
		t.Fatal(err)
	}
	readq := s.ReadQuery{Organization: f.Org, Actors: []string{f.Actor(f.Subject)}, FromMicros: (f.Now - 10) * 1000000, ThroughMicros: (f.Now + 10) * 1000000, Limit: 100}
	rpcRows, end, err := rpc.ReadPage(ctx, readq, nil)
	if err != nil || !end || len(rpcRows) != 3 {
		t.Fatal("RPC population included read audits", rpcRows, end, err)
	}
	readq.Limit = 0
	summary, err := rpc.Summary(ctx, readq)
	rpc.Close()
	if err != nil || len(summary) != 1 || summary[0].Method != "eth_call" {
		t.Fatal("RPC summary included read audits", summary, err)
	}
	requests, err := reader.OpenRequests(ctx, "", (f.Now-10)*1000000)
	if err != nil {
		t.Fatal(err)
	}
	readq.Limit = 100
	requestRows, end, err := requests.ReadPage(ctx, readq, nil)
	requests.Close()
	if err != nil || !end || len(requestRows) != 7 {
		t.Fatal("recognized population missing audits", requestRows, end, err)
	}
	// Stop all read traffic and the actual writer before the owner-only drained
	// index rollback. Sealed v1 rows/hash bytes remain readable in exact005.
	server.Close()
	closeRecorder()
	var before, after string
	if err = x.owner.QueryRow(ctx, `SELECT request_params FROM ops_activity_v1.qualified_logs WHERE correlation_id=$1`, lastReference).Scan(&before); err != nil {
		t.Fatal(err)
	}
	if err = s.DowngradeTo005(ctx, x.dsn, "b1_writer", "b1_reader", "b1_retention", true); err != nil {
		t.Fatal(err)
	}
	oldReader, err := pgx.Connect(ctx, x.reader)
	if err != nil {
		t.Fatal(err)
	}
	defer oldReader.Close(ctx)
	if err = oldReader.QueryRow(ctx, `SELECT request_params FROM ops_activity_v1.qualified_logs WHERE correlation_id=$1`, lastReference).Scan(&after); err != nil || before != after {
		t.Fatal("rollback rewrote completion", err)
	}
	if decoded, err := a.DecodeEnvelope([]byte(after)); err != nil || decoded.Method != activitymethoddata.AdminAccessLogs || decoded.Version != 1 {
		t.Fatal("legacy v1 decode", decoded, err)
	}
	var oldRPC, oldRequests int
	if err = oldReader.QueryRow(ctx, `SELECT count(*) FROM ops_activity_v1.qualified_logs WHERE correlation_id=$1 AND lower(left(method,9))<>'explorer.'`, lastReference).Scan(&oldRPC); err != nil {
		t.Fatal(err)
	}
	if err = oldReader.QueryRow(ctx, `SELECT count(*) FROM ops_activity_v1.qualified_logs WHERE correlation_id=$1 AND (lower(left(method,9))<>'explorer.' OR method=ANY($2::text[]))`, lastReference, activitymethoddata.ExplorerLabels()).Scan(&oldRequests); err != nil || oldRPC != 0 || oldRequests != 0 {
		t.Fatal("old population accidentally admitted new reserved completion", oldRPC, oldRequests, err)
	}
	if strings.Contains(after, "cursor") || strings.Contains(after, "from=") {
		t.Fatal("query provenance leaked into v1 envelope")
	}
	if err = s.Migrate(ctx, x.dsn, "b1_writer", "b1_reader", "b1_retention", true); err != nil {
		t.Fatal(err)
	}
	if err = reader.CheckReady(ctx); err != nil {
		t.Fatal("upgrade after rollback", err)
	}
}
