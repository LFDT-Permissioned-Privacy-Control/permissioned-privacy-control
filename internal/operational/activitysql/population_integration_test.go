package activitysql_test

import (
	"github.com/google/uuid"
	a "privacy-proxy/internal/activitylog"
	"privacy-proxy/internal/activitymethoddata"
	"privacy-proxy/internal/audit/buffer"
	s "privacy-proxy/internal/operational/activitysql"
	"strconv"
	"testing"
)

func TestActualReaderRPCAndRecognizedRequestPopulations(t *testing.T) {
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
	// The owner fixture deliberately includes historical ambiguous labels. New
	// Recorder registrations reject those; neither selected population admits them.
	methods := []string{"explorer.stats", "Explorer.stats", "explorer.unknown", "method0", "eth_call", "explorer.invalid_transport", "explorer.blocks"}
	const at = int64(1700000000000000)
	entries := make([]buffer.Entry, 0, len(methods))
	for i, method := range methods {
		entries = append(entries, attributed(t, testEntry(t, run.Binding(), int64(i+1), at+int64(i)), method, i%2 == 0))
	}
	if err = run.SealBatch(ctx, entries); err != nil {
		t.Fatal(err)
	}
	first, err := reader.Open(ctx, "", at)
	if err != nil {
		t.Fatal(err)
	}
	if first.Population() != activitymethoddata.PopulationRPC {
		t.Fatal("default widened")
	}
	ref := first.Cut().Reference
	page, end, err := first.ReadPage(ctx, readQuery(at, at+10, 1), nil)
	if err != nil || end || len(page) != 1 || page[0].Envelope.Method != "method0" {
		t.Fatal("RPC predicate must precede limit", page, end, err)
	}
	e := page[0].Envelope
	ordinal, err := strconv.ParseInt(e.Ordinal, 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	next := &s.PageKey{ObservedMicros: e.ObservedMicros, ProducerID: e.ProducerID, RunID: e.RunID, Ordinal: ordinal, RecordID: e.RecordID}
	page, end, err = first.ReadPage(ctx, readQuery(at, at+10, 1), next)
	if err != nil || !end || len(page) != 1 || page[0].Envelope.Method != "eth_call" {
		t.Fatal("RPC continuation", page, end, err)
	}
	summary, err := first.Summary(ctx, readQuery(at, at+10, 0))
	if err != nil || len(summary) != 2 {
		t.Fatal("RPC summary population", summary, err)
	}
	first.Close()
	requests, err := reader.OpenRequests(ctx, ref, at)
	if err != nil {
		t.Fatal(err)
	}
	defer requests.Close()
	if requests.Population() != activitymethoddata.PopulationRequests {
		t.Fatal("request selection lost")
	}
	page, end, err = requests.ReadPage(ctx, readQuery(at, at+10, 100), nil)
	expected := []string{"explorer.stats", "method0", "eth_call", "explorer.invalid_transport", "explorer.blocks"}
	if err != nil || !end || len(page) != len(expected) {
		t.Fatal("recognized requests", page, end, err)
	}
	for i, row := range page {
		if row.Envelope.Method != expected[i] {
			t.Fatal("request order or unknown namespace admitted", row.Envelope.Method)
		}
	}
	summary, err = requests.Summary(ctx, readQuery(at, at+10, 0))
	if err != nil || len(summary) != 5 {
		t.Fatal("request summary population", summary, err)
	}
}
