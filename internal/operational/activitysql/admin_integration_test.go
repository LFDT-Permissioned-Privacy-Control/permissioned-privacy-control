package activitysql_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"privacy-proxy/internal/accesslog"
	a "privacy-proxy/internal/activitylog"
	"privacy-proxy/internal/audit/buffer"
	f "privacy-proxy/internal/disclosuretest"
	"privacy-proxy/internal/operational/activitysource"
	s "privacy-proxy/internal/operational/activitysql"
)

func adminEnvelope(t *testing.T, entry buffer.Entry, org, actor, method string, denied bool) buffer.Entry {
	t.Helper()
	record, e := a.DecodeSpool(entry.Data)
	if e != nil {
		t.Fatal(e)
	}
	v := record.Fields()
	v.ActorID = actor
	v.DataOrg = org
	v.Method = method
	v.HTTP = 200
	v.IP = "192.0.2.5"
	v.BufferSeq = "1"
	v.Outcome = "success"
	v.Status = 200
	v.RPCError = nil
	if denied {
		code := int32(-32001)
		v.Outcome = "denied"
		v.Status = 403
		v.RPCError = &code
	}
	raw, _ := json.Marshal(v)
	entry.Data = append(append([]byte{}, raw[:len(raw)-len(`,"b":"1"}`)]...), '}')
	if _, e = a.DecodeSpool(entry.Data); e != nil {
		t.Fatal(e)
	}
	return entry
}
func TestAdminActualPGHTTPStableCutFiltersAndPrivacy(t *testing.T) {
	x := setupDatabase(t)
	ctx := t.Context()
	writer, e := s.OpenWriter(ctx, x.writer, x.scope)
	if e != nil {
		t.Fatal(e)
	}
	defer writer.Close()
	reader, e := s.OpenReader(ctx, x.reader, x.scope)
	if e != nil {
		t.Fatal(e)
	}
	defer reader.Close()
	// Additive owner upgrade accepts the exact previous catalog only, preserves
	// rows/ACLs, and is idempotent. A missing index makes runtime reads fail shut.
	if _, e = x.owner.Exec(ctx, `DROP INDEX public.activity_org_page`); e != nil {
		t.Fatal(e)
	}
	if e = reader.CheckReady(ctx); e == nil {
		t.Fatal("runtime accepted old catalog")
	}
	if e = s.Migrate(ctx, x.dsn, "b1_writer", "b1_reader", "b1_retention", false); e == nil {
		t.Fatal("undrained upgrade")
	}
	if e = s.Migrate(ctx, x.dsn, "b1_writer", "b1_reader", "b1_retention", true); e != nil {
		t.Fatal("005->006", e)
	}
	if e = s.Migrate(ctx, x.dsn, "b1_writer", "b1_reader", "b1_retention", true); e != nil {
		t.Fatal("idempotent006", e)
	}
	snapshot := f.Snapshot(t, nil)
	now := time.Unix(f.Now, 0)
	clock := func() time.Time { return now }
	service, e := accesslog.New(accesslog.Config{Snapshot: snapshot, Reader: activitysource.AdminReader{Store: reader}, Expected: reader.Metadata(), Clock: clock, Keys: accesslog.Keys{Active: accesslog.Key{ID: "admin", Bytes: bytes.Repeat([]byte{17}, 32)}}})
	if e != nil {
		t.Fatal(e)
	}
	// This reader/catalog fixture keeps actual audit appends durable locally,
	// without starting a SQL sealer that would alter its independently seeded
	// source population. Audited sealing/cut evolution has a dedicated test.
	metadata := reader.Metadata()
	auditRecorder, e := a.New(ctx, a.Config{Network: x.registration.Network, SourceID: metadata.SourceID, ProducerID: uuid.NewString(), ExpectedGeneration: metadata.Generation, Configuration: metadata.Configuration, Methods: []string{"eth_call", "explorer.admin_access_logs"}, Clock: clock, BufferDirectory: t.TempDir(), Limits: a.DefaultLimits()}, writer)
	if e != nil {
		t.Fatal(e)
	}
	defer auditRecorder.Close(context.Background())
	handler, e := accesslog.NewHandler(service, auditRecorder)
	if e != nil {
		t.Fatal(e)
	}
	mux := http.NewServeMux()
	handler.Register(mux)
	httpServer := httptest.NewServer(mux)
	defer httpServer.Close()
	query := url.Values{"from": {time.Unix(f.Now-10, 0).UTC().Format(time.RFC3339Nano)}, "to": {time.Unix(f.Now+10, 0).UTC().Format(time.RFC3339Nano)}, "limit": {"2"}}
	call := func(org, token string, q url.Values) (int, []byte) {
		t.Helper()
		if e := auditRecorder.CheckHealth(); e != nil {
			t.Fatal(e)
		}
		req, e := http.NewRequestWithContext(ctx, "GET", httpServer.URL+"/api/v2/orgs/"+org+"/access-logs?"+q.Encode(), nil)
		if e != nil {
			t.Fatal(e)
		}
		req.Header.Set("Authorization", "Bearer "+token)
		result, e := httpServer.Client().Do(req)
		if e != nil {
			t.Fatal(e)
		}
		defer result.Body.Close()
		body, e := io.ReadAll(io.LimitReader(result.Body, 193<<10))
		if e != nil {
			t.Fatal(e)
		}
		if result.Header.Get("Cache-Control") != "no-store" {
			t.Fatal("cache")
		}
		return result.StatusCode, body
	}
	admin := f.Token(t, snapshot, f.AdminSubject, "Admin")
	readonly := f.Token(t, snapshot, f.Subject, "Readonly")
	member := f.Token(t, snapshot, f.Subject, "Local")
	foreign := f.Token(t, snapshot, f.Subject, "Foreign")
	parse := func(q url.Values) accesslog.Page {
		t.Helper()
		status, body := call(f.Org, admin, q)
		var p accesslog.Page
		if status != 200 || json.Unmarshal(body, &p) != nil {
			t.Fatalf("page status %d %s", status, body)
		}
		return p
	}
	if p := parse(query); len(p.Items) != 0 || p.Next != nil || p.Source.Population != "SEALED_REQUEST_COMPLETIONS_AS_OF_CHAIN_HEAD" {
		t.Fatal("healthy empty", p)
	}
	for _, item := range []struct {
		token string
		want  int
	}{{readonly, 200}, {member, 403}, {foreign, 403}, {"invalid", 401}} {
		if status, _ := call(f.Org, item.token, query); status != item.want {
			t.Fatal("authority", status, item.want)
		}
	}
	if status, _ := call(f.OtherOrg, admin, query); status != 403 {
		t.Fatal("wrong org", status)
	}
	// Two producers and duplicate microseconds exercise every part of the strict
	// descending tuple. A filtered match sits behind many unrelated newest rows.
	var envelopes []a.Envelope
	for runIndex := 0; runIndex < 2; runIndex++ {
		run, e := writer.StartRun(ctx, a.RunRequest{ProducerID: uuid.NewString(), RunID: uuid.NewString()})
		if e != nil {
			t.Fatal(e)
		}
		entries := []buffer.Entry{}
		for i := 1; i <= 7; i++ {
			org, actor, method := f.Org, f.Actor(f.Subject), "eth_call"
			denied := i == 1
			if i == 2 {
				org = f.OtherOrg
			}
			if i == 3 {
				org = ""
				actor = ""
			}
			if i == 4 {
				actor = f.Actor(f.AdminSubject)
			}
			if i == 5 {
				method = "explorer.blocks"
			}
			if i == 6 {
				method = "Explorer.unknown"
			}
			entry := adminEnvelope(t, testEntry(t, run.Binding(), int64(i), f.Now*1000000+int64(i%2)), org, actor, method, denied)
			entries = append(entries, entry)
			record, _ := a.DecodeSpool(entry.Data)
			v := record.Fields()
			if org == f.Org && method != "Explorer.unknown" {
				envelopes = append(envelopes, v)
			}
		}
		if e = run.SealBatch(ctx, entries); e != nil {
			t.Fatal(e)
		}
	}
	sort.Slice(envelopes, func(i, j int) bool {
		a, b := envelopes[i], envelopes[j]
		if a.ObservedMicros != b.ObservedMicros {
			return a.ObservedMicros > b.ObservedMicros
		}
		if a.ProducerID != b.ProducerID {
			return a.ProducerID > b.ProducerID
		}
		if a.RunID != b.RunID {
			return a.RunID > b.RunID
		}
		ai, _ := strconv.Atoi(a.Ordinal)
		bi, _ := strconv.Atoi(b.Ordinal)
		if ai != bi {
			return ai > bi
		}
		return a.RecordID > b.RecordID
	})
	first := parse(query)
	if len(first.Items) != 2 || first.Next == nil {
		t.Fatal("first page", first)
	}
	if e = s.DowngradeTo005(ctx, x.dsn, "b1_writer", "b1_reader", "b1_retention", false); e == nil {
		t.Fatal("undrained downgrade")
	}
	if e = s.DowngradeTo005(ctx, x.reader, "b1_writer", "b1_reader", "b1_retention", true); e == nil {
		t.Fatal("nonowner downgrade")
	}
	var beforeRows, afterRows int64
	if e = x.owner.QueryRow(ctx, `SELECT count(*) FROM public.access_logs`).Scan(&beforeRows); e != nil {
		t.Fatal(e)
	}
	if e = s.DowngradeTo005(ctx, x.dsn, "b1_writer", "b1_reader", "b1_retention", true); e != nil {
		t.Fatal("006->005 with history", e)
	}
	if e = x.owner.QueryRow(ctx, `SELECT count(*) FROM public.access_logs`).Scan(&afterRows); e != nil || beforeRows != afterRows {
		t.Fatal("downgrade changed rows", e, beforeRows, afterRows)
	}
	if e = reader.CheckReady(ctx); e == nil {
		t.Fatal("006 reader silently accepted005")
	}
	if e = s.Migrate(ctx, x.dsn, "b1_writer", "b1_reader", "b1_retention", true); e != nil {
		t.Fatal("005->006 with history", e)
	}
	if check := parse(query); check.Source.HeadReference != first.Source.HeadReference || check.Items[0].RequestReference != first.Items[0].RequestReference {
		t.Fatal("006 rewrote history")
	}

	// Append after first cut, including an older timestamp, cannot leak into it.
	late, e := writer.StartRun(ctx, a.RunRequest{ProducerID: uuid.NewString(), RunID: uuid.NewString()})
	if e != nil {
		t.Fatal(e)
	}
	extra := adminEnvelope(t, testEntry(t, late.Binding(), 1, f.Now*1000000), f.Org, f.Actor(f.Subject), "eth_call", false)
	if e = late.SealOne(ctx, extra.Seq, extra.Data); e != nil {
		t.Fatal(e)
	}
	actual := append([]accesslog.Item{}, first.Items...)
	next := first.Next
	for next != nil {
		q := cloneQuery(query)
		q.Set("cursor", *next)
		p := parse(q)
		if p.Source.HeadReference != first.Source.HeadReference || p.Source.SourceAsOf != first.Source.SourceAsOf {
			t.Fatal("cut changed")
		}
		actual = append(actual, p.Items...)
		next = p.Next
	}
	if len(actual) != len(envelopes) {
		t.Fatal("skips/unscoped rows", len(actual), len(envelopes))
	}
	for i, item := range actual {
		if item.RequestReference != envelopes[i].RecordID || item.OrganizationID != f.Org {
			t.Fatal("order/scope", i, item)
		}
	}
	filters := cloneQuery(query)
	filters.Set("actorId", f.Actor(f.Subject))
	filters.Set("method", "eth_call")
	filters.Set("outcome", "denied")
	filters.Set("limit", "1")
	p := parse(filters)
	if len(p.Items) != 1 || p.Items[0].HTTPStatus != 200 || p.Items[0].RecordedStatus != 403 || p.Items[0].RPCErrorCode == nil || *p.Items[0].RPCErrorCode != -32001 || p.Items[0].TrustedIP == nil || *p.Items[0].TrustedIP != "192.0.2.5" || p.Items[0].Reason != "not_recorded" {
		t.Fatal("filters/status/IP", p)
	}
	ref := p.Items[0].RequestReference
	filters.Set("requestReference", ref)
	p = parse(filters)
	if len(p.Items) != 1 || p.Items[0].RequestReference != ref || p.Next != nil {
		t.Fatal("reference filter", p)
	}
	half := cloneQuery(query)
	half.Set("from", time.UnixMicro(f.Now*1000000).UTC().Format(time.RFC3339Nano))
	half.Set("to", time.UnixMicro(f.Now*1000000+1).UTC().Format(time.RFC3339Nano))
	half.Set("limit", "100")
	for _, item := range parse(half).Items {
		if item.ObservedAt != time.Unix(f.Now, 0).UTC().Format(time.RFC3339Nano) {
			t.Fatal("not half open", item)
		}
	}
	q := cloneQuery(query)
	q.Set("cursor", *first.Next)
	q.Set("method", "eth_call")
	if status, _ := call(f.Org, admin, q); status != 409 {
		t.Fatal("changed filter", status)
	}
	q = cloneQuery(query)
	q.Set("cursor", *first.Next)
	if status, _ := call(f.Org, readonly, q); status != 409 {
		t.Fatal("changed actor", status)
	}
	token := *first.Next
	q.Set("cursor", token[:len(token)-1]+"!")
	if status, _ := call(f.Org, admin, q); status != 400 {
		t.Fatal("tampered cursor", status)
	}
	// Required disclosure targets remain required despite the new admin route.
	disclosure, e := reader.Open(ctx, "", 0)
	if e != nil {
		t.Fatal(e)
	}
	if _, _, e = disclosure.ReadPage(ctx, s.ReadQuery{Organization: f.Org, FromMicros: 0, ThroughMicros: a.MaxObservedMicros, Limit: 1}, nil); !errors.Is(e, a.ErrInvalid) {
		t.Fatal("disclosure actors weakened", e)
	}
	disclosure.Close()
	// Real durable recorder -> sealer -> restricted reader -> admin HTTP retains
	// its generated receipt and actual HTTP/RPC/outcome as separate fields.
	recorder, e := a.New(ctx, a.Config{Network: x.registration.Network, SourceID: x.scope.SourceID, ProducerID: uuid.NewString(), ExpectedGeneration: x.scope.ExpectedGeneration, Configuration: a.Digest(x.registration.Configuration), Methods: []string{"eth_call"}, Clock: clock, BufferDirectory: t.TempDir(), Limits: a.DefaultLimits()}, writer)
	if e != nil {
		t.Fatal(e)
	}
	runctx, cancel := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- recorder.Run(runctx) }()
	defer func() {
		cancel()
		closectx, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		if e := recorder.Close(closectx); e != nil {
			t.Error(e)
		}
		<-done
	}()
	slot, e := recorder.Reserve()
	if e != nil {
		t.Fatal(e)
	}
	code := int32(-32001)
	receipt, e := slot.Complete(a.Completion{ActorID: f.Actor(f.Subject), DataOrganizationID: f.Org, Method: "eth_call", PolicyDigest: a.Digest{7}, HTTPStatus: 200, RPCErrorCode: &code, Outcome: a.Denied, TrustedIP: "2001:db8::5"})
	if e != nil {
		t.Fatal(e)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		var exists bool
		if e = x.owner.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM ops_activity_v1.qualified_logs WHERE correlation_id=$1)`, receipt.RecordID()).Scan(&exists); e != nil {
			t.Fatal(e)
		}
		if exists {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("actual sealer timeout")
		}
		time.Sleep(20 * time.Millisecond)
	}
	rq := cloneQuery(query)
	rq.Set("requestReference", receipt.RecordID())
	item := parse(rq).Items
	if len(item) != 1 || item[0].RequestReference != receipt.RecordID() || item[0].TrustedIP == nil || *item[0].TrustedIP != "2001:db8::5" {
		t.Fatal("durable receipt roundtrip", item)
	}
	restricted, e := pgx.Connect(ctx, x.reader)
	if e != nil {
		t.Fatal(e)
	}
	defer restricted.Close(ctx)
	if _, e = restricted.Exec(ctx, `DELETE FROM ops_activity_v1.qualified_logs`); e == nil {
		t.Fatal("reader mutated")
	}
	if _, e = restricted.Exec(ctx, `SELECT * FROM public.access_logs`); e == nil {
		t.Fatal("raw table readable")
	}
	retention, e := s.OpenRetention(ctx, x.retention, x.scope)
	if e != nil {
		t.Fatal(e)
	}
	defer retention.Close()
	if _, e = retention.Prune(ctx, (f.Now-1)*1000000, 100); e != nil {
		t.Fatal(e)
	}
	q = cloneQuery(query)
	q.Set("cursor", *first.Next)
	if status, body := call(f.Org, admin, q); status != 410 || !strings.Contains(string(body), "retainedFrom") {
		t.Fatal("retention must be explicit", status, string(body))
	}

	if status, _ := call(f.Org, admin, query); status != 410 {
		t.Fatal("fresh below-floor query", status)
	}
	current := accesslog.Query{FromMicros: f.Now * 1000000, ToMicros: (f.Now + 10) * 1000000, Limit: 100}
	response, e := service.Read(ctx, admin, f.Org, current, "")
	if e != nil {
		t.Fatal(e)
	}
	if _, e = x.owner.Exec(ctx, `UPDATE ops_activity_v1.sources SET ready=false WHERE network_key=$1`, x.scope.NetworkKey[:]); e != nil {
		t.Fatal(e)
	}
	var released bytes.Buffer
	if _, e = response.WriteTo(&released); !errors.Is(e, accesslog.ErrUnavailable) || released.Len() != 0 {
		t.Fatal("stale source output", e, released.String())
	}
	if _, e = x.owner.Exec(ctx, `UPDATE ops_activity_v1.sources SET ready=true WHERE network_key=$1`, x.scope.NetworkKey[:]); e != nil {
		t.Fatal(e)
	}
	response, e = service.Read(ctx, admin, f.Org, current, "")
	if e != nil {
		t.Fatal(e)
	}
	if _, e = retention.Prune(ctx, f.Now*1000000+1, 100); e != nil {
		t.Fatal(e)
	}
	released.Reset()
	var pruned *accesslog.RetentionError
	if _, e = response.WriteTo(&released); !errors.As(e, &pruned) || released.Len() != 0 {
		t.Fatal("pruned output released", e, released.String())
	}
	if _, e = x.owner.Exec(ctx, `UPDATE ops_activity_v1.sources SET ready=true,generation=$2 WHERE network_key=$1`, x.scope.NetworkKey[:], uuid.NewString()); e != nil {
		t.Fatal(e)
	}
	fresh := cloneQuery(query)
	fresh.Set("from", time.Unix(f.Now+1, 0).UTC().Format(time.RFC3339Nano))
	if status, _ := call(f.Org, admin, fresh); status != 503 {
		t.Fatal("generation changed", status)
	}
	// Expiry is checked before any source query, and failures never release rows.
	now = time.Unix(f.Now+301, 0)
	if status, _ := call(f.Org, admin, query); status != 401 {
		t.Fatal("expired token", status)
	}
}

func cloneQuery(v url.Values) url.Values {
	out := url.Values{}
	for k, values := range v {
		out[k] = append([]string{}, values...)
	}
	return out
}
