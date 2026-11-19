package protectedsource

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	a "privacy-proxy/internal/admission"
	c "privacy-proxy/internal/disclosurecase"
	d "privacy-proxy/internal/disclosuredata"
	"privacy-proxy/internal/disclosurehttp"
	p "privacy-proxy/internal/disclosurepolicy"
	f "privacy-proxy/internal/disclosuretest"
	"privacy-proxy/internal/operational/admissionsql"
	"privacy-proxy/internal/operational/disclosuresql"
	"privacy-proxy/internal/rpcexecution"
)

// The hook only schedules a real fixture write between sampling and the real
// source's final gate. It supplies no permission, facts or validation result.
type nativeFinanceHook struct {
	d.RetainedSources
	mu     sync.Mutex
	before func()
}
type nativeFinanceHookSnapshot struct {
	d.RetainedSnapshot
	owner *nativeFinanceHook
}

func (s *nativeFinanceHook) OpenRetained(ctx context.Context, scope d.ReadScope, refs []d.SourceRef, basis *d.RetainedBasis, after *d.Position) (d.RetainedSnapshot, error) {
	read, err := s.RetainedSources.OpenRetained(ctx, scope, refs, basis, after)
	if err != nil {
		return nil, err
	}
	return &nativeFinanceHookSnapshot{read, s}, nil
}
func (s *nativeFinanceHookSnapshot) CheckCurrent(ctx context.Context) error {
	s.owner.mu.Lock()
	fn := s.owner.before
	s.owner.before = nil
	s.owner.mu.Unlock()
	if fn != nil {
		fn()
	}
	return s.RetainedSnapshot.CheckCurrent(ctx)
}

func TestActualNativeFinanceLivePagingAndAsOfSummary(t *testing.T) {
	db := ownedFunctionalDB(t)
	ctx := t.Context()
	financeDSN, owner := db.database(t, "native_finance")
	for _, role := range []string{"nfp_app", "nfp_reader", "nfp_retention"} {
		functionalRole(t, owner, role)
	}
	if err := admissionsql.Migrate(ctx, financeDSN, "nfp_app", "nfp_reader", "nfp_retention"); err != nil {
		t.Fatal(err)
	}
	network := a.NetworkBinding{Environment: "test", ChainID: "1", GenesisHash: "0x" + strings.Repeat("0", 63) + "1", DeploymentID: "native-finance-test"}
	key, _ := network.Key()
	generation := uuid.NewString()
	if err := admissionsql.BootstrapEmpty(ctx, financeDSN, network, generation); err != nil {
		t.Fatal(err)
	}
	reader, err := admissionsql.OpenReader(ctx, functionalDSN(financeDSN, "nfp_reader"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(reader.Close)
	rule := f.DefaultRule()
	rule.Resources = []p.Resource{p.ComplianceReport}
	rule.MaxLevel = p.Full
	bundle := f.Snapshot(t, []p.RuleSource{rule})
	clock := func() time.Time { return time.Unix(f.Now, 0).UTC() }
	plan := d.SourcePlan{Version: 3, Profile: d.NativeFinanceSourceProfile, BundleDigest: d.Digest(bundle.Metadata().ManifestDigest), NetworkKey: d.Digest(key.String()), PlanDigest: d.Digest("sha256:" + strings.Repeat("5", 64)), Resources: []p.Resource{p.ComplianceReport}}
	finance, err := admissionsql.NewRetainedFinanceReader(admissionsql.FinanceReaderConfig{Store: reader, Network: network, ExpectedState: a.ExpectedState{Generation: generation, Coverage: admissionsql.EmptyCoverage()}, Plan: plan, Clock: clock})
	if err != nil {
		t.Fatal(err)
	}
	sources := &nativeFinanceHook{RetainedSources: &Sources{plan: plan, finance: finance, clock: clock}}
	caseDSN, caseOwner := db.database(t, "native_finance_cases")
	for _, role := range []string{"nfp_case_app", "nfp_case_retention"} {
		functionalRole(t, caseOwner, role)
	}
	if err := disclosuresql.Migrate(ctx, caseDSN, "nfp_case_app", "nfp_case_retention"); err != nil {
		t.Fatal(err)
	}
	store, err := disclosuresql.Open(ctx, functionalDSN(caseDSN, "nfp_case_app"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(store.Close)
	cfg := c.Config{Snapshot: bundle, Clock: clock, Store: store, StoreEpoch: "native-finance", CursorKeys: c.CursorKeys{Active: c.CursorKey{ID: "admin", Key: bytes.Repeat([]byte{31}, 32)}}}
	data := c.RetainedDataConfig{Network: d.NetworkBinding(network), Sources: sources, RenderKeys: d.Keys{Active: d.Key{ID: "render", Bytes: bytes.Repeat([]byte{33}, 32)}}, CursorKeys: d.Keys{Active: d.Key{ID: "data", Bytes: bytes.Repeat([]byte{32}, 32)}}}
	service, err := c.NewWithRetainedData(cfg, data)
	if err != nil {
		t.Fatal(err)
	}
	handler, err := disclosurehttp.NewWithData(service)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	handler.Register(mux)
	server := httptest.NewTLSServer(mux)
	t.Cleanup(server.Close)
	token := f.Token(t, bundle, f.Subject, "Auditor")
	request := func(path string, body any, want int) []byte {
		t.Helper()
		raw, _ := json.Marshal(body)
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, server.URL+path, bytes.NewReader(raw))
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
		bodyRaw, err := io.ReadAll(io.LimitReader(response.Body, c.MaxResponseBytes+1))
		if err != nil || response.StatusCode != want {
			t.Fatalf("HTTP %d want%d %s %v", response.StatusCode, want, bodyRaw, err)
		}
		return bodyRaw
	}
	scope := f.Scope()
	scope.Resources = []p.Resource{p.ComplianceReport}
	scope.Level = p.Full
	var opened c.CaseResponse
	if json.Unmarshal(request("/api/v1/disclosure/cases", c.CreateRequest{RuleID: "auditor", RecipientActorID: f.Actor(f.Subject), CaseReference: "NATIVE-FINANCE", Purpose: "Investigation", Scope: scope, ExpiresAt: f.Now + 120, IdempotencyKey: uuid.NewString()}, 201), &opened) != nil {
		t.Fatal("case")
	}
	path := "/api/v1/disclosure/cases/" + opened.CaseID + "/read"
	insert := func(q interface {
		QueryRow(context.Context, string, ...any) pgx.Row
	}, org, actor string, at time.Time) int64 {
		t.Helper()
		var id int64
		err := q.QueryRow(ctx, `INSERT INTO ops_admission_v2.compliance_events(network_key,tx_hash,actor_id,org_id,kind,coverage,decision,monitored,reason,decision_at,policy_digest,anchor_hash,anchor_number,anchor_timestamp,evidence_profile)VALUES($1,$2,$3,$4::uuid,'admission_only','not_detected','allowed',false,'',$5,$6,$7,1,1,$8)RETURNING id`, key[:], bytes.Repeat([]byte{3}, 32), actor, org, at, bytes.Repeat([]byte{4}, 32), bytes.Repeat([]byte{5}, 32), rpcexecution.GuardRetainedProfileID).Scan(&id)
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	// One INSERT produces a cohort above BOTH old16384 rows and2MiB framing.
	if _, err = owner.Exec(ctx, `INSERT INTO ops_admission_v2.compliance_events(network_key,tx_hash,actor_id,org_id,kind,coverage,decision,monitored,reason,decision_at,policy_digest,anchor_hash,anchor_number,anchor_timestamp,evidence_profile)SELECT $1,$2,$3,$4::uuid,'admission_only','not_detected','allowed',false,'',$5,$6,$7,1,1,$8 FROM generate_series(1,20001)`, key[:], bytes.Repeat([]byte{3}, 32), f.Actor(f.Subject), f.Org, clock().Add(-time.Second), bytes.Repeat([]byte{4}, 32), bytes.Repeat([]byte{5}, 32), rpcexecution.GuardRetainedProfileID); err != nil {
		t.Fatal(err)
	}
	insert(owner, f.OtherOrg, f.Actor(f.Subject), clock())
	insert(owner, f.Org, f.Actor(f.AdminSubject), clock())
	insert(owner, f.Org, f.Actor(f.Subject), time.Unix(scope.DataTime.End, 0).Add(time.Microsecond))
	reportQuery, err := d.NormalizeRetained(d.Query{Version: 1, Resource: p.ComplianceReport, View: d.Report}, scope)
	if err != nil {
		t.Fatal(err)
	}
	readScope := d.ReadScope{Namespace: d.Digest("sha256:" + strings.Repeat("9", 64)), CaseID: opened.CaseID, CaseVersion: 1, RecipientActorID: f.Actor(f.Subject), DataOrganizationID: f.Org, BundleDigest: plan.BundleDigest, RuleDigest: d.Digest("sha256:" + strings.Repeat("8", 64)), EffectiveUntil: clock().Add(time.Minute), Query: reportQuery}
	summary, err := finance.OpenSummary(ctx, readScope)
	if err != nil {
		t.Fatal("large summary", err)
	}
	defer summary.Close()
	if summary.Summary() == nil || summary.Summary().MatchingRetainedCount != "20001" || len(summary.Evidence()) != 0 {
		t.Fatal("summary hydrated/capped detail", summary.Summary())
	}
	insert(owner, f.Org, f.Actor(f.Subject), clock())
	if err = summary.CheckCurrent(ctx); err != nil || summary.Summary().MatchingRetainedCount != "20001" {
		t.Fatal("append invalidated as-of summary", err)
	}
	query := d.Query{Version: 1, Resource: p.ComplianceReport, View: d.List, Limit: ptrFinance(uint16(25))}
	type page struct {
		ReadID string
		Result struct {
			Version               uint8 `json:"v"`
			Items                 []d.ComplianceEvidenceDTO
			NextCursor            *string
			MatchingRetainedCount d.Count
			ObservedAt            time.Time
			Pagination            string
		}
	}
	sources.mu.Lock()
	sources.before = func() { insert(owner, f.Org, f.Actor(f.Subject), clock()) }
	sources.mu.Unlock()
	var first page
	if json.Unmarshal(request(path, query, 200), &first) != nil || first.Result.Version != 2 || len(first.Result.Items) != 25 || first.Result.MatchingRetainedCount != "20002" || first.Result.Pagination != "live-keyset" || first.Result.NextCursor == nil || !strings.HasPrefix(*first.Result.NextCursor, "df1.") {
		t.Fatal("large live page", first)
	}
	var eventRaw []byte
	if err = caseOwner.QueryRow(ctx, `SELECT summary FROM ops_v2.disclosure_events WHERE attempt_id=$1::uuid`, first.ReadID).Scan(&eventRaw); err != nil {
		t.Fatal(err)
	}
	var event c.EventSummary
	if json.Unmarshal(eventRaw, &event) != nil || event.Exposure == nil || event.Exposure.Version != 1 || event.Exposure.QualifiedTotal == nil || *event.Exposure.QualifiedTotal != "20002" || event.Count != 25 {
		t.Fatal("large real exposure count", string(eventRaw))
	}
	// A new matching row after sampling is legal; next sample reports its new
	// count while the original df1 after-tuple remains case/filter bound.
	query.Cursor = first.Result.NextCursor
	var second page
	if json.Unmarshal(request(path, query, 200), &second) != nil || second.Result.MatchingRetainedCount != "20003" || len(second.Result.Items) != 25 {
		t.Fatal("live continuation", second)
	}
	seen := map[d.Count]bool{}
	for _, row := range first.Result.Items {
		seen[row.ID] = true
	}
	for _, row := range second.Result.Items {
		if seen[row.ID] {
			t.Fatal("duplicate live tuple", row.ID)
		}
	}
	query.Cursor = nil
	// Only the sampled returned rows are revalidated, including continued scope.
	sources.mu.Lock()
	sources.before = func() {
		id, _ := strconv.ParseInt(string(first.Result.Items[0].ID), 10, 64)
		if _, err := owner.Exec(ctx, `UPDATE ops_admission_v2.compliance_events SET actor_id=$1 WHERE id=$2`, f.Actor(f.AdminSubject), id); err != nil {
			t.Fatal(err)
		}
	}
	sources.mu.Unlock()
	request(path, query, 409)
	// The same current source gates remain authoritative for sampled aggregates.
	if _, err = owner.Exec(ctx, `UPDATE ops_admission_v2.network_state SET ready=false WHERE network_key=$1`, key[:]); err != nil {
		t.Fatal(err)
	}
	if err = summary.CheckCurrent(ctx); err == nil {
		t.Fatal("unready source kept summary deliverable")
	}
	if _, err = owner.Exec(ctx, `UPDATE ops_admission_v2.network_state SET ready=true WHERE network_key=$1`, key[:]); err != nil {
		t.Fatal(err)
	}
	// Explicit old cursor rejection and no unaudited data on failed exposure.
	query.Cursor = ptrFinance("dd2.old.prototype")
	request(path, query, 400)
	query.Cursor = nil
	badService, err := c.NewWithRetainedData(c.Config{Snapshot: bundle, Clock: clock, Store: financeAuditFailure{Store: store}, StoreEpoch: cfg.StoreEpoch, CursorKeys: cfg.CursorKeys}, data)
	if err != nil {
		t.Fatal(err)
	}
	if response, err := badService.Read(ctx, token, opened.CaseID, query); err == nil || response != nil {
		t.Fatal("unaudited live data", response, err)
	}
	if err = summary.CheckCurrent(ctx); err != nil {
		t.Fatal("source did not recover ready gate", err)
	}
	var held int
	if err = owner.QueryRow(ctx, `SELECT count(*) FROM pg_stat_activity WHERE usename='nfp_reader' AND xact_start IS NOT NULL`).Scan(&held); err != nil || held != 0 {
		t.Fatal("held source transaction", held, err)
	}
	// A separate narrow cohort exercises complete traversals, equal timestamps,
	// non-contiguous IDs and the actual 1/25/100 page sizes without scanning the
	// large cohort in the browser or depending on insertion order.
	for i := 0; i < 103; i++ {
		insert(owner, f.Org, f.Actor(f.Subject), clock().Add(-100*time.Second+time.Duration(i%3)*time.Microsecond))
		insert(owner, f.OtherOrg, f.Actor(f.Subject), clock().Add(-100*time.Second))
	}
	for _, limit := range []uint16{1, 25, 100} {
		q := d.Query{Version: 1, Resource: p.ComplianceReport, View: d.List, Limit: ptrFinance(limit), DataTime: &p.Interval{Start: f.Now - 100, End: f.Now - 99}}
		ids := map[d.Count]bool{}
		pages := 0
		for {
			var result page
			if json.Unmarshal(request(path, q, 200), &result) != nil || result.Result.MatchingRetainedCount != "103" || len(result.Result.Items) == 0 || len(result.Result.Items) > int(limit) {
				t.Fatal("bounded traversal", limit, result)
			}
			for _, row := range result.Result.Items {
				if ids[row.ID] {
					t.Fatal("duplicate traversal ID", limit, row.ID)
				}
				ids[row.ID] = true
			}
			pages++
			if result.Result.NextCursor == nil {
				break
			}
			q.Cursor = result.Result.NextCursor
			if pages > 103 {
				t.Fatal("nonterminating traversal")
			}
		}
		if len(ids) != 103 || pages != (103+int(limit)-1)/int(limit) {
			t.Fatal("missing keyset rows", limit, len(ids), pages)
		}
	}
}

func TestActualNativeComplianceAggregateAboveInlineLimit(t *testing.T) {
	ctx := t.Context()
	node := ownedFunctionalNode(t)
	var controls functionalControl
	config := actualFunctionalConfig(t, node, func(c functionalControl) { controls = c })
	source, err := New(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	owner := controls.admission
	key, _ := config.Finance.Network.Key()
	appendRows := func(count int) {
		t.Helper()
		_, err := owner.Exec(ctx, `INSERT INTO ops_admission_v2.compliance_events(network_key,tx_hash,actor_id,org_id,kind,coverage,decision,monitored,reason,decision_at,policy_digest,anchor_hash,anchor_number,anchor_timestamp,evidence_profile)SELECT $1,$2,$3,$4::uuid,'admission_only','not_detected','allowed',false,'',$5,$6,$7,1,1,$8 FROM generate_series(1,$9::int)`, key[:], bytes.Repeat([]byte{3}, 32), f.Actor(f.Subject), f.Org, config.Clock().Add(-time.Second), bytes.Repeat([]byte{4}, 32), bytes.Repeat([]byte{5}, 32), rpcexecution.GuardRetainedProfileID, count)
		if err != nil {
			t.Fatal(err)
		}
	}
	appendRows(1001)
	functionalExec(t, owner, `CREATE DATABASE native_report_cases`)
	caseURL, err := url.Parse(owner.Config().ConnString())
	if err != nil {
		t.Fatal(err)
	}
	caseURL.Path = "/native_report_cases"
	caseDSN := caseURL.String()
	caseOwner, err := pgx.Connect(ctx, caseDSN)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = caseOwner.Close(context.Background()) })
	for _, role := range []string{"native_report_app", "native_report_retention"} {
		functionalRole(t, caseOwner, role)
	}
	if err = disclosuresql.Migrate(ctx, caseDSN, "native_report_app", "native_report_retention"); err != nil {
		t.Fatal(err)
	}
	store, err := disclosuresql.Open(ctx, functionalDSN(caseDSN, "native_report_app"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(store.Close)
	sources := &nativeFinanceHook{RetainedSources: source}
	service, err := c.NewWithRetainedData(c.Config{Snapshot: config.Snapshot, Clock: config.Clock, Store: store, StoreEpoch: "native-report", CursorKeys: c.CursorKeys{Active: c.CursorKey{ID: "admin", Key: bytes.Repeat([]byte{31}, 32)}}}, c.RetainedDataConfig{Network: d.NetworkBinding(config.Network), Sources: sources, RenderKeys: config.RenderKeys, CursorKeys: d.Keys{Active: d.Key{ID: "data", Bytes: bytes.Repeat([]byte{32}, 32)}}})
	if err != nil {
		t.Fatal(err)
	}
	handler, err := disclosurehttp.NewWithData(service)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	handler.Register(mux)
	server := httptest.NewTLSServer(mux)
	t.Cleanup(server.Close)
	token := f.Token(t, config.Snapshot, f.Subject, "Auditor")
	request := func(path string, body any, want int) []byte {
		t.Helper()
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, server.URL+path, bytes.NewReader(raw))
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
		raw, err = io.ReadAll(io.LimitReader(response.Body, c.MaxResponseBytes+1))
		if err != nil || response.StatusCode != want {
			t.Fatalf("HTTP %d want%d: %s %v", response.StatusCode, want, raw, err)
		}
		return raw
	}
	scope := p.Scope{TargetActors: []string{f.Actor(f.Subject)}, Resources: []p.Resource{p.ComplianceReport}, Addresses: p.Addresses{Mode: "all-target-addresses", Values: []string{}}, DataTime: p.Interval{Start: f.Now - 10, End: f.Now + 10}, Level: p.Full}
	var opened c.CaseResponse
	if err = json.Unmarshal(request("/api/v1/disclosure/cases", c.CreateRequest{RuleID: "auditor", RecipientActorID: f.Actor(f.Subject), CaseReference: "AGGREGATE-1001", Purpose: "Investigation", Scope: scope, ExpiresAt: f.Now + 120, IdempotencyKey: uuid.NewString()}, 201), &opened); err != nil {
		t.Fatal(err)
	}
	// An append after the report's sample does not turn an honest as-of count
	// into a spurious conflict. All other real source and exposure gates remain.
	sources.before = func() { appendRows(1) }
	raw := request("/api/v1/disclosure/cases/"+opened.CaseID+"/read", d.Query{Version: 1, Resource: p.ComplianceReport, View: d.Report}, 200)
	var result struct {
		ReadID   string
		Coverage d.CoverageDTO
		Result   d.ComplianceSummaryDTO
	}
	if err = json.Unmarshal(raw, &result); err != nil || result.Result.Version != 2 || result.Result.Finance.MatchingRetainedCount != "1001" || result.Result.Finance.Coverage != "RETAINED_AT_READ" || result.Result.KYC != "not_evaluated" || result.Result.Sanctions.ScopedAddressCount != 1 || result.Coverage.Status != "RETAINED_AT_READ" || result.Coverage.SourceBasisDigest == "" || result.Coverage.SourceCutDigest != "" || strings.Contains(string(raw), `"evidence"`) {
		t.Fatal("aggregate did not preserve qualified summary", string(raw), err)
	}
	var eventRaw []byte
	if err = caseOwner.QueryRow(ctx, `SELECT summary FROM ops_v2.disclosure_events WHERE attempt_id=$1::uuid`, result.ReadID).Scan(&eventRaw); err != nil {
		t.Fatal(err)
	}
	var audit c.EventSummary
	if json.Unmarshal(eventRaw, &audit) != nil || audit.Exposure == nil || audit.Exposure.Resource != p.ComplianceReport || audit.Exposure.View != d.Report || audit.Count != 1 {
		t.Fatal("aggregate mandatory audit", string(eventRaw))
	}
	t.Logf("NATIVE_REPORT_HTTP=%s", raw)
}
