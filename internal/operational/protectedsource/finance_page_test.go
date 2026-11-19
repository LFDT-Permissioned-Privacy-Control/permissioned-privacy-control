package protectedsource

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
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

type financeAuditFailure struct{ c.Store }

func (s financeAuditFailure) WithLockedCase(context.Context, string, string, int64, func(c.Case) (c.Event, error)) (c.CommitReceipt, error) {
	return c.CommitReceipt{}, c.ErrUnavailable
}

// One owned PostgreSQL fixture, actual restricted finance/case roles and actual
// HTTP. The production retained source has deliberately NIL unrelated readers:
// this proves finance List does not call node/indexer/wallet/activity/sanctions.
func TestActualRetainedFinanceEvidencePages(t *testing.T) {
	db := ownedFunctionalDB(t)
	ctx := t.Context()
	financeDSN, owner := db.database(t, "finance_pages")
	for _, role := range []string{"fp_app", "fp_reader", "fp_retention"} {
		functionalRole(t, owner, role)
	}
	if err := admissionsql.Migrate(ctx, financeDSN, "fp_app", "fp_reader", "fp_retention"); err != nil {
		t.Fatal(err)
	}
	network := a.NetworkBinding{Environment: "test", ChainID: "1", GenesisHash: "0x" + strings.Repeat("0", 63) + "1", DeploymentID: "finance-pages-test"}
	key, _ := network.Key()
	generation := uuid.NewString()
	if err := admissionsql.BootstrapEmpty(ctx, financeDSN, network, generation); err != nil {
		t.Fatal(err)
	}
	reader, err := admissionsql.OpenReader(ctx, functionalDSN(financeDSN, "fp_reader"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(reader.Close)
	rule := f.DefaultRule()
	rule.Resources = []p.Resource{p.ComplianceReport}
	rule.MaxLevel = p.Full
	snapshot := f.Snapshot(t, []p.RuleSource{rule})
	var now atomic.Int64
	now.Store(f.Now)
	clock := func() time.Time { return time.Unix(now.Load(), 0).UTC() }
	plan := d.SourcePlan{Version: 2, Profile: d.RetainedSourceProfile, BundleDigest: d.Digest(snapshot.Metadata().ManifestDigest), NetworkKey: d.Digest(key.String()), PlanDigest: d.Digest("sha256:" + strings.Repeat("5", 64)), Resources: []p.Resource{p.ComplianceReport}}
	finance, err := admissionsql.NewRetainedFinanceReader(admissionsql.FinanceReaderConfig{Store: reader, Network: network, ExpectedState: a.ExpectedState{Generation: generation, Coverage: admissionsql.EmptyCoverage()}, Plan: plan, Clock: clock})
	if err != nil {
		t.Fatal(err)
	}
	sources := &Sources{plan: plan, finance: finance, clock: clock}
	caseDSN, caseOwner := db.database(t, "finance_cases")
	for _, role := range []string{"fp_case_app", "fp_case_retention"} {
		functionalRole(t, caseOwner, role)
	}
	if err := disclosuresql.Migrate(ctx, caseDSN, "fp_case_app", "fp_case_retention"); err != nil {
		t.Fatal(err)
	}
	store, err := disclosuresql.Open(ctx, functionalDSN(caseDSN, "fp_case_app"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(store.Close)
	cfg := c.Config{Snapshot: snapshot, Clock: clock, Store: store, StoreEpoch: "finance-pages", CursorKeys: c.CursorKeys{Active: c.CursorKey{ID: "admin", Key: bytes.Repeat([]byte{31}, 32)}}}
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
	token := f.Token(t, snapshot, f.Subject, "Auditor")
	request := func(path string, body any, status int) []byte {
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
		value, err := io.ReadAll(io.LimitReader(response.Body, c.MaxResponseBytes+1))
		if err != nil || response.StatusCode != status {
			t.Fatalf("HTTP status=%d want=%d error=%v body=%s", response.StatusCode, status, err, value)
		}
		return value
	}
	scope := f.Scope()
	scope.Resources = []p.Resource{p.ComplianceReport}
	scope.Level = p.Full
	scope.TargetActors = append(scope.TargetActors, f.Actor(f.AdminSubject))
	created := request("/api/v1/disclosure/cases", c.CreateRequest{RuleID: "auditor", RecipientActorID: f.Actor(f.Subject), CaseReference: "FINANCE-PAGES", Purpose: "Retained evidence", Scope: scope, ExpiresAt: f.Now + 120, IdempotencyKey: uuid.NewString()}, http.StatusCreated)
	var opened c.CaseResponse
	if json.Unmarshal(created, &opened) != nil || opened.CaseID == "" {
		t.Fatal("case", string(created))
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
	ids := []int64{}
	for i := 0; i < 123; i++ {
		ids = append(ids, insert(owner, f.Org, f.Actor(f.Subject), clock()))
		insert(owner, f.OtherOrg, f.Actor(f.Subject), clock())
	}
	insert(owner, f.Org, f.Actor(f.AdminSubject), clock())
	insert(owner, f.Org, f.Actor(f.Subject), clock().Add(time.Microsecond))
	query := d.Query{Version: 1, Resource: p.ComplianceReport, View: d.List, Limit: ptrFinance(uint16(25)), TargetActorIDs: []string{f.Actor(f.Subject)}}
	type pageResult struct {
		ReadID   string
		Coverage d.CoverageDTO
		Result   struct {
			Items                 []d.ComplianceEvidenceDTO
			NextCursor            *string
			MatchingRetainedCount d.Count
		}
	}
	firstRaw := request(path, query, 200)
	var first pageResult
	if json.Unmarshal(firstRaw, &first) != nil || first.Result.MatchingRetainedCount != "123" || len(first.Result.Items) != 25 || first.Result.NextCursor == nil || first.Coverage.Status != "RETAINED_AT_READ" {
		t.Fatal("first page", string(firstRaw))
	}
	t.Logf("real first page shape: view=list retainedCount=%s rows=%d coverage=%s", first.Result.MatchingRetainedCount, len(first.Result.Items), first.Coverage.Status)
	if destination := os.Getenv("OPS_TEST_FINANCE_PAGE_SAMPLE"); destination != "" {
		if err := os.WriteFile(destination, firstRaw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	seen := []int64{}
	page := first
	for {
		for _, row := range page.Result.Items {
			id, _ := strconv.ParseInt(string(row.ID), 10, 64)
			seen = append(seen, id)
			if row.TransactionHash == nil {
				t.Fatal("Full omitted actual hash")
			}
		}
		if page.Result.NextCursor == nil {
			break
		}
		query.Cursor = page.Result.NextCursor
		if json.Unmarshal(request(path, query, 200), &page) != nil || page.Result.MatchingRetainedCount != "123" {
			t.Fatal("continuation")
		}
	}
	if len(seen) != len(ids) {
		t.Fatal("page count", len(seen))
	}
	for i, id := range ids {
		if seen[i] != id {
			t.Fatal("skipped/duplicate", i, id, seen[i])
		}
	}
	// No held snapshot/transaction after source acquisition, rendering or audit.
	var held int
	if owner.QueryRow(ctx, `SELECT count(*)FROM pg_stat_activity WHERE usename='fp_reader'AND xact_start IS NOT NULL`).Scan(&held) != nil || held != 0 {
		t.Fatal("held SQL snapshot", held)
	}
	// The exposure total must come from finance, with page rows kept separate.
	var summary []byte
	if caseOwner.QueryRow(ctx, `SELECT summary FROM ops_v2.disclosure_events WHERE attempt_id=$1::uuid`, first.ReadID).Scan(&summary) != nil {
		t.Fatal("missing exposure audit")
	}
	if !bytes.Contains(summary, []byte(`"qualifiedTotal": "123"`)) && !bytes.Contains(summary, []byte(`"qualifiedTotal":"123"`)) {
		t.Fatal("finance audit count", string(summary))
	}
	// A report is still complete-or-error at100, not the new page format.
	reportQuery := query
	reportQuery.View = d.Report
	reportQuery.Limit = nil
	reportQuery.Cursor = nil
	normalized, _ := d.NormalizeRetained(reportQuery, scope)
	rs := d.ReadScope{Namespace: plan.PlanDigest, CaseID: opened.CaseID, CaseVersion: 1, RecipientActorID: f.Actor(f.Subject), DataOrganizationID: f.Org, BundleDigest: plan.BundleDigest, RuleDigest: plan.PlanDigest, EffectiveUntil: clock().Add(time.Minute), Query: normalized}
	if snap, err := finance.Open(ctx, rs, nil); snap != nil || !errors.Is(err, d.ErrTooBroad) {
		t.Fatal("complete report limit changed", err)
	}
	query.Cursor = first.Result.NextCursor
	// Changed filters/limit cannot reuse the cursor or silently restart.
	bad := query
	bad.TargetActorIDs = []string{f.Actor(f.AdminSubject)}
	request(path, bad, 409)
	bad = query
	bad.Limit = ptrFinance(uint16(24))
	request(path, bad, 409)
	bad = query
	bad.Cursor = ptrFinance(*query.Cursor + "x")
	request(path, bad, 400)
	// All rows are validated, including a malformed last row outside page1.
	functionalExec(t, owner, `UPDATE ops_admission_v2.compliance_events SET evidence_profile='wrong-profile'WHERE id=$1`, ids[len(ids)-1])
	initial := query
	initial.Cursor = nil
	request(path, initial, 503)
	functionalExec(t, owner, `UPDATE ops_admission_v2.compliance_events SET evidence_profile=$2 WHERE id=$1`, ids[len(ids)-1], rpcexecution.GuardRetainedProfileID)
	// A valid mutation outside the requested page changes the original cohort.
	functionalExec(t, owner, `UPDATE ops_admission_v2.compliance_events SET policy_digest=$2 WHERE id=$1`, ids[len(ids)-1], bytes.Repeat([]byte{9}, 32))
	request(path, query, 409)
	functionalExec(t, owner, `UPDATE ops_admission_v2.compliance_events SET policy_digest=$2 WHERE id=$1`, ids[len(ids)-1], bytes.Repeat([]byte{4}, 32))
	// Currentness catches appends and pruning, without inventing retention floor.
	n, _ := d.NormalizeRetained(initial, scope)
	rs.Query = n
	snap, err := finance.OpenPage(ctx, rs, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	added := insert(owner, f.Org, f.Actor(f.Subject), clock())
	if !errors.Is(snap.CheckCurrent(ctx), d.ErrConflict) {
		t.Fatal("append passed final source check")
	}
	request(path, query, 409)
	snap.Close()
	functionalExec(t, owner, `DELETE FROM ops_admission_v2.compliance_events WHERE id=$1`, added)
	functionalExec(t, owner, `DELETE FROM ops_admission_v2.compliance_events WHERE id=$1`, ids[len(ids)-1])
	request(path, query, 409)
	// A lower allocated ID can commit after the first observation. This must not
	// be silently omitted by treating an ID upper bound as a committed frontier.
	other, err := pgx.Connect(ctx, financeDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close(context.Background())
	tx, err := other.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	low := insert(tx, f.Org, f.Actor(f.Subject), clock())
	high := insert(owner, f.Org, f.Actor(f.Subject), clock())
	if low >= high {
		t.Fatal("ID race fixture")
	}
	snap, err = finance.OpenPage(ctx, rs, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	before := request(path, initial, 200)
	var race pageResult
	_ = json.Unmarshal(before, &race)
	if tx.Commit(ctx) != nil || !errors.Is(snap.CheckCurrent(ctx), d.ErrConflict) {
		t.Fatal("late lower-ID commit not detected")
	}
	snap.Close()
	query.Cursor = race.Result.NextCursor
	request(path, query, 409)
	// Both lower levels preserve existing evidence field omissions.
	for _, level := range []p.Level{p.Redacted, p.Pseudonymous} {
		q := initial
		q.Level = &level
		raw := request(path, q, 200)
		if bytes.Contains(raw, []byte(`"transactionHash"`)) || bytes.Contains(raw, []byte(`"recordId"`)) || bytes.Contains(raw, []byte(`"reason"`)) {
			t.Fatal("lower-level raw evidence", string(raw))
		}
	}
	// Narrowed integer-second interval is server applied, not a local-page filter.
	q := initial
	q.DataTime = &p.Interval{Start: f.Now - 1, End: f.Now - 1}
	var zero pageResult
	_ = json.Unmarshal(request(path, q, 200), &zero)
	if zero.Result.MatchingRetainedCount != "0" || len(zero.Result.Items) != 0 || zero.Result.NextCursor != nil {
		t.Fatal("zero narrowed cohort")
	}
	// Source bytes cannot escape an unsuccessful locked-case audit commit.
	failedCfg := cfg
	failedCfg.Store = financeAuditFailure{store}
	failed, err := c.NewWithRetainedData(failedCfg, data)
	if err != nil {
		t.Fatal(err)
	}
	if response, err := failed.Read(ctx, token, opened.CaseID, initial); response != nil || err == nil {
		t.Fatal("uncommitted exposure returned response")
	}
	response, err := service.Read(ctx, token, opened.CaseID, initial)
	if err != nil {
		t.Fatal(err)
	}
	now.Store(f.Now + 121)
	var output bytes.Buffer
	if _, err := response.WriteTo(&output); err == nil || output.Len() != 0 {
		t.Fatal("expired final delivery exposed bytes")
	}
	now.Store(f.Now)
	// The bound applies to the full cohort, not just the25 retained page bodies.
	functionalExec(t, owner, `INSERT INTO ops_admission_v2.compliance_events(network_key,tx_hash,actor_id,org_id,kind,coverage,from_address,to_address,amount_wei,currency,decision,monitored,reason,decision_at,policy_digest,anchor_hash,anchor_number,anchor_timestamp,evidence_profile)SELECT $1,$2,$3,$4::uuid,'root_native','root_transfer',$5,$6,'1','usd','allowed',false,repeat('b',2000),$7,$8,$9,1,1,$10 FROM generate_series(1,1000)`, key[:], bytes.Repeat([]byte{3}, 32), f.Actor(f.Subject), f.Org, bytes.Repeat([]byte{11}, 20), bytes.Repeat([]byte{12}, 20), clock(), bytes.Repeat([]byte{4}, 32), bytes.Repeat([]byte{5}, 32), rpcexecution.GuardRetainedProfileID)
	request(path, initial, 422)
	functionalExec(t, owner, `DELETE FROM ops_admission_v2.compliance_events WHERE reason=repeat('b',2000)`)
	lock, err := owner.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Rollback(context.Background())
	if _, err = lock.Exec(ctx, `LOCK TABLE ops_admission_v2.compliance_events IN ACCESS EXCLUSIVE MODE`); err != nil {
		t.Fatal(err)
	}
	short, cancel := context.WithTimeout(ctx, 40*time.Millisecond)
	defer cancel()
	started := time.Now()
	if pending, err := finance.OpenPage(short, rs, nil, nil); pending != nil || !errors.Is(err, d.ErrUnavailable) || time.Since(started) > time.Second {
		t.Fatal("page SQL deadline", err)
	}
}

func ptrFinance[T any](v T) *T { return &v }
