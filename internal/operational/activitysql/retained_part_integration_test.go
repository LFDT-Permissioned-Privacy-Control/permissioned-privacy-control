package activitysql_test

import (
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	a "privacy-proxy/internal/activitylog"
	"privacy-proxy/internal/audit/buffer"
	d "privacy-proxy/internal/disclosuredata"
	p "privacy-proxy/internal/disclosurepolicy"
	f "privacy-proxy/internal/disclosuretest"
	"privacy-proxy/internal/operational/activitysource"
	s "privacy-proxy/internal/operational/activitysql"
)

func TestRetainedActivityPartClosesActualSQLBeforeOtherSources(t *testing.T) {
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
	entries := []buffer.Entry{attributed(t, testEntry(t, run.Binding(), 1, f.Now*1000000), "eth_call", true), attributed(t, testEntry(t, run.Binding(), 2, f.Now*1000000+1), "explorer.blocks", true)}
	if err = run.SealBatch(ctx, entries); err != nil {
		t.Fatal(err)
	}
	digest := d.Digest("sha256:" + strings.Repeat("1", 64))
	plan := d.SourcePlan{Version: 2, Profile: d.RetainedSourceProfile, BundleDigest: digest, NetworkKey: d.Digest("sha256:" + hexDigest(reader.Metadata().NetworkKey)), PlanDigest: digest, Resources: []p.Resource{p.ActivityLogs, p.ActivitySummary, p.ComplianceReport}}
	part, err := activitysource.NewRetainedPart(reader, plan)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = activitysource.New(reader, plan); err == nil {
		t.Fatal("legacy constructor accepted retained whole plan")
	}
	scopeFor := func(resource p.Resource) d.ReadScope {
		view := d.Report
		limit := uint16(1)
		query := d.Query{Version: 1, Resource: resource, View: view}
		if resource == p.ActivityLogs {
			query.View = d.List
			query.Limit = &limit
		}
		queryScope := p.Scope{TargetActors: []string{f.Actor(f.Subject)}, Resources: []p.Resource{resource}, Addresses: p.Addresses{Mode: "all-target-addresses", Values: []string{}}, DataTime: p.Interval{Start: f.Now - 1, End: f.Now + 1}, Level: p.Full}
		normalized, err := d.Normalize(query, queryScope)
		if err != nil {
			t.Fatal(err)
		}
		return d.ReadScope{Namespace: digest, CaseID: uuid.NewString(), CaseVersion: 1, RecipientActorID: f.Actor(f.AdminSubject), DataOrganizationID: f.Org, BundleDigest: digest, RuleDigest: digest, EffectiveUntil: time.Unix(f.Now+300, 0).UTC(), Query: normalized}
	}
	scope := scopeFor(p.ActivityLogs)
	first, err := part.Open(ctx, scope, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	facts, err := first.Facts()
	if err != nil || facts.End || len(facts.Activities) != 1 || facts.Next == nil {
		t.Fatal("first actual page", facts, err)
	}
	var held int
	if err = x.owner.QueryRow(ctx, `SELECT count(*) FROM pg_stat_activity WHERE usename=$1 AND xact_start IS NOT NULL`, x.registration.Roles.Reader).Scan(&held); err != nil || held != 0 {
		t.Fatal("activity held SQL across another source", held, err)
	}
	reference := d.SourceRef{Kind: d.ActivitySource, ID: first.Descriptor().Reference}
	second, err := part.Open(ctx, scope, &reference, facts.Next)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	page, err := second.Facts()
	if err != nil || !page.End || len(page.Activities) != 1 || page.Activities[0].Method != "explorer.blocks" {
		t.Fatal("recognized request continuation", page, err)
	}
	if err = second.CheckCurrent(ctx); err != nil {
		t.Fatal("closed actual cut currentness", err)
	}
	compliance, err := part.Open(ctx, scopeFor(p.ComplianceReport), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer compliance.Close()
	summary, err := compliance.Facts()
	if err != nil || summary.ActivitySummary == nil || summary.ActivitySummary.Total != "2" || len(summary.ActivitySummary.Methods) != 2 {
		t.Fatal("whole request compliance aggregate", summary, err)
	}
}
