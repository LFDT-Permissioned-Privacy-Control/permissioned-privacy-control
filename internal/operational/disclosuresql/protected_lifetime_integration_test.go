package disclosuresql_test

import (
	"bytes"
	"context"
	"sync/atomic"
	"testing"
	"time"

	p "privacy-proxy/internal/disclosurepolicy"
	f "privacy-proxy/internal/disclosuretest"
	"privacy-proxy/internal/operational/disclosuresql"
)

// This qualifies actual case/audit COMMIT and the final byte gate; the source
// remains the existing typed gate fixture, not a history-population proof.
func TestActualProtectedOriginalLifetimeAfterAuditCommit(t *testing.T) {
	_, app, _, owner := database(t)
	store, err := disclosuresql.Open(t.Context(), app)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	snapshot := f.Snapshot(t, []p.RuleSource{f.DefaultRule()})
	clock := &atomic.Int64{}
	clock.Store(f.Now)
	service, _, _, _ := newGateService(t, snapshot, store, clock)
	token := f.Token(t, snapshot, f.Subject, "Auditor")
	opened := openGateCase(t, service, token, []p.Resource{p.ActivitySummary}, p.Redacted)
	for _, scenario := range []string{"parent-cancel", "original-deadline"} {
		t.Run(scenario, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			if scenario == "original-deadline" {
				cancel()
				ctx, cancel = context.WithTimeout(t.Context(), time.Second)
			}
			defer cancel()
			before := count(t, owner, "disclosure_events")
			prepared, err := service.Read(ctx, token, opened.CaseID, summaryQuery())
			if err != nil || prepared == nil {
				t.Fatal("prepare", err)
			}
			if count(t, owner, "disclosure_events") != before+1 {
				t.Fatal("no actual committed exposure receipt")
			}
			if scenario == "parent-cancel" {
				cancel()
			} else {
				<-ctx.Done()
			}
			var dst bytes.Buffer
			if _, err := prepared.WriteTo(&dst); err == nil || dst.Len() != 0 {
				t.Fatal("expired original lifetime released committed prepared bytes", err, dst.Len())
			}
		})
	}
}
