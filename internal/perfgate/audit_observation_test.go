package perfgate

import (
	"context"
	"fmt"
	"math"
	"testing"
	"time"
)

func auditMetrics(backlog float64) string {
	return fmt.Sprintf("privacyproxy_audit_sealing_backlog_entries %g\nprivacyproxy_audit_sealing_degraded 0\nprivacyproxy_audit_sealing_stopped{reason=\"chain_refused\"} 0\nprivacyproxy_audit_sealing_stopped{reason=\"stalled\"} 0\n", backlog)
}

func TestAuditObservationRequiresDirectHealthyMetrics(t *testing.T) {
	for _, tc := range []struct {
		name, text     string
		known, healthy bool
	}{
		{"empty", auditMetrics(0), true, true},
		{"pending", auditMetrics(17), true, true},
		{"old server without gauges", "unrelated_counter 0\n", false, false},
		{"NaN is not empty", auditMetrics(math.NaN()), false, false},
		{"duplicate gauge", auditMetrics(0) + "privacyproxy_audit_sealing_backlog_entries 0\n", false, false},
		{"degraded", auditMetrics(0) + "privacyproxy_audit_sealing_degraded 1\n", true, false},
		{"refused", auditMetrics(0) + "privacyproxy_audit_sealing_stopped{reason=\"chain_refused\"} 1\n", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := observeAuditMetrics(tc.text)
			if got.known != tc.known || (got.known && got.healthy != tc.healthy) {
				t.Fatalf("observation = %+v, want known=%v healthy=%v", got, tc.known, tc.healthy)
			}
		})
	}
}

func TestStalledAuditProgressIsNeverCountedAsDrained(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	calls := 0
	got := waitForAuditDrain(ctx, func(context.Context) (string, error) {
		calls++
		if calls == 4 {
			cancel()
		}
		return auditMetrics(17), nil // repeated unchanged backlog, no progress
	}, func(context.Context) (bool, error) { return true, nil }, time.Second, time.Millisecond, time.Now().Add(-20*time.Second))
	if got.Drained || !got.Observed || got.FinalBacklog == nil || *got.FinalBacklog != 17 {
		t.Fatalf("stalled sealer claimed drain: %+v", got)
	}
}

func TestAuditDrainWaitsForFutureFinalizationRecords(t *testing.T) {
	calls := 0
	got := waitForAuditDrain(t.Context(), func(context.Context) (string, error) {
		calls++
		return auditMetrics(0), nil
	}, func(context.Context) (bool, error) { return calls >= 4, nil }, time.Second, time.Millisecond, time.Now().Add(-20*time.Second))
	if !got.Drained || !got.LifecycleComplete || calls < 6 || got.FromWindowEndSeconds < 20 {
		t.Fatalf("idle buffer before finalization was counted as full drain: %+v (%d samples)", got, calls)
	}
}

func TestMissingAuditMetricsRemainUnknown(t *testing.T) {
	got := waitForAuditDrain(t.Context(), func(context.Context) (string, error) { return "", nil },
		func(context.Context) (bool, error) { return true, nil }, time.Second, time.Millisecond, time.Now())
	if got.Observed || got.Drained {
		t.Fatalf("missing metrics counted as drain: %+v", got)
	}
}

func TestFinalizedCohortExcludesFutureAndUnincludedHashes(t *testing.T) {
	end := time.Unix(1000, 0)
	hashes := finalizedCohort(map[string]Stamp{
		"old":     {Finalized: end.Add(-time.Second).UnixNano()},
		"future":  {Finalized: end.Add(time.Second).UnixNano()},
		"pending": {},
	}, end)
	if len(hashes) != 1 || hashes[0] != "old" {
		t.Fatalf("wrong prefix: %v", hashes)
	}
}

func TestAuditTailRequiresReadAfterActualVisibilityWithinDeadline(t *testing.T) {
	end := time.Unix(1000, 0)
	visible := end.Add(5 * time.Second)
	for _, s := range []AuditSample{
		{Started: end, Ended: end.Add(time.Second), Healthy: true},
		{Started: visible, Ended: end.Add(31 * time.Second), Healthy: true},
		{Started: visible, Ended: visible.Add(time.Second), Backlog: 1, Healthy: true},
		{Started: visible, Ended: visible.Add(time.Second), Healthy: false},
	} {
		if auditTailObserved([]AuditSample{s}, visible, end.Add(30*time.Second)) {
			t.Fatalf("invalid audit proof: %+v", s)
		}
	}
	if !auditTailObserved([]AuditSample{{Started: visible, Ended: visible.Add(time.Second), Healthy: true}}, visible, end.Add(30*time.Second)) {
		t.Fatal("healthy empty scrape after committed-row visibility did not establish drain")
	}
}

func TestOldInsertTimestampDoesNotProveCommitVisibility(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	now := time.Now()
	got := observeFinalizedTail(ctx, func() (map[string]Stamp, error) {
		return map[string]Stamp{"tx": {Finalized: now.Add(-2 * time.Second).UnixNano()}}, nil
	}, func(context.Context, []string) (bool, error) {
		// The row may have an old final_at in an uncommitted INSERT, but the
		// actual SQL snapshot still cannot see it. Cancel without accepting it.
		cancel()
		return false, nil
	}, func(context.Context) (string, error) { t.Fatal("audit read preceded visibility"); return "", nil },
		now.Add(-time.Second), now, now.Add(time.Second), time.Millisecond)
	if got.Reconciled || got.AuditDrained {
		t.Fatalf("uncommitted row claimed a drained tail: %+v", got)
	}
}

func TestTailObservesVisibleRowsBeforeItsEmptyAuditScrape(t *testing.T) {
	now := time.Now()
	var calls []string
	got := observeFinalizedTail(t.Context(), func() (map[string]Stamp, error) {
		calls = append(calls, "node")
		return map[string]Stamp{"tx": {Finalized: now.Add(-2 * time.Second).UnixNano()}}, nil
	}, func(_ context.Context, hashes []string) (bool, error) {
		calls = append(calls, "visibility")
		if len(hashes) != 1 || hashes[0] != "tx" {
			t.Fatalf("wrong cohort: %v", hashes)
		}
		return true, nil
	}, func(context.Context) (string, error) { calls = append(calls, "audit"); return auditMetrics(0), nil },
		now.Add(-time.Second), now, now.Add(time.Second), time.Millisecond)
	if !got.VisibilityObserved || !got.Reconciled || !got.AuditObserved || !got.AuditDrained || fmt.Sprint(calls) != "[node visibility audit]" {
		t.Fatalf("wrong observation order/proof: %+v %v", got, calls)
	}
	if got.AuditSamples[0].Started.Before(got.QueryEnded) {
		t.Fatal("scrape started before committed visibility")
	}
}

func TestVisibilityReadFinishingAfterDeadlineDoesNotProveTail(t *testing.T) {
	now := time.Now()
	got := observeFinalizedTail(t.Context(), func() (map[string]Stamp, error) {
		return map[string]Stamp{"tx": {Finalized: now.Add(-2 * time.Second).UnixNano()}}, nil
	}, func(ctx context.Context, _ []string) (bool, error) {
		<-ctx.Done() // a query that finally exposes the row after the bound
		return true, nil
	}, func(context.Context) (string, error) {
		t.Fatal("late visibility permitted an audit proof")
		return "", nil
	},
		now.Add(-time.Second), now, now.Add(10*time.Millisecond), time.Millisecond)
	if got.VisibilityObserved || got.Reconciled || got.AuditDrained {
		t.Fatalf("late visibility met deadline: %+v", got)
	}
}

func TestMissingPrefixAuditMetricsRemainUnknown(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	now := time.Now()
	got := observeFinalizedTail(ctx, func() (map[string]Stamp, error) { return map[string]Stamp{}, nil },
		func(context.Context, []string) (bool, error) { return true, nil },
		func(context.Context) (string, error) { cancel(); return "", nil },
		now.Add(-time.Second), now, now.Add(time.Second), time.Millisecond)
	if !got.Reconciled || got.AuditObserved || got.AuditDrained {
		t.Fatalf("missing gauge claimed empty prefix audit: %+v", got)
	}
}

func TestFinalStatusAnswersCannotReduceCommittedBacklog(t *testing.T) {
	stats := MockStats{FinalizedTxs: 10, FinalAnswered: 10}
	got, ok := conservativeBacklog(0, stats.FinalizedTxs)
	if !ok || got != 10 {
		t.Fatalf("uncommitted answers hid backlog: %d %v", got, ok)
	}
	if _, ok := conservativeBacklog(11, 10); ok {
		t.Fatal("inconsistent count snapshots claimed zero backlog")
	}
}

func TestFullAuditDrainReadsLifecycleBeforeMetrics(t *testing.T) {
	var calls []string
	got := waitForAuditDrain(t.Context(), func(context.Context) (string, error) {
		calls = append(calls, "audit")
		return auditMetrics(0), nil
	}, func(context.Context) (bool, error) { calls = append(calls, "visibility"); return true, nil },
		time.Second, time.Millisecond, time.Now())
	if !got.Drained || fmt.Sprint(calls) != "[visibility audit visibility audit visibility audit]" || got.LastAuditStarted.Before(got.VisibilityCheckedAt) {
		t.Fatalf("empty scrape preceded lifecycle visibility: %+v %v", got, calls)
	}
}

func TestWindowCommitsUseOnlyVisibilityReadsInsideWindow(t *testing.T) {
	start := time.Unix(1000, 0)
	end := start.Add(time.Minute)
	samples := []ReconcileSample{
		{QueryStarted: start.Add(-time.Second), QueryEnded: start, VisibleFinalized: 10},
		{QueryStarted: start.Add(time.Second), QueryEnded: start.Add(2 * time.Second), VisibleFinalized: 20},
		{QueryStarted: end.Add(-2 * time.Second), QueryEnded: end.Add(-time.Second), VisibleFinalized: 100},
		{QueryStarted: end.Add(-time.Second), QueryEnded: end.Add(time.Second), VisibleFinalized: 150},
	}
	got, n, known := visibleWindowCommits(samples, start, end)
	if !known || got != 80 || n != 2 {
		t.Fatalf("window visibility = %d %d %v", got, n, known)
	}
	if _, _, known := visibleWindowCommits(samples[:2], start, end); known {
		t.Fatal("one in-window snapshot established commit throughput")
	}
}

func TestWindowCoverageRejectsSparseSamplesAndHoles(t *testing.T) {
	start := time.Unix(1000, 0)
	end := start.Add(time.Minute)
	var dense []Sample
	for second := 1; second < 60; second++ {
		dense = append(dense, Sample{At: start.Add(time.Duration(second) * time.Second), Value: 0})
	}
	if count, ok := windowCoverage(dense, start, end, 2*time.Second); !ok || count != 59 {
		t.Fatalf("dense coverage: %d %v", count, ok)
	}
	for _, tc := range []struct {
		name    string
		samples []Sample
	}{
		{"one zero point", dense[:1]},
		{"fresh endpoint only", dense[58:]},
		{"large middle hole despite enough points", append(append([]Sample{}, dense[:25]...), dense[35:]...)},
		{"stale first point", dense[2:]},
		{"stale last point", dense[:57]},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, ok := windowCoverage(tc.samples, start, end, 2*time.Second); ok {
				t.Fatal("inadequate series established observed window")
			}
		})
	}
}

func TestAuditWindowCoverageDoesNotRequireASequenceEstimate(t *testing.T) {
	start := time.Unix(1000, 0)
	p := Phases{Start: start.Add(-time.Minute), WindowStart: start, WindowEnd: start.Add(time.Minute)}
	report := &Gate2Report{Series: map[string][]Sample{}}
	for second := 1; second < 60; second++ {
		report.Series["audit_pending_entries"] = append(report.Series["audit_pending_entries"], Sample{At: start.Add(time.Duration(second) * time.Second)})
	}
	summarizeAudit(report, nil, p)
	if !report.Audit.BacklogWindowObserved || report.Audit.BacklogWindowSamples != 59 || !report.Audit.BacklogObserved {
		t.Fatalf("direct observations lost without SQL sequence: %+v", report.Audit)
	}
	report.Series["audit_pending_entries"] = report.Series["audit_pending_entries"][58:]
	report.Audit = AuditReport{}
	summarizeAudit(report, nil, p)
	if report.Audit.BacklogWindowObserved || report.Audit.BacklogWindowSamples != 1 {
		t.Fatalf("one point claimed full audit window: %+v", report.Audit)
	}
}
