package perfgate

import (
	"bufio"
	"context"
	"math"
	"strconv"
	"strings"
	"time"
)

// A stationary sealed sequence cannot distinguish an empty buffer from a
// stalled sealer. Only the server's conservative backlog and health gauges
// support a positive drain observation. Older servers lack them: unknown.
type auditObservation struct {
	known, healthy bool
	backlog        float64
}

func observeAuditMetrics(text string) auditObservation {
	var result auditObservation
	var pending, degraded, stopped bool
	result.healthy = true
	scanner := bufio.NewScanner(strings.NewReader(text))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 2 || strings.HasPrefix(fields[0], "#") {
			continue
		}
		name := strings.SplitN(fields[0], "{", 2)[0]
		if name != "privacyproxy_audit_sealing_backlog_entries" && name != "privacyproxy_audit_sealing_degraded" && name != "privacyproxy_audit_sealing_stopped" {
			continue
		}
		value, err := strconv.ParseFloat(fields[1], 64)
		if err != nil || math.IsNaN(value) || math.IsInf(value, 0) || value < 0 {
			return auditObservation{}
		}
		switch name {
		case "privacyproxy_audit_sealing_backlog_entries":
			if pending { // duplicate gauges cannot establish a measurement
				return auditObservation{}
			}
			pending, result.backlog = true, value
		case "privacyproxy_audit_sealing_degraded":
			degraded = true
			result.healthy = result.healthy && value == 0
		case "privacyproxy_audit_sealing_stopped":
			stopped = true
			result.healthy = result.healthy && value == 0
		}
	}
	result.known = scanner.Err() == nil && pending && degraded && stopped
	return result
}

type auditDrainObservation struct {
	Drained, Observed, LifecycleComplete                  bool
	WaitSeconds, FromWindowEndSeconds                     float64
	FinalBacklog                                          *float64
	VisibilityCheckedAt, LastAuditStarted, LastAuditEnded time.Time
}

// The entire metrics read must follow a query showing all relevant rows visible and
// finish within the deadline. Record both edges to avoid counting a scrape
// that straddled either boundary as proof.
type AuditSample struct {
	Started time.Time `json:"started"`
	Ended   time.Time `json:"ended"`
	Backlog float64   `json:"backlog"`
	Healthy bool      `json:"healthy"`
}

func auditTailObserved(samples []AuditSample, visibleAt, deadline time.Time) bool {
	for _, s := range samples {
		if !s.Started.Before(visibleAt) && !s.Ended.After(deadline) && !s.Ended.Before(s.Started) && s.Healthy && s.Backlog == 0 {
			return true
		}
	}
	return false
}

// finalizedCohort freezes only hashes the node had finalized by the window
// edge. It contains no OPS timestamps: an INSERT timestamp is not a commit.
func finalizedCohort(stamps map[string]Stamp, windowEnd time.Time) []string {
	var hashes []string
	for hash, stamp := range stamps {
		if stamp.Finalized > 0 && stamp.Finalized <= windowEnd.UnixNano() {
			hashes = append(hashes, hash)
		}
	}
	return hashes
}

// TailObservation records actual visibility and audit reads within the tail
// deadline. VisibleAt is a query-completion bound, never a commit timestamp.
type TailObservation struct {
	Method             string        `json:"method"`
	VisibilityObserved bool          `json:"visibility_observed"`
	Reconciled         bool          `json:"reconciled"`
	AuditObserved      bool          `json:"audit_observed"`
	AuditDrained       bool          `json:"audit_drained"`
	CohortSize         *int          `json:"cohort_size,omitempty"`
	VisibleAt          time.Time     `json:"visible_at,omitempty"`
	QueryStarted       time.Time     `json:"query_started,omitempty"`
	QueryEnded         time.Time     `json:"query_ended,omitempty"`
	AuditSamples       []AuditSample `json:"audit_samples,omitempty"`
}

// Observe the already-finalized prefix late in the 30-second tail, after the
// throughput window. All matching status rows must be visible before a fresh
// healthy empty-buffer scrape. A late query/scrape can never establish the
// bound, even when its rows have old final_at values.
func observeFinalizedTail(ctx context.Context, stamps func() (map[string]Stamp, error), visible func(context.Context, []string) (bool, error), scrape func(context.Context) (string, error), windowEnd, begin, deadline time.Time, interval time.Duration) (out TailObservation) {
	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	timer := time.NewTimer(max(0, time.Until(begin)))
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return out
	case <-timer.C:
	}
	if time.Now().Before(windowEnd) {
		return out
	}
	snapshot, err := stamps()
	if err != nil || time.Now().After(deadline) {
		return out
	}
	hashes := finalizedCohort(snapshot, windowEnd)
	cohortSize := len(hashes)
	out.CohortSize = &cohortSize
	out.Method = "finalized_prefix_visibility"
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		if !out.Reconciled {
			out.QueryStarted = time.Now()
			complete, err := visible(ctx, hashes)
			out.QueryEnded = time.Now()
			if err == nil && !out.QueryEnded.After(deadline) {
				out.VisibilityObserved = true
				if complete {
					out.Reconciled = true
					out.VisibleAt = out.QueryEnded
				}
			}
		}
		if out.Reconciled {
			started := time.Now()
			text, err := scrape(ctx)
			ended := time.Now()
			if observed := observeAuditMetrics(text); err == nil && observed.known && !ended.After(deadline) {
				out.AuditObserved = true
				out.AuditSamples = append(out.AuditSamples, AuditSample{Started: started, Ended: ended, Backlog: observed.backlog, Healthy: observed.healthy})
				if auditTailObserved(out.AuditSamples, out.VisibleAt, deadline) {
					out.AuditDrained = true
					return out
				}
			}
		}
		select {
		case <-ctx.Done():
			return out
		case <-ticker.C:
		}
	}
}

// ReconcileSample records a committed-row snapshot followed by node finality.
// The ordering makes BacklogUpperBound conservative for a fresh unique ledger.
type ReconcileSample struct {
	QueryStarted      time.Time `json:"query_started"`
	QueryEnded        time.Time `json:"query_ended"`
	NodeObservedAt    time.Time `json:"node_observed_at"`
	VisibleFinalized  int64     `json:"visible_finalized"`
	NodeFinalized     int64     `json:"node_finalized"`
	BacklogUpperBound int64     `json:"backlog_upper_bound"`
}

// Counts whose entire SQL reads lie inside the window bound only commits
// between those two snapshots. They cannot overstate whole-window commits.
func visibleWindowCommits(samples []ReconcileSample, start, end time.Time) (count int64, observations int, known bool) {
	var first, last *ReconcileSample
	for i := range samples {
		s := &samples[i]
		if s.QueryStarted.Before(start) || s.QueryEnded.After(end) || s.QueryEnded.Before(s.QueryStarted) {
			continue
		}
		if first == nil {
			first = s
		}
		last = s
		observations++
	}
	if first == nil || last == first || last.VisibleFinalized < first.VisibleFinalized {
		return 0, observations, false
	}
	return last.VisibleFinalized - first.VisibleFinalized, observations, true
}

// Window coverage is required before an empty/flat observed series can
// establish a bounded backlog. One point or a long sampling hole is unknown,
// even when all observed values happen to be zero.
func windowCoverage(samples []Sample, start, end time.Time, maxGap time.Duration) (count int, adequate bool) {
	if !end.After(start) || maxGap <= 0 {
		return 0, false
	}
	var first, last time.Time
	ordered := true
	for _, sample := range samples {
		if sample.At.Before(start) || !sample.At.Before(end) {
			continue
		}
		if count == 0 {
			first = sample.At
		} else if !sample.At.After(last) || sample.At.Sub(last) > maxGap {
			ordered = false
		}
		last = sample.At
		count++
	}
	needed := int(math.Ceil(float64(end.Sub(start)) / float64(maxGap)))
	adequate = ordered && count >= max(2, needed) && first.Sub(start) <= maxGap && end.Sub(last) <= maxGap
	return count, adequate
}

// Read committed status counts before node finality. New finalizations or
// intervening commits can only overstate backlog, not invent a drained tail.
func conservativeBacklog(committed, finalized int64) (int64, bool) {
	if committed < 0 || finalized < committed {
		return 0, false
	}
	return finalized - committed, true
}

// Future finalizations can append more audit records after an idle tick.
// Require both completed transaction lifecycles and a healthy empty buffer.
func waitForAuditDrain(ctx context.Context, scrape func(context.Context) (string, error), settled func(context.Context) (bool, error), limit, interval time.Duration, windowEnd time.Time) (result auditDrainObservation) {
	start := time.Now()
	defer func() {
		result.WaitSeconds = time.Since(start).Seconds()
		result.FromWindowEndSeconds = max(0, time.Since(windowEnd).Seconds())
	}()
	ctx, cancel := context.WithTimeout(ctx, limit)
	defer cancel()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	stable := 0
	for {
		complete, settledErr := settled(ctx)
		result.VisibilityCheckedAt = time.Now()
		result.LastAuditStarted = time.Now()
		metrics, err := scrape(ctx)
		result.LastAuditEnded = time.Now()
		observation := observeAuditMetrics(metrics)
		result.Observed = err == nil && observation.known
		if !result.Observed {
			return result
		}
		backlog := observation.backlog
		result.FinalBacklog = &backlog
		result.LifecycleComplete = settledErr == nil && complete
		if observation.healthy && backlog == 0 && result.LifecycleComplete {
			stable++
			if stable >= 3 {
				result.Drained = true
				return result
			}
		} else {
			stable = 0
		}
		select {
		case <-ctx.Done():
			return result
		case <-ticker.C:
		}
	}
}
