package perfgate

import (
	"math"
	"testing"
	"time"
)

func phasesAt(start time.Time, warmup, window time.Duration) Phases {
	return Phases{Start: start, WindowStart: start.Add(warmup), WindowEnd: start.Add(warmup + window)}
}

func okRecord(scheduled time.Time, latency time.Duration) RequestRecord {
	return RequestRecord{Scheduled: scheduled, Sent: scheduled, Done: scheduled.Add(latency), HTTPStatus: 200, OK: true}
}

func TestAccountCountsOnlyCompletionsInsideTheWindow(t *testing.T) {
	start := time.Unix(1_000, 0)
	p := phasesAt(start, 30*time.Second, 60*time.Second)
	records := []RequestRecord{
		okRecord(start.Add(time.Second), time.Millisecond),                           // warm-up
		okRecord(start.Add(29*time.Second+999*time.Millisecond), 2*time.Millisecond), // scheduled in warm-up, done in window
		okRecord(start.Add(40*time.Second), time.Millisecond),                        // window
		okRecord(start.Add(89*time.Second+999*time.Millisecond), 5*time.Millisecond), // scheduled in window, done in drain
		okRecord(start.Add(95*time.Second), time.Millisecond),                        // drain
	}
	got := Account(records, p)
	if got.CompletedInWindow != 2 {
		t.Fatalf("completed in window = %d, want 2 (warm-up and drain completions excluded)", got.CompletedInWindow)
	}
	if want := 2.0 / 60; math.Abs(got.AchievedPerSecond-want) > 1e-9 {
		t.Fatalf("achieved %.6f, want %.6f", got.AchievedPerSecond, want)
	}
	if got.ScheduledInWindow != 2 {
		t.Fatalf("scheduled in window = %d, want 2", got.ScheduledInWindow)
	}
	if got.Phase["warmup"].OK != 1 || got.Phase["window"].OK != 2 || got.Phase["drain"].OK != 2 {
		t.Fatalf("per-phase ok %+v", got.Phase)
	}
}

func TestAccountCountsRejectionsByCompletionPhase(t *testing.T) {
	start := time.Unix(1_000, 0)
	p := phasesAt(start, 10*time.Second, 60*time.Second)
	reject := func(at time.Time, status, rpc int) RequestRecord {
		return RequestRecord{Scheduled: at, Sent: at, Done: at.Add(time.Millisecond), HTTPStatus: status, RPCError: rpc}
	}
	records := []RequestRecord{
		reject(start.Add(time.Second), 503, 0),
		reject(start.Add(20*time.Second), 200, -32000),
		reject(start.Add(21*time.Second), 429, 0),
		{Scheduled: start.Add(22 * time.Second), Sent: start.Add(22 * time.Second), TransportError: true},
		{Scheduled: start.Add(23 * time.Second), Sent: start.Add(23 * time.Second)}, // sent, never answered before the run ended
		{Scheduled: start.Add(24 * time.Second)},                                    // never sent: the offered schedule ended first
		reject(start.Add(75*time.Second), 503, 0),
	}
	got := Account(records, p)
	if got.Phase["warmup"].Rejected != 1 || got.Phase["window"].Rejected != 5 || got.Phase["drain"].Rejected != 1 {
		t.Fatalf("rejections %+v", got.Phase)
	}
	if got.Unfinished != 1 || got.NotSent != 1 {
		t.Fatalf("unfinished %d, not sent %d", got.Unfinished, got.NotSent)
	}
	want := map[string]int{"http_503": 2, "rpc_-32000": 1, "http_429": 1, "transport": 1, "unfinished": 1, "not_sent": 1}
	for k, v := range want {
		if got.Failures[k] != v {
			t.Fatalf("failures %v, want %v", got.Failures, want)
		}
	}
	if got.CompletedInWindow != 0 {
		t.Fatalf("a rejected request counted as completed")
	}
}

func TestAccountLatencyIsMeasuredFromScheduledTime(t *testing.T) {
	start := time.Unix(1_000, 0)
	p := phasesAt(start, 0, 60*time.Second)
	var records []RequestRecord
	for i := 0; i < 100; i++ {
		at := start.Add(time.Duration(i) * 10 * time.Millisecond)
		// The pacer fell behind: sent 40 ms late, answered 1 ms after sending.
		records = append(records, RequestRecord{Scheduled: at, Sent: at.Add(40 * time.Millisecond), Done: at.Add(41 * time.Millisecond), HTTPStatus: 200, OK: true})
	}
	got := Account(records, p)
	if got.LatencyMS.P50 != 41 || got.LatencyMS.P99 != 41 || got.LatencyMS.Max != 41 {
		t.Fatalf("latency %+v, want 41 ms from the scheduled time", got.LatencyMS)
	}
	if got.SendLagMS.P50 != 40 {
		t.Fatalf("send lag %+v", got.SendLagMS)
	}
}

func TestPercentilesNearestRank(t *testing.T) {
	values := make([]time.Duration, 0, 100)
	for i := 100; i >= 1; i-- {
		values = append(values, time.Duration(i)*time.Millisecond)
	}
	got := Percentiles(values)
	if got.P50 != 50 || got.P99 != 99 || got.Max != 100 || got.Count != 100 {
		t.Fatalf("percentiles %+v", got)
	}
	if empty := Percentiles(nil); empty.Count != 0 || empty.Max != 0 {
		t.Fatalf("empty %+v", empty)
	}
}

func TestTrendPerSecond(t *testing.T) {
	start := time.Unix(0, 0)
	var rising, flat []Sample
	for i := 0; i < 60; i++ {
		at := start.Add(time.Duration(i) * time.Second)
		rising = append(rising, Sample{At: at, Value: float64(100 + 25*i)})
		flat = append(flat, Sample{At: at, Value: 7})
	}
	if slope := Trend(rising); math.Abs(slope-25) > 1e-9 {
		t.Fatalf("rising slope %f", slope)
	}
	if slope := Trend(flat); slope != 0 {
		t.Fatalf("flat slope %f", slope)
	}
	if slope := Trend(rising[:1]); slope != 0 {
		t.Fatalf("single sample slope %f", slope)
	}
}

func TestAccountCountsWindowScheduledRejectionsThatEndInDrain(t *testing.T) {
	start := time.Unix(1_000, 0)
	p := phasesAt(start, 10*time.Second, 60*time.Second)
	late := start.Add(69*time.Second + 900*time.Millisecond)
	records := []RequestRecord{{Scheduled: late, Sent: late, Done: late.Add(500 * time.Millisecond), HTTPStatus: 503}}
	got := Account(records, p)
	if got.Phase["drain"].Rejected != 1 || got.RejectedScheduledInWindow != 1 {
		t.Fatalf("a window request rejected after the edge must still fail the window: %+v", got)
	}
}
