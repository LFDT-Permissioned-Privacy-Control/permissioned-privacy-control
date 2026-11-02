package perfgate

import (
	"math"
	"sort"
	"strconv"
	"time"
)

// RequestRecord is one timed request. Scheduled is when the pacer intended to
// send it (open loop) or when the worker became free (closed loop); latency is
// measured from it, so a pacer backlog shows up as latency, not as a lower
// offered rate.
type RequestRecord struct {
	Scheduled      time.Time
	Sent           time.Time
	Done           time.Time
	HTTPStatus     int
	RPCError       int
	TransportError bool
	// OK means HTTP 200, no JSON-RPC error and the expected transaction hash.
	OK bool
}

// Phases splits a run into warm-up [Start, WindowStart), the steady window
// [WindowStart, WindowEnd) and the drain after WindowEnd.
type Phases struct {
	Start, WindowStart, WindowEnd time.Time
}

func (p Phases) of(at time.Time) string {
	switch {
	case at.Before(p.WindowStart):
		return "warmup"
	case at.Before(p.WindowEnd):
		return "window"
	default:
		return "drain"
	}
}

// PhaseCount is the outcome of requests by the phase in which they ended
// (or, for requests that never ended, the phase in which they were scheduled).
type PhaseCount struct {
	OK       int `json:"ok"`
	Rejected int `json:"rejected"`
}

// Millis is a latency distribution in whole milliseconds.
type Millis struct {
	Count int   `json:"count"`
	P50   int64 `json:"p50"`
	P99   int64 `json:"p99"`
	Max   int64 `json:"max"`
}

// WindowReport is the steady-window result. Achieved counts only successful
// completions inside the window, so warm-up and drain never inflate it.
type WindowReport struct {
	WindowSeconds     float64 `json:"window_seconds"`
	CompletedInWindow int     `json:"completed_in_window"`
	AchievedPerSecond float64 `json:"achieved_per_second"`
	ScheduledInWindow int     `json:"scheduled_in_window"`
	// RejectedScheduledInWindow counts every non-success among requests
	// scheduled inside the window, wherever they ended: the pass criterion.
	RejectedScheduledInWindow int                   `json:"rejected_scheduled_in_window"`
	Phase                     map[string]PhaseCount `json:"phase"`
	Failures                  map[string]int        `json:"failures"`
	Unfinished                int                   `json:"unfinished"`
	LatencyMS                 Millis                `json:"latency_ms"`
	SendLagMS                 Millis                `json:"send_lag_ms"`
}

// Account computes the window report. Latency and send lag cover successful
// requests scheduled inside the window, including those that finished during
// the drain, so a slow tail is not hidden by the window edge.
func Account(records []RequestRecord, p Phases) WindowReport {
	report := WindowReport{WindowSeconds: p.WindowEnd.Sub(p.WindowStart).Seconds(), Phase: map[string]PhaseCount{"warmup": {}, "window": {}, "drain": {}}, Failures: map[string]int{}}
	var latency, lag []time.Duration
	for _, r := range records {
		inWindow := p.of(r.Scheduled) == "window"
		if inWindow {
			report.ScheduledInWindow++
		}
		ended := r.Done
		if ended.IsZero() {
			ended = r.Scheduled
		}
		phase := p.of(ended)
		count := report.Phase[phase]
		if r.OK {
			count.OK++
			if phase == "window" {
				report.CompletedInWindow++
			}
			if inWindow {
				latency = append(latency, r.Done.Sub(r.Scheduled))
				lag = append(lag, r.Sent.Sub(r.Scheduled))
			}
		} else {
			count.Rejected++
			if inWindow {
				report.RejectedScheduledInWindow++
			}
			report.Failures[failureClass(r)]++
			if r.Done.IsZero() && !r.TransportError {
				report.Unfinished++
			}
		}
		report.Phase[phase] = count
	}
	if report.WindowSeconds > 0 {
		report.AchievedPerSecond = float64(report.CompletedInWindow) / report.WindowSeconds
	}
	report.LatencyMS = Percentiles(latency)
	report.SendLagMS = Percentiles(lag)
	return report
}

func failureClass(r RequestRecord) string {
	switch {
	case r.TransportError:
		return "transport"
	case r.Done.IsZero():
		return "unfinished"
	case r.HTTPStatus != 200:
		return "http_" + strconv.Itoa(r.HTTPStatus)
	case r.RPCError != 0:
		return "rpc_" + strconv.Itoa(r.RPCError)
	default:
		return "unexpected_result"
	}
}

// Percentiles uses the nearest-rank method on whole milliseconds.
func Percentiles(values []time.Duration) Millis {
	if len(values) == 0 {
		return Millis{}
	}
	sorted := append([]time.Duration(nil), values...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	rank := func(q float64) int64 {
		i := int(math.Ceil(q*float64(len(sorted))-1e-9)) - 1
		if i < 0 {
			i = 0
		}
		if i >= len(sorted) {
			i = len(sorted) - 1
		}
		return sorted[i].Milliseconds()
	}
	return Millis{Count: len(sorted), P50: rank(.50), P99: rank(.99), Max: sorted[len(sorted)-1].Milliseconds()}
}

// Sample is one time-series point (backlog, buffer length, lag).
type Sample struct {
	At    time.Time `json:"at"`
	Value float64   `json:"value"`
}

// Trend is the least-squares slope in units per second; a bounded series
// has a slope near zero over the window.
func Trend(samples []Sample) float64 {
	if len(samples) < 2 {
		return 0
	}
	var sx, sy, sxx, sxy float64
	origin := samples[0].At
	for _, s := range samples {
		x := s.At.Sub(origin).Seconds()
		sx += x
		sy += s.Value
		sxx += x * x
		sxy += x * s.Value
	}
	n := float64(len(samples))
	denominator := n*sxx - sx*sx
	if denominator == 0 {
		return 0
	}
	return (n*sxy - sx*sy) / denominator
}
