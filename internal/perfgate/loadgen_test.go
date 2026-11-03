package perfgate

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func echoTarget(t *testing.T, n int, handler http.HandlerFunc) Target {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	target := Target{URL: server.URL}
	for i := 0; i < n; i++ {
		hash := fmt.Sprintf("0x%064x", i)
		target.Bodies = append(target.Bodies, []byte(`{"id":1,"params":["`+hash+`"]}`))
		target.Tokens = append(target.Tokens, "token")
		target.Expected = append(target.Expected, hash)
	}
	return target
}

func echoHandler(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	hash := strings.Split(strings.Split(string(body), `["`)[1], `"]`)[0]
	if r.Header.Get("Authorization") != "Bearer token" {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	if strings.HasSuffix(hash, "7") {
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"no"}}`))
		return
	}
	_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":"` + hash + `"}`))
}

func TestOpenLoopOffersAtTheRequestedRateAndClassifiesReplies(t *testing.T) {
	target := echoTarget(t, 200, echoHandler)
	start := time.Now().Add(20 * time.Millisecond)
	records := OpenLoop(context.Background(), NewLoadClient(64), target, 1000, 200, start, 64)
	ok, rpc := 0, 0
	for i, r := range records {
		if want := start.Add(time.Duration(i) * time.Millisecond); !r.Scheduled.Equal(want) {
			t.Fatalf("request %d scheduled %s, want %s", i, r.Scheduled, want)
		}
		if r.OK {
			ok++
		}
		if r.RPCError == -32000 {
			rpc++
		}
	}
	wantRPC := 0
	for _, hash := range target.Expected {
		if strings.HasSuffix(hash, "7") {
			wantRPC++
		}
	}
	if ok != 200-wantRPC || rpc != wantRPC {
		t.Fatalf("ok=%d rpc errors=%d, want %d/%d", ok, rpc, 200-wantRPC, wantRPC)
	}
	if spread := records[len(records)-1].Sent.Sub(records[0].Sent); spread < 150*time.Millisecond {
		t.Fatalf("requests were not paced: %s", spread)
	}
}

func TestClosedLoopKeepsConcurrencyAndStops(t *testing.T) {
	var inFlight, peak atomic.Int64
	target := echoTarget(t, 10_000, func(w http.ResponseWriter, r *http.Request) {
		now := inFlight.Add(1)
		for {
			p := peak.Load()
			if now <= p || peak.CompareAndSwap(p, now) {
				break
			}
		}
		time.Sleep(time.Millisecond)
		inFlight.Add(-1)
		echoHandler(w, r)
	})
	records := ClosedLoop(context.Background(), NewLoadClient(64), target, 8, time.Now().Add(150*time.Millisecond))
	if len(records) == 0 || len(records) >= 10_000 {
		t.Fatalf("closed loop sent %d", len(records))
	}
	if peak.Load() > 8 {
		t.Fatalf("peak concurrency %d above 8", peak.Load())
	}
	for _, r := range records {
		if r.Done.IsZero() || r.Scheduled.IsZero() {
			t.Fatalf("incomplete record %+v", r)
		}
	}
}

// countingServer counts the TCP connections the runner opens and the peak
// number of requests the server sees at once.
type countingServer struct {
	conns, inFlight, peak atomic.Int64
}

func (c *countingServer) start(t *testing.T, n int, delay time.Duration) Target {
	t.Helper()
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		now := c.inFlight.Add(1)
		for {
			p := c.peak.Load()
			if now <= p || c.peak.CompareAndSwap(p, now) {
				break
			}
		}
		select {
		case <-time.After(delay):
		case <-r.Context().Done():
		}
		c.inFlight.Add(-1)
		echoHandler(w, r)
	}))
	server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			c.conns.Add(1)
		}
	}
	server.Start()
	t.Cleanup(server.Close)
	target := Target{URL: server.URL}
	for i := 0; i < n; i++ {
		hash := fmt.Sprintf("0x%063x0", i) // ends in 0, never 7: every reply is a success
		target.Bodies = append(target.Bodies, []byte(`{"id":1,"params":["`+hash+`"]}`))
		target.Tokens = append(target.Tokens, "token")
		target.Expected = append(target.Expected, hash)
	}
	return target
}

// R12.1: the open loop keeps at most `workers` requests in flight on at most
// `workers` keep-alive connections. When the server is slower than
// workers/rate, the overflow waits in the runner and shows as send lag from
// the schedule; it never opens extra connections or fails in transport.
// Admission stops at the end of the offered schedule, and the backlog left
// then is reported as not sent (rejections), with every record kept at its
// index.
func TestOpenLoopIsBoundedByItsConnectionPool(t *testing.T) {
	var server countingServer
	// 1,000/s offered for 300 ms against 8 workers × 10 ms = 800/s capacity.
	target := server.start(t, 300, 10*time.Millisecond)
	start := time.Now().Add(20 * time.Millisecond)
	const workers = 8
	records := OpenLoop(context.Background(), NewLoadClient(workers), target, 1000, 300, start, workers)
	if len(records) != 300 {
		t.Fatalf("records %d, want one per offered request", len(records))
	}
	if got := server.conns.Load(); got > workers {
		t.Fatalf("runner opened %d connections, want <= %d", got, workers)
	}
	if got := server.peak.Load(); got > workers {
		t.Fatalf("server saw %d concurrent requests, want <= %d", got, workers)
	}
	lagged, notSent := 0, 0
	for i, r := range records {
		if want := start.Add(time.Duration(i) * time.Millisecond); !r.Scheduled.Equal(want) {
			t.Fatalf("request %d scheduled %s, want %s", i, r.Scheduled, want)
		}
		if r.TransportError {
			t.Fatalf("request %d transport error: %+v", i, r)
		}
		if r.Sent.IsZero() {
			notSent++
			continue
		}
		if !r.OK {
			t.Fatalf("request %d failed: %+v", i, r)
		}
		if r.Sent.Sub(r.Scheduled) > 5*time.Millisecond {
			lagged++
		}
	}
	if lagged < 20 || notSent == 0 || server.peak.Load() != workers {
		t.Fatalf("lagged %d, not sent %d, server peak %d: the runner queue is not measured", lagged, notSent, server.peak.Load())
	}
	report := Account(records, Phases{Start: start, WindowStart: start, WindowEnd: start.Add(time.Hour)})
	if report.NotSent != notSent || report.RejectedScheduledInWindow != notSent || report.Failures["not_sent"] != notSent {
		t.Fatalf("unsent requests must be rejections: %+v", report)
	}
	if report.ConnectionsOpened > workers || report.PeakInFlight != workers || report.RunnerTransportErrors != 0 || !report.Valid {
		t.Fatalf("report %+v", report)
	}
}

// A run deadline ends requests that are still in flight; they are unfinished
// or unsent rejections, never transport errors, and the loop returns promptly.
func TestOpenLoopRunDeadlineLeavesUnfinishedNotTransportErrors(t *testing.T) {
	var server countingServer
	target := server.start(t, 40, 2*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	began := time.Now()
	// 100/s × 40 = a 400 ms schedule that outlasts the 300 ms deadline.
	records := OpenLoop(ctx, NewLoadClient(4), target, 100, 40, began.Add(20*time.Millisecond), 4)
	if took := time.Since(began); took > time.Second {
		t.Fatalf("open loop returned after %s, want the run deadline", took)
	}
	report := Account(records, Phases{Start: began, WindowStart: began, WindowEnd: began.Add(time.Hour)})
	if len(records) != 40 || report.ScheduledInWindow != 40 || report.RejectedScheduledInWindow != 40 {
		t.Fatalf("every offered request must be accounted: %d records, %+v", len(records), report)
	}
	if report.RunnerTransportErrors != 0 || report.Unfinished != 4 || report.NotSent != 36 {
		t.Fatalf("report %+v", report)
	}
}

// A connection the server closes after holding the request for its own
// timeout is a server rejection, not a runner fault.
func TestServerTimeoutIsNotARunnerTransportError(t *testing.T) {
	start := time.Unix(1_000, 0)
	records := []RequestRecord{{Scheduled: start, Sent: start, TransportError: true, TransportErrorKind: "server_timeout"}}
	report := Account(records, Phases{Start: start, WindowStart: start, WindowEnd: start.Add(time.Hour)})
	if report.RunnerTransportErrors != 0 || !report.Valid || report.Failures["server_timeout"] != 1 || report.RejectedScheduledInWindow != 1 {
		t.Fatalf("report %+v", report)
	}
	if kind := classifyNoResponse(io.EOF, time.Now().Add(-ServerTimeoutAfter)); kind != "server_timeout" {
		t.Fatalf("EOF after the server timeout classified %q", kind)
	}
	if kind := classifyNoResponse(io.EOF, time.Now()); kind != "eof" {
		t.Fatalf("early EOF classified %q", kind)
	}
}

// A dial failure is a runner transport error: it is counted on its own and
// makes the result invalid.
func TestTransportErrorsAreCountedSeparatelyAndInvalidateTheRun(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	url := "http://" + l.Addr().String()
	_ = l.Close() // nothing listens: every dial is refused
	target := Target{URL: url, Bodies: [][]byte{[]byte(`{}`), []byte(`{}`)}, Tokens: []string{"", ""}, Expected: []string{"a", "b"}}
	start := time.Now().Add(50 * time.Millisecond)
	records := OpenLoop(context.Background(), NewLoadClient(2), target, 100, 2, start, 2)
	report := Account(records, Phases{Start: start, WindowStart: start, WindowEnd: start.Add(time.Hour)})
	if report.RunnerTransportErrors != 2 || report.TransportErrorKinds["dial"] != 2 {
		t.Fatalf("transport errors %d kinds %v", report.RunnerTransportErrors, report.TransportErrorKinds)
	}
	if report.Valid || report.InvalidReason == "" {
		t.Fatalf("a run with transport errors must be invalid: %+v", report)
	}
	if report.RejectedScheduledInWindow != 2 {
		t.Fatalf("transport errors must still be rejections: %+v", report)
	}
}
