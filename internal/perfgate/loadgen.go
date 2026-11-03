package perfgate

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// Target is the request stream: Bodies[i] is sent with Tokens[i] and must
// return Expected[i] as its JSON-RPC result.
type Target struct {
	URL      string
	Bodies   [][]byte
	Tokens   []string
	Expected []string
}

// NewLoadClient is the runner's keep-alive pool: at most maxConns
// connections, all kept idle between requests, so the runner never opens and
// discards a connection per request. It has no per-request timeout: a
// mid-flight timeout closes its connection, and redialing under load is what
// exhausted the host's ephemeral ports in P0 (R12.1). The run context bounds
// requests instead. Idle connections are dropped after 30 s, before the OPS
// server's own 60 s idle timeout, so a reused connection is never one the
// server is closing.
func NewLoadClient(maxConns int) *http.Client {
	transport := &http.Transport{
		DialContext:         (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		MaxIdleConns:        maxConns,
		MaxIdleConnsPerHost: maxConns,
		MaxConnsPerHost:     maxConns,
		IdleConnTimeout:     30 * time.Second,
		DisableCompression:  true,
	}
	return &http.Client{Transport: transport}
}

// ServerTimeoutAfter is a safe lower bound on the time after which a
// connection the OPS server drops is its own timeout rather than a runner or
// host fault: its WriteTimeout (30 s, cmd/server/main.go) drops the
// connection; its ReadTimeout (10 s) only cancels the handler's context.
const ServerTimeoutAfter = 9 * time.Second

// classifyNoResponse classifies a request that got no HTTP response. A reset
// or EOF on a request the server held for at least ServerTimeoutAfter is
// "server_timeout": a rejection by OPS. Every other kind is a runner-side
// failure (the request never produced a server decision).
func classifyNoResponse(err error, sent time.Time) string {
	kind := transportKind(err)
	if (kind == "eof" || kind == "reset") && !sent.IsZero() && time.Since(sent) >= ServerTimeoutAfter {
		return "server_timeout"
	}
	return kind
}

func transportKind(err error) string {
	var netErr net.Error
	var opErr *net.OpError
	switch {
	case errors.As(err, &opErr) && opErr.Op == "dial":
		return "dial"
	case errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF):
		return "eof"
	case errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.EPIPE):
		return "reset"
	case errors.As(err, &netErr) && netErr.Timeout():
		return "timeout"
	default:
		return "other"
	}
}

func send(ctx context.Context, client *http.Client, t Target, i int, r *RequestRecord) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.URL, bytes.NewReader(t.Bodies[i]))
	if err != nil {
		r.TransportError = true
		return
	}
	req.Header.Set("Content-Type", "application/json")
	if t.Tokens[i] != "" {
		req.Header.Set("Authorization", "Bearer "+t.Tokens[i])
	}
	// Sent is when a connection was obtained, so waiting for a pooled
	// connection shows up as send lag rather than server time.
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), &httptrace.ClientTrace{GotConn: func(info httptrace.GotConnInfo) {
		r.Sent = time.Now()
		r.NewConn = !info.Reused
	}}))
	resp, err := client.Do(req)
	if err != nil {
		// The run deadline cancels in-flight requests: those stay unfinished.
		if ctx.Err() == nil {
			r.TransportError, r.TransportErrorKind = true, classifyNoResponse(err, r.Sent)
		}
		return
	}
	// Read the whole body so the connection goes back to the pool.
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	r.Done = time.Now()
	r.HTTPStatus = resp.StatusCode
	if err != nil {
		if ctx.Err() == nil {
			r.TransportError, r.TransportErrorKind = true, classifyNoResponse(err, r.Sent)
		} else {
			r.Done = time.Time{}
		}
		return
	}
	var reply struct {
		Result string `json:"result"`
		Error  *struct {
			Code int `json:"code"`
		} `json:"error"`
	}
	if json.Unmarshal(body, &reply) != nil {
		return
	}
	if reply.Error != nil {
		r.RPCError = reply.Error.Code
		if r.RPCError == 0 {
			r.RPCError = -1
		}
		return
	}
	r.OK = resp.StatusCode == http.StatusOK && reply.Result == t.Expected[i]
}

// OpenLoop offers requests 0..n-1 at rate per second from start, regardless of
// completions, through a fixed pool of workers (the client's connection
// count). Request i is due at start + i/rate; the next free worker sends it at
// once if it is overdue (a catch-up pacer, so the offered rate does not drift).
// When every worker is busy the due requests wait in the runner, and that wait
// is part of their latency, which is measured from the schedule. So the
// server never sees more than workers requests at once and the runner never
// opens more than workers connections, while an overloaded server still shows
// up as latency, as requests unfinished at the run deadline, and as requests
// never sent: admission stops at the end of the offered schedule
// (start + n/rate, the end of the steady window), so a backlog is not sent
// into the drain. Every one of the n requests gets a record with its scheduled
// time, so records[i] always belongs to request i and an unsent request is a
// rejection, never a missing row.
func OpenLoop(ctx context.Context, client *http.Client, t Target, rate, n int, start time.Time, workers int) []RequestRecord {
	records := make([]RequestRecord, n)
	interval := time.Second / time.Duration(rate)
	for i := range records {
		records[i].Scheduled = start.Add(time.Duration(i) * interval)
	}
	scheduleEnd := start.Add(time.Duration(n) * interval)
	if workers <= 0 {
		workers = 1
	}
	var next atomic.Int64
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			timer := time.NewTimer(time.Hour)
			timer.Stop()
			defer timer.Stop()
			for ctx.Err() == nil {
				i := int(next.Add(1) - 1)
				if i >= n {
					return
				}
				if d := time.Until(records[i].Scheduled); d > 0 {
					timer.Reset(d)
					select {
					case <-ctx.Done():
						return
					case <-timer.C:
					}
				} else if time.Now().After(scheduleEnd) {
					return // the offered schedule is over: the backlog stays unsent
				}
				send(ctx, client, t, i, &records[i])
			}
		}()
	}
	wg.Wait()
	return records
}

// ClosedLoop runs concurrency workers, each sending its next request as soon
// as its previous one ends, until stop or the requests run out.
func ClosedLoop(ctx context.Context, client *http.Client, t Target, concurrency int, stop time.Time) []RequestRecord {
	records := make([]RequestRecord, len(t.Bodies))
	var next atomic.Int64
	var used atomic.Int64
	var wg sync.WaitGroup
	for w := 0; w < concurrency; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ctx.Err() == nil && time.Now().Before(stop) {
				i := int(next.Add(1) - 1)
				if i >= len(t.Bodies) {
					return
				}
				used.Add(1)
				records[i].Scheduled = time.Now()
				send(ctx, client, t, i, &records[i])
			}
		}()
	}
	wg.Wait()
	return records[:min(int(used.Load()), len(records))]
}
