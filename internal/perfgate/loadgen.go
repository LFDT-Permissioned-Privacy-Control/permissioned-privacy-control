package perfgate

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"sync"
	"sync/atomic"
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

// NewLoadClient keeps connections alive and bounds them, so a server stall
// shows up as latency from the scheduled time instead of port exhaustion.
func NewLoadClient(maxConns int) *http.Client {
	transport := &http.Transport{
		DialContext:         (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		MaxIdleConns:        maxConns,
		MaxIdleConnsPerHost: maxConns,
		MaxConnsPerHost:     maxConns,
		IdleConnTimeout:     90 * time.Second,
		DisableCompression:  true,
	}
	return &http.Client{Transport: transport, Timeout: 60 * time.Second}
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
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), &httptrace.ClientTrace{GotConn: func(httptrace.GotConnInfo) { r.Sent = time.Now() }}))
	resp, err := client.Do(req)
	if err != nil {
		// A run abort cancels in-flight requests: those stay unfinished.
		r.TransportError = ctx.Err() == nil
		return
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	resp.Body.Close()
	r.Done = time.Now()
	r.HTTPStatus = resp.StatusCode
	if err != nil {
		r.TransportError = true
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
// completions (a catch-up pacer: a late dispatcher fires immediately, so the
// offered rate does not drift). It returns once every request has ended or ctx
// is done; unfinished requests keep a zero Done.
func OpenLoop(ctx context.Context, client *http.Client, t Target, rate, n int, start time.Time) []RequestRecord {
	records := make([]RequestRecord, n)
	interval := time.Second / time.Duration(rate)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		if ctx.Err() != nil {
			wg.Wait()
			return records[:i]
		}
		scheduled := start.Add(time.Duration(i) * interval)
		if d := time.Until(scheduled); d > 0 {
			select {
			case <-ctx.Done():
				wg.Wait()
				return records[:i] // never-dispatched requests are not records
			case <-time.After(d):
			}
		}
		records[i].Scheduled = scheduled
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			send(ctx, client, t, i, &records[i])
		}(i)
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
