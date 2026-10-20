package nodehttp

import (
	"bytes"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// These benchmarks prove the upstream-transport fix (RD-1112): forwarding to a
// single node host under concurrency with Go's default transport
// (MaxIdleConnsPerHost=2) churns TCP connections, while the tuned transport
// reuses a warm pool. The headline metric is "newconns" — total TCP
// connections opened over the run. Lower = less churn / TIME_WAIT / ephemeral
// port pressure. ns/op understates the prod win because loopback dial is ~free;
// across a real network each avoided dial is a full RTT + handshake.
//
//	go test -run '^$' -bench BenchmarkUpstreamForward -benchtime=2s ./internal/nodehttp/

func benchUpstreamForward(b *testing.B, client *http.Client) {
	var newConns int64

	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		_ = r.Body.Close()
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":"0x1"}`)
	})

	srv := httptest.NewUnstartedServer(h)
	srv.Config.ConnState = func(_ net.Conn, s http.ConnState) {
		if s == http.StateNew {
			atomic.AddInt64(&newConns, 1)
		}
	}
	srv.Start()
	defer srv.Close()

	reqBody := []byte(`{"jsonrpc":"2.0","method":"eth_sendRawTransaction","params":["0xf86c..."],"id":1}`)

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			req, err := http.NewRequest(http.MethodPost, srv.URL, bytes.NewReader(reqBody))
			if err != nil {
				b.Error(err)
				return
			}
			req.Header.Set("Content-Type", "application/json")
			resp, err := client.Do(req)
			if err != nil {
				b.Error(err)
				return
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
		}
	})
	b.StopTimer()

	total := atomic.LoadInt64(&newConns)
	b.ReportMetric(float64(total), "newconns")
	if b.N > 0 {
		b.ReportMetric(float64(total)/float64(b.N)*1000, "newconns/Kreq")
	}
}

// BenchmarkUpstreamForward_DefaultTransport replicates the pre-fix client:
// &http.Client{Timeout} → http.DefaultTransport (MaxIdleConnsPerHost=2).
func BenchmarkUpstreamForward_DefaultTransport(b *testing.B) {
	benchUpstreamForward(b, &http.Client{Timeout: 30 * time.Second})
}

// BenchmarkUpstreamForward_TunedTransport uses the fix.
func BenchmarkUpstreamForward_TunedTransport(b *testing.B) {
	benchUpstreamForward(b, NewClient(30*time.Second, DefaultTransportConfig()))
}
