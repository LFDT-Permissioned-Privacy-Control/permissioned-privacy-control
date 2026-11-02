package perfgate

import (
	"context"
	"fmt"
	"io"
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
	records := OpenLoop(context.Background(), NewLoadClient(64), target, 1000, 200, start)
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
