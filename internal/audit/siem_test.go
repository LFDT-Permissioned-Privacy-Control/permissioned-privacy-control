package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// mustNewForwarder is a test helper that builds a SIEMForwarder pointing at a
// loopback httptest server. AllowInsecure is set because httptest.NewServer
// gives back an http://127.0.0.1:... URL which the production SSRF guard
// (correctly) rejects. The relaxed mode used here mirrors what server.go
// configures when ENVIRONMENT != "production" (RD-950).
func mustNewForwarder(t *testing.T, cfg SIEMConfig) *SIEMForwarder {
	t.Helper()
	cfg.AllowInsecure = true
	fwd, err := NewSIEMForwarder(cfg)
	if err != nil {
		t.Fatalf("NewSIEMForwarder: %v", err)
	}
	return fwd
}

func TestSIEM_SuccessfulSendClearsBatch(t *testing.T) {
	var received atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var events []SIEMEvent
		if err := json.NewDecoder(r.Body).Decode(&events); err != nil {
			t.Errorf("decode error: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		received.Add(int64(len(events)))
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	fwd := mustNewForwarder(t, SIEMConfig{
		WebhookURL:    srv.URL,
		BatchSize:     100,
		FlushInterval: 50 * time.Millisecond,
	})

	fwd.Send(SIEMEvent{Action: "eth_call", Outcome: "success"})
	fwd.Send(SIEMEvent{Action: "eth_sendTransaction", Outcome: "success"})

	fwd.Start()
	time.Sleep(120 * time.Millisecond)
	fwd.Stop()

	if received.Load() != 2 {
		t.Fatalf("expected 2 events received by SIEM, got %d", received.Load())
	}

	// After stop, internal batch should be empty.
	remaining := fwd.queued()
	if remaining != 0 {
		t.Fatalf("expected empty batch after stop, got %d", remaining)
	}
}

func TestSIEM_FailedSendWithFallback(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	fallbackPath := filepath.Join(t.TempDir(), "fallback.jsonl")

	fwd := mustNewForwarder(t, SIEMConfig{
		WebhookURL:      srv.URL,
		BatchSize:       100,
		FlushInterval:   50 * time.Millisecond,
		FallbackLogPath: fallbackPath,
	})

	fwd.Send(SIEMEvent{Action: "eth_call", Outcome: "success"})
	fwd.Send(SIEMEvent{Action: "eth_getBalance", Outcome: "success"})

	fwd.Start()
	// Wait for flush + retries (3 retries with backoff: 0s + 1s + 2s = ~3s).
	time.Sleep(5 * time.Second)
	fwd.Stop()

	// Check fallback file was written.
	data, err := os.ReadFile(fallbackPath)
	if err != nil {
		t.Fatalf("failed to read fallback file: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("expected fallback file to contain events")
	}

	// Parse each JSON line.
	lines := 0
	dec := json.NewDecoder(bytes.NewReader(data))
	for dec.More() {
		var event SIEMEvent
		if err := dec.Decode(&event); err != nil {
			t.Fatalf("failed to decode fallback event: %v", err)
		}
		lines++
	}
	if lines != 2 {
		t.Fatalf("expected 2 events in fallback file, got %d", lines)
	}
}

func TestSIEM_FailedSendWithoutFallback(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	fwd := mustNewForwarder(t, SIEMConfig{
		WebhookURL:    srv.URL,
		BatchSize:     100,
		FlushInterval: 50 * time.Millisecond,
		// No FallbackLogPath - events will be dropped with ERROR log.
	})

	fwd.Send(SIEMEvent{Action: "eth_call", Outcome: "success"})

	fwd.Start()
	time.Sleep(5 * time.Second)
	fwd.Stop()

	// No crash, events dropped. The ERROR log is printed but we cannot easily
	// capture log output in this test without a custom logger.
	remaining := fwd.queued()
	if remaining != 0 {
		t.Fatalf("expected empty batch after stop, got %d", remaining)
	}
}

func TestSIEM_StopFlushesPending(t *testing.T) {
	var received atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var events []SIEMEvent
		if err := json.NewDecoder(r.Body).Decode(&events); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		received.Add(int64(len(events)))
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	fwd := mustNewForwarder(t, SIEMConfig{
		WebhookURL:    srv.URL,
		BatchSize:     100,
		FlushInterval: 1 * time.Hour, // will not tick during test
	})

	fwd.Send(SIEMEvent{Action: "eth_call", Outcome: "success"})
	fwd.Start()

	// Stop should flush the pending event.
	fwd.Stop()

	if received.Load() != 1 {
		t.Fatalf("expected 1 event flushed on Stop(), got %d", received.Load())
	}
}

func TestSIEM_BatchSizeTrigger(t *testing.T) {
	var flushes atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		flushes.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	fwd := mustNewForwarder(t, SIEMConfig{
		WebhookURL:    srv.URL,
		BatchSize:     3,
		FlushInterval: 1 * time.Hour, // will not tick during test
	})

	fwd.Start()

	// Adding 3 events should trigger an immediate flush (batch full).
	fwd.Send(SIEMEvent{Action: "a", Outcome: "success"})
	fwd.Send(SIEMEvent{Action: "b", Outcome: "success"})
	fwd.Send(SIEMEvent{Action: "c", Outcome: "success"})

	// Give the flush a moment to complete.
	time.Sleep(100 * time.Millisecond)

	if flushes.Load() < 1 {
		t.Fatal("expected at least 1 flush when batch size reached")
	}

	fwd.Stop()
}

// TestNewSIEMForwarder_RejectsBadURL verifies the defence-in-depth wiring
// added for RD-950: NewSIEMForwarder now refuses to construct a forwarder
// whose WebhookURL would fail the SSRF guard, so a misconfiguration fails
// fast at startup rather than at the first flush.
func TestNewSIEMForwarder_RejectsBadURL(t *testing.T) {
	tests := []struct {
		name          string
		url           string
		allowInsecure bool
	}{
		{"prod rejects http", "http://siem.example.com/ingest", false},
		{"prod rejects loopback", "https://127.0.0.1/ingest", false},
		{"prod rejects AWS metadata", "https://169.254.169.254/", false},
		{"prod rejects private", "https://10.1.2.3/ingest", false},
		{"non-prod rejects http public", "http://siem.example.com/ingest", true},
		{"non-prod rejects AWS metadata", "http://169.254.169.254/", true},
		{"both reject malformed", "://bad", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fwd, err := NewSIEMForwarder(SIEMConfig{
				WebhookURL:    tt.url,
				BatchSize:     10,
				FlushInterval: time.Second,
				AllowInsecure: tt.allowInsecure,
			})
			if err == nil {
				t.Fatalf("NewSIEMForwarder(%q, allowInsecure=%v) returned nil error, want failure",
					tt.url, tt.allowInsecure)
			}
			if fwd != nil {
				t.Errorf("NewSIEMForwarder(%q): expected nil forwarder on error, got %#v", tt.url, fwd)
			}
		})
	}
}

// TestNewSIEMForwarder_AcceptsGoodURL is the positive case — a real-shaped
// production URL (public HTTPS) must construct cleanly.
func TestNewSIEMForwarder_AcceptsGoodURL(t *testing.T) {
	fwd, err := NewSIEMForwarder(SIEMConfig{
		WebhookURL:    "https://siem.example.com/ingest",
		BatchSize:     10,
		FlushInterval: time.Second,
	})
	if err != nil {
		t.Fatalf("NewSIEMForwarder: %v", err)
	}
	if fwd == nil {
		t.Fatal("NewSIEMForwarder returned nil forwarder with nil error")
	}
}

// The sealer sends SIEM events on its own goroutine: a full batch is flushed
// by the forwarder's goroutine, never inline, so a slow SIEM endpoint cannot
// stall audit sealing (RD-1410). Events past the bounded queue go
// the failed-batch way (fallback log, dropped counter), never block.
func TestSIEM_SendNeverWaitsForTheWebhook(t *testing.T) {
	release := make(chan struct{})
	var received atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release
		var events []SIEMEvent
		_ = json.NewDecoder(r.Body).Decode(&events)
		received.Add(int64(len(events)))
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	fwd := mustNewForwarder(t, SIEMConfig{WebhookURL: srv.URL, BatchSize: 10, FlushInterval: time.Hour})
	fwd.Start()
	began := time.Now()
	for i := 0; i < 300; i++ {
		fwd.Send(SIEMEvent{Action: "a", Outcome: "success"})
	}
	if took := time.Since(began); took > 500*time.Millisecond {
		t.Fatalf("300 sends took %s against a stalled webhook", took)
	}
	close(release)
	fwd.Stop()
	if got := received.Load(); got != 300 {
		t.Fatalf("webhook received %d events, want all 300 after the stall", got)
	}
}

// Stop keeps its budget even when a flush is already running against a
// failing endpoint (review finding 3): in-flight sends are cancelled when the
// budget is spent, and every event that was not delivered is written to the
// fallback log instead of being dropped.
func TestSIEM_StopBudgetHoldsDuringARunningFlush(t *testing.T) {
	first := make(chan struct{})
	var once sync.Once
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		once.Do(func() { close(first) })
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	fallback := filepath.Join(t.TempDir(), "fallback.jsonl")
	fwd := mustNewForwarder(t, SIEMConfig{WebhookURL: srv.URL, BatchSize: 2, FlushInterval: time.Hour, FallbackLogPath: fallback})
	fwd.stopBudget = 300 * time.Millisecond
	fwd.Start()
	for i := 0; i < 12; i++ {
		fwd.Send(SIEMEvent{Action: fmt.Sprintf("a%d", i), Outcome: "success"})
	}
	<-first // a flush is running: its first attempt failed and it is retrying
	began := time.Now()
	fwd.Stop()
	if took := time.Since(began); took > 2*time.Second {
		t.Fatalf("Stop took %s with a %s budget", took, fwd.stopBudget)
	}
	data, err := os.ReadFile(fallback)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]int{}
	dec := json.NewDecoder(bytes.NewReader(data))
	for dec.More() {
		var ev SIEMEvent
		if err := dec.Decode(&ev); err != nil {
			t.Fatal(err)
		}
		seen[ev.Action]++
	}
	if len(seen) != 12 {
		t.Fatalf("fallback log holds %d distinct events, want all 12: %v", len(seen), seen)
	}
	for action, n := range seen {
		if n != 1 {
			t.Fatalf("event %s written %d times to the fallback log", action, n)
		}
	}
}

// Delivery runs on several senders at once (review finding 4): with four
// senders, four batches are in flight together, never more.
func TestSIEM_SendersDeliverConcurrently(t *testing.T) {
	var inflight, peak, received atomic.Int64
	all := make(chan struct{})
	var once sync.Once
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := inflight.Add(1)
		for {
			p := peak.Load()
			if n <= p || peak.CompareAndSwap(p, n) {
				break
			}
		}
		if n >= 4 {
			once.Do(func() { close(all) })
		}
		select {
		case <-all:
		case <-time.After(2 * time.Second):
		}
		var events []SIEMEvent
		_ = json.NewDecoder(r.Body).Decode(&events)
		received.Add(int64(len(events)))
		inflight.Add(-1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	fwd := mustNewForwarder(t, SIEMConfig{WebhookURL: srv.URL, BatchSize: 10, Senders: 4, FlushInterval: time.Hour})
	fwd.Start()
	for i := 0; i < 80; i++ {
		fwd.Send(SIEMEvent{Action: "a", Outcome: "success"})
	}
	deadline := time.Now().Add(20 * time.Second)
	for received.Load() < 80 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	fwd.Stop()
	if got := received.Load(); got != 80 {
		t.Fatalf("received %d of 80 events", got)
	}
	if got := peak.Load(); got != 4 {
		t.Fatalf("peak of %d batches in flight, want 4 (one per sender)", got)
	}
}

// An event sent after Stop is not left in a queue nobody delivers: it takes
// the failed-delivery path at once. Stop without Start does not hang.
func TestSIEM_SendAfterStopGoesToTheFallbackLog(t *testing.T) {
	fallback := filepath.Join(t.TempDir(), "fallback.jsonl")
	fwd := mustNewForwarder(t, SIEMConfig{WebhookURL: "http://127.0.0.1:1/ingest", BatchSize: 10, FlushInterval: time.Hour, FallbackLogPath: fallback})
	fwd.Stop()
	fwd.Send(SIEMEvent{Action: "late", Outcome: "success"})
	if n := fwd.queued(); n != 0 {
		t.Fatalf("%d events queued after Stop", n)
	}
	data, err := os.ReadFile(fallback)
	if err != nil || !bytes.Contains(data, []byte(`"action":"late"`)) {
		t.Fatalf("fallback log %q %v, want the late event", data, err)
	}
}

// Senders reuse their connections (review of finding 4): opening one per batch
// would add a TCP and TLS handshake to every request and cut the capacity.
func TestSIEM_SendersReuseConnections(t *testing.T) {
	var opened, received atomic.Int64
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var events []SIEMEvent
		_ = json.NewDecoder(r.Body).Decode(&events)
		received.Add(int64(len(events)))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"accepted":true}`))
	}))
	srv.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			opened.Add(1)
		}
	}
	srv.Start()
	defer srv.Close()
	fwd := mustNewForwarder(t, SIEMConfig{WebhookURL: srv.URL, BatchSize: 10, Senders: 4, FlushInterval: time.Hour})
	fwd.Start()
	for i := 0; i < 800; i++ {
		fwd.Send(SIEMEvent{Action: "a", Outcome: "success"})
	}
	deadline := time.Now().Add(20 * time.Second)
	for received.Load() < 800 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	fwd.Stop()
	if got := received.Load(); got != 800 {
		t.Fatalf("received %d of 800 events", got)
	}
	if got := opened.Load(); got > 8 {
		t.Fatalf("%d connections opened for 80 batches on 4 senders", got)
	}
}

// A request the endpoint refuses as such (4xx other than 408 and 429) is not
// retried: it would fail the same way three times.
func TestSIEM_ClientErrorsAreNotRetried(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusRequestEntityTooLarge)
	}))
	defer srv.Close()
	fwd := mustNewForwarder(t, SIEMConfig{WebhookURL: srv.URL, BatchSize: 1, FlushInterval: time.Hour})
	if err := fwd.send(context.Background(), []SIEMEvent{{Action: "a"}}); err == nil {
		t.Fatal("a 413 must fail the batch")
	}
	if got := hits.Load(); got != 1 {
		t.Fatalf("%d attempts for a 413, want 1", got)
	}
}

// Start after Stop starts nothing, and both are safe to call twice.
func TestSIEM_StartAfterStopStartsNothing(t *testing.T) {
	fwd := mustNewForwarder(t, SIEMConfig{WebhookURL: "http://127.0.0.1:1/ingest", BatchSize: 1, FlushInterval: time.Hour})
	fwd.Stop()
	fwd.Start()
	fwd.Stop()
	if fwd.started {
		t.Fatal("Start after Stop started the senders")
	}
}
