package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"sync"
	"time"

	"privacy-proxy/internal/netguard"

	"github.com/prometheus/client_golang/prometheus"
)

// SIEMConfig configures the SIEM webhook forwarder.
type SIEMConfig struct {
	WebhookURL      string
	AuthHeader      string
	BatchSize       int
	FlushInterval   time.Duration
	FallbackLogPath string // If set, failed batches are appended here as JSON lines.
	// Senders is the number of batches delivered at once (default
	// DefaultSIEMSenders). Delivery capacity is about Senders × BatchSize /
	// the endpoint's round-trip time.
	Senders int
	// AllowInsecure relaxes the SSRF guard so HTTP (not just HTTPS) and
	// loopback/private destinations are accepted. Intended for tests and
	// local development only — production callers MUST leave this false so
	// netguard.ValidateWebhookURL (strict mode) is applied.
	AllowInsecure bool
}

// DefaultSIEMSenders is the default number of concurrent SIEM deliveries.
const DefaultSIEMSenders = 4

// SIEMEvent represents an audit event to forward to a SIEM system.
type SIEMEvent struct {
	Timestamp     time.Time `json:"timestamp"`
	EventType     string    `json:"event_type"`
	CorrelationID string    `json:"correlation_id,omitempty"`
	ActorID       string    `json:"actor_id,omitempty"`
	Action        string    `json:"action"`
	Outcome       string    `json:"outcome"`
	Details       string    `json:"details,omitempty"`
	SourceIP      string    `json:"source_ip,omitempty"`
	EntryHash     string    `json:"entry_hash,omitempty"`
	// MatchedVia is "passthrough" when the action method is an operator
	// passthrough method — forwarded unfiltered, outside the proxy's model.
	MatchedVia string `json:"matched_via,omitempty"`
}

// SIEMForwarder batches audit events and forwards them to a SIEM webhook.
// Events wait in a bounded in-memory queue of batches; Senders goroutines
// deliver full batches as soon as they are complete, and every flush interval
// also the last, partial one.
type SIEMForwarder struct {
	cfg    SIEMConfig
	client *http.Client

	mu sync.Mutex
	// queue holds the waiting events in batches of at most BatchSize, oldest
	// first; only the last batch may be partial.
	queue [][]SIEMEvent

	kick     chan struct{} // a full batch is waiting (one token per sender)
	tick     chan struct{} // the flush interval passed: send partial batches too
	stopping chan struct{} // closed by Stop
	// sendCtx is cancelled when the stop budget is spent, which aborts the
	// sends in flight and their retry waits.
	sendCtx    context.Context
	cancel     context.CancelFunc
	workers    sync.WaitGroup
	started    bool
	stopped    bool // Stop has finished: later events go to the failed-delivery path
	stopOnce   sync.Once
	stopBudget time.Duration
	fallbackMu sync.Mutex // one fallback-log write at a time

	// Prometheus metrics (optional, set via SetMetrics)
	batchesTotal       *prometheus.CounterVec
	eventsDroppedTotal prometheus.Counter
}

// SetMetrics configures Prometheus metrics for the SIEM forwarder.
func (s *SIEMForwarder) SetMetrics(batches *prometheus.CounterVec, dropped prometheus.Counter) {
	s.batchesTotal = batches
	s.eventsDroppedTotal = dropped
}

// NewSIEMForwarder creates a new SIEM forwarder. Call Start() to begin flushing.
//
// The WebhookURL is validated at construction time via
// netguard.ValidateWebhookURLForEnv (RD-950) — a malformed or SSRF-prone destination
// makes the forwarder fail fast at startup rather than at the first flush.
// Callers in production must leave SIEMConfig.AllowInsecure=false so HTTPS
// is required and loopback/RFC-1918/link-local destinations are rejected.
func NewSIEMForwarder(cfg SIEMConfig) (*SIEMForwarder, error) {
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = 100
	}
	if cfg.FlushInterval <= 0 {
		cfg.FlushInterval = 30 * time.Second
	}
	if cfg.Senders <= 0 {
		cfg.Senders = DefaultSIEMSenders
	}
	if err := netguard.ValidateWebhookURLForEnv(cfg.WebhookURL, cfg.AllowInsecure); err != nil {
		return nil, fmt.Errorf("siem webhook url: %w", err)
	}

	sendCtx, cancel := context.WithCancel(context.Background())
	return &SIEMForwarder{
		cfg: cfg,
		client: &http.Client{
			Timeout: 10 * time.Second,
			// Refuse private/loopback destinations at dial time, after DNS
			// resolution (RD-1266). URL validation above can only inspect the
			// hostname; this catches a name that resolves — or rebinds — to an
			// internal address. Relaxed in non-production, matching the URL
			// guard's own relaxation.
			Transport: siemTransport(cfg),
			// Disallow redirects: a redirect could lead to a private/internal
			// address even when the original URL was validated (open-redirect SSRF).
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return fmt.Errorf("redirects not permitted for SIEM webhook")
			},
		},
		kick:       make(chan struct{}, cfg.Senders),
		tick:       make(chan struct{}, 1),
		stopping:   make(chan struct{}),
		sendCtx:    sendCtx,
		cancel:     cancel,
		stopBudget: stopFlushBudget,
	}, nil
}

// siemTransport is the guarded transport with one idle connection kept per
// sender, so every sender reuses its connection instead of paying a TCP and
// TLS handshake per batch.
func siemTransport(cfg SIEMConfig) *http.Transport {
	t := netguard.GuardedTransport(cfg.AllowInsecure)
	t.MaxIdleConnsPerHost = max(t.MaxIdleConnsPerHost, cfg.Senders)
	return t
}

// maxQueuedBatches bounds the batches waiting for a sender.
const maxQueuedBatches = 100

// Send queues an event for the next batch and never waits for the webhook:
// a full batch wakes a sender, which delivers it. The audit sealer calls
// Send, so a slow SIEM endpoint must not stall sealing (RD-1410). When the
// senders fall more than maxQueuedBatches batches behind, the oldest batch
// takes the failed-batch path (fallback log, dropped counter) instead of
// growing without bound.
func (s *SIEMForwarder) Send(event SIEMEvent) {
	s.mu.Lock()
	if s.stopped {
		s.mu.Unlock()
		s.handleFailedBatch([]SIEMEvent{event}, errSIEMStopped)
		return
	}
	if n := len(s.queue); n == 0 || len(s.queue[n-1]) >= s.cfg.BatchSize {
		s.queue = append(s.queue, make([]SIEMEvent, 0, s.cfg.BatchSize))
	}
	last := len(s.queue) - 1
	s.queue[last] = append(s.queue[last], event)
	full := len(s.queue[last]) >= s.cfg.BatchSize
	var overflow []SIEMEvent
	if len(s.queue) > maxQueuedBatches {
		overflow = s.queue[0]
		s.queue[0] = nil
		s.queue = s.queue[1:]
	}
	s.mu.Unlock()

	if overflow != nil {
		s.handleFailedBatch(overflow, fmt.Errorf("SIEM forwarder queue full (%d batches waiting)", maxQueuedBatches))
	}
	if full {
		select {
		case s.kick <- struct{}{}:
		default:
		}
	}
}

// take removes the oldest batch: only a full one unless partial is set.
func (s *SIEMForwarder) take(partial bool) []SIEMEvent {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.queue) == 0 || (!partial && len(s.queue[0]) < s.cfg.BatchSize) {
		return nil
	}
	events := s.queue[0]
	s.queue[0] = nil
	s.queue = s.queue[1:]
	if len(s.queue) == 0 {
		s.queue = nil // release the backing array once drained
	}
	return events
}

// queued reports how many events are waiting.
func (s *SIEMForwarder) queued() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, b := range s.queue {
		n += len(b)
	}
	return n
}

// Start begins delivery: Senders goroutines and the flush-interval timer.
func (s *SIEMForwarder) Start() {
	s.mu.Lock()
	if s.started || s.stopping == nil || isClosed(s.stopping) {
		s.mu.Unlock()
		return
	}
	s.started = true
	s.workers.Add(s.cfg.Senders + 1)
	s.mu.Unlock()
	go s.ticker()
	for i := 0; i < s.cfg.Senders; i++ {
		go s.sender()
	}
}

// Stop delivers what is queued for at most the stop budget, then cancels
// the sends still in flight. Every event not delivered by then takes the
// failed-delivery path (the fallback log when one is configured), including
// batches a cancelled send was carrying.
func (s *SIEMForwarder) Stop() {
	s.stopOnce.Do(func() {
		s.mu.Lock()
		close(s.stopping) // under mu: Start never adds workers after this
		s.mu.Unlock()
		done := make(chan struct{})
		go func() {
			s.workers.Wait()
			close(done)
		}()
		budget := time.NewTimer(s.stopBudget)
		defer budget.Stop()
		select {
		case <-done:
		case <-budget.C:
			s.cancel()
			<-done
		}
		s.cancel()
		s.mu.Lock()
		s.stopped = true
		s.mu.Unlock()
		if rest := s.takeAll(); len(rest) > 0 {
			s.handleFailedBatch(rest, errSIEMStopped)
		}
	})
}

var errSIEMStopped = errors.New("SIEM forwarder stopped before delivery")

func isClosed(c chan struct{}) bool {
	select {
	case <-c:
		return true
	default:
		return false
	}
}

func (s *SIEMForwarder) takeAll() []SIEMEvent {
	s.mu.Lock()
	defer s.mu.Unlock()
	var rest []SIEMEvent
	for _, b := range s.queue {
		rest = append(rest, b...)
	}
	s.queue = nil
	return rest
}

func (s *SIEMForwarder) ticker() {
	defer s.workers.Done()
	t := time.NewTicker(s.cfg.FlushInterval)
	defer t.Stop()
	for {
		select {
		case <-s.stopping:
			return
		case <-t.C:
			select {
			case s.tick <- struct{}{}:
			default:
			}
		}
	}
}

func (s *SIEMForwarder) sender() {
	defer s.workers.Done()
	for {
		select {
		case <-s.stopping:
			s.deliverQueued(true)
			return
		case <-s.kick:
			s.deliverQueued(false)
		case <-s.tick:
			s.deliverQueued(true)
		}
	}
}

// stopFlushBudget bounds delivery after Stop: what is still queued or in
// flight once it is spent takes the failed-delivery path, so a SIEM outage
// cannot hold shutdown for every queued batch's retries.
const stopFlushBudget = 10 * time.Second

// flush delivers everything queued on the calling goroutine (tests).
func (s *SIEMForwarder) flush() { s.deliverQueued(true) }

// deliverQueued sends batches until none is left to take (with partial, the
// last short one too). Once the send context is cancelled, the rest of the
// queue takes the failed-delivery path without being sent.
func (s *SIEMForwarder) deliverQueued(partial bool) {
	for {
		if s.sendCtx.Err() != nil {
			if rest := s.takeAll(); len(rest) > 0 {
				s.handleFailedBatch(rest, errSIEMStopped)
			}
			return
		}
		events := s.take(partial)
		if events == nil {
			return
		}
		if err := s.send(s.sendCtx, events); err != nil {
			s.handleFailedBatch(events, err)
		} else if s.batchesTotal != nil {
			s.batchesTotal.WithLabelValues("success").Inc()
		}
	}
}

const maxRetries = 3

func (s *SIEMForwarder) send(ctx context.Context, events []SIEMEvent) error {
	body, err := json.Marshal(events)
	if err != nil {
		return fmt.Errorf("marshal events: %w", err)
	}

	// RD-950: defence-in-depth re-validation immediately before the outbound
	// request. NewSIEMForwarder already validates the URL at startup, but
	// re-checking here means any future code that mutates s.cfg.WebhookURL
	// (or any new flush path that constructs SIEMForwarder by hand) still
	// has to clear the SSRF guard before reaching net/http. The check is
	// cheap (no DNS, no network) and runs once per batch, not per event.
	if err := netguard.ValidateWebhookURLForEnv(s.cfg.WebhookURL, s.cfg.AllowInsecure); err != nil {
		return fmt.Errorf("SIEM webhook URL failed SSRF guard: %w", err)
	}

	var lastErr error
	for attempt := 0; attempt < maxRetries; attempt++ {
		if attempt > 0 {
			wait := time.NewTimer(time.Duration(attempt) * time.Second)
			select {
			case <-ctx.Done():
				wait.Stop()
				return fmt.Errorf("after %d attempts: %w (last error: %v)", attempt, ctx.Err(), lastErr)
			case <-wait.C:
			}
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.cfg.WebhookURL, bytes.NewReader(body))
		if err != nil {
			return fmt.Errorf("create request: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")
		if s.cfg.AuthHeader != "" {
			req.Header.Set("Authorization", s.cfg.AuthHeader)
		}

		resp, err := s.client.Do(req)
		if err != nil {
			// The transport's error quotes the request URL, which can carry
			// a collector token; keep only the cause.
			var urlErr *url.Error
			if errors.As(err, &urlErr) {
				err = urlErr.Err
			}
			lastErr = err
			if ctx.Err() != nil {
				return fmt.Errorf("after %d attempts: %w (last error: %v)", attempt+1, ctx.Err(), lastErr)
			}
			continue
		}
		// Read what is left of the body so the connection is reused.
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
		resp.Body.Close()

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return nil
		}
		lastErr = fmt.Errorf("SIEM webhook returned status %d", resp.StatusCode)
		if resp.StatusCode >= 400 && resp.StatusCode < 500 && resp.StatusCode != http.StatusRequestTimeout && resp.StatusCode != http.StatusTooManyRequests {
			// The endpoint refused this request as such: a retry fails the same way.
			return lastErr
		}
	}

	return fmt.Errorf("after %d retries: %w", maxRetries, lastErr)
}

// handleFailedBatch handles events that could not be sent after all retries.
// M4 fix: if FallbackLogPath is configured, write events to a local file so
// operators can recover them manually. The batch is always dropped from memory
// (no infinite retry) regardless of fallback success.
func (s *SIEMForwarder) handleFailedBatch(events []SIEMEvent, sendErr error) {
	if s.batchesTotal != nil {
		s.batchesTotal.WithLabelValues("error").Inc()
	}
	if s.eventsDroppedTotal != nil {
		s.eventsDroppedTotal.Add(float64(len(events)))
	}

	if s.cfg.FallbackLogPath != "" {
		if err := s.writeFallback(events); err != nil {
			slog.Error("SIEM flush failed and fallback write also failed, dropping events", "send_error", sendErr, "fallback_error", err, "count", len(events))
		} else {
			slog.Warn("SIEM flush failed, wrote events to fallback log", "error", sendErr, "count", len(events), "fallback_path", s.cfg.FallbackLogPath)
		}
		return
	}

	// No fallback configured - log at ERROR level with count.
	slog.Error("SIEM flush failed, dropping events (no fallback path configured)", "error", sendErr, "count", len(events))
}

// writeFallback appends events as JSON lines to the fallback log file: the
// whole batch in one write, and one batch at a time (senders, overflow and
// Stop can all reach it at once).
func (s *SIEMForwarder) writeFallback(events []SIEMEvent) error {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	for _, event := range events {
		if err := enc.Encode(event); err != nil {
			return fmt.Errorf("encode event for fallback log: %w", err)
		}
	}
	s.fallbackMu.Lock()
	defer s.fallbackMu.Unlock()
	f, err := os.OpenFile(s.cfg.FallbackLogPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("open fallback log: %w", err)
	}
	if _, err := f.Write(buf.Bytes()); err != nil {
		_ = f.Close()
		return fmt.Errorf("write events to fallback log: %w", err)
	}
	return f.Close()
}
