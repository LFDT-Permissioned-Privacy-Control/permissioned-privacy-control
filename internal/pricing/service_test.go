package pricing

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"privacy-proxy/internal/compliance"
)

// mockSystemPriceStore implements SystemPriceStore for testing.
type mockSystemPriceStore struct {
	mu        sync.Mutex
	prices    []*compliance.SystemTokenPrice
	upserted  []*compliance.SystemTokenPrice
	listCalls atomic.Int32
}

func (m *mockSystemPriceStore) ListSystemTokenPrices(_ context.Context) ([]*compliance.SystemTokenPrice, error) {
	m.listCalls.Add(1)
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.prices, nil
}

func (m *mockSystemPriceStore) UpsertSystemTokenPrice(_ context.Context, price *compliance.SystemTokenPrice) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.upserted = append(m.upserted, price)
	return nil
}

func (m *mockSystemPriceStore) getUpserted() []*compliance.SystemTokenPrice {
	m.mu.Lock()
	defer m.mu.Unlock()
	result := make([]*compliance.SystemTokenPrice, len(m.upserted))
	copy(result, m.upserted)
	return result
}

// mockSettingsStore implements SettingsStore for testing.
type mockSettingsStore struct {
	settings map[string]string
}

func (m *mockSettingsStore) GetSystemSetting(_ context.Context, key string) (string, error) {
	return m.settings[key], nil
}

// fakeRoundTripper intercepts HTTP requests and returns canned CoinGecko responses.
type fakeRoundTripper struct {
	calls atomic.Int32
	delay time.Duration
}

func (f *fakeRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	f.calls.Add(1)

	if f.delay > 0 {
		time.Sleep(f.delay)
	}

	currencies := strings.Split(req.URL.Query().Get("vs_currencies"), ",")
	if len(currencies) == 0 {
		currencies = []string{"usd"}
	}

	// Return a price for each requested currency
	ethPrices := map[string]float64{}
	for _, c := range currencies {
		ethPrices[c] = 3500.0
	}
	resp := map[string]map[string]float64{
		"ethereum": ethPrices,
	}
	body, _ := json.Marshal(resp)

	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(newBytesReader(body)),
	}, nil
}

func newBytesReader(b []byte) *bytesReader { return &bytesReader{data: b} }

type bytesReader struct {
	data []byte
	pos  int
}

func (r *bytesReader) Read(p []byte) (int, error) {
	if r.pos >= len(r.data) {
		return 0, io.EOF
	}
	n := copy(p, r.data[r.pos:])
	r.pos += n
	return n, nil
}

func newTestService(store SystemPriceStore, settings SettingsStore, interval time.Duration, rt *fakeRoundTripper) *Service {
	svc := NewService(store, settings, interval)
	svc.fetcher.client = &http.Client{Transport: rt}
	return svc
}

func TestRefreshNow_TriggersImmediateFetch(t *testing.T) {
	cgID := "ethereum"
	store := &mockSystemPriceStore{
		prices: []*compliance.SystemTokenPrice{
			{
				ID:          1,
				CoingeckoID: &cgID,
				Symbol:      "ETH",
				Decimals:    18,
				PriceFiat:   0,
				Source:      "coingecko",
			},
		},
	}
	settings := &mockSettingsStore{settings: map[string]string{"base_currency": "usd"}}
	rt := &fakeRoundTripper{}

	// Long interval so ticker won't fire during test.
	svc := newTestService(store, settings, 1*time.Hour, rt)
	svc.Start()
	defer svc.Stop()

	// Start() does an initial fetch — wait for it.
	waitForCalls(t, &rt.calls, 1, 2*time.Second)
	initialCalls := rt.calls.Load()

	// Signal a refresh.
	svc.RefreshNow()

	// Wait for the refresh fetch.
	waitForCalls(t, &rt.calls, initialCalls+1, 2*time.Second)

	// Verify upserts happened (initial + refresh = 2).
	time.Sleep(50 * time.Millisecond)
	upserted := store.getUpserted()
	if len(upserted) < 2 {
		t.Fatalf("expected at least 2 upserts (initial + refresh), got %d", len(upserted))
	}
	if upserted[len(upserted)-1].PriceFiat != 3500.0 {
		t.Errorf("expected price 3500.0, got %f", upserted[len(upserted)-1].PriceFiat)
	}
}

func TestRefreshNow_DoesNotBlockCaller(t *testing.T) {
	cgID := "ethereum"
	store := &mockSystemPriceStore{
		prices: []*compliance.SystemTokenPrice{
			{
				ID:          1,
				CoingeckoID: &cgID,
				Symbol:      "ETH",
				Decimals:    18,
				PriceFiat:   0,
				Source:      "coingecko",
			},
		},
	}
	settings := &mockSettingsStore{settings: map[string]string{"base_currency": "usd"}}
	rt := &fakeRoundTripper{delay: 500 * time.Millisecond}

	svc := newTestService(store, settings, 1*time.Hour, rt)
	svc.Start()
	defer svc.Stop()

	// Wait for initial fetch to complete so the goroutine is idle.
	waitForCalls(t, &rt.calls, 1, 3*time.Second)

	// RefreshNow must return immediately (it just sends on the channel).
	start := time.Now()
	svc.RefreshNow()
	elapsed := time.Since(start)

	if elapsed > 50*time.Millisecond {
		t.Errorf("RefreshNow blocked for %s, expected it to return immediately", elapsed)
	}
}

func TestRefreshNow_CoalescesMultipleCalls(t *testing.T) {
	cgID := "ethereum"
	store := &mockSystemPriceStore{
		prices: []*compliance.SystemTokenPrice{
			{
				ID:          1,
				CoingeckoID: &cgID,
				Symbol:      "ETH",
				Decimals:    18,
				PriceFiat:   0,
				Source:      "coingecko",
			},
		},
	}
	settings := &mockSettingsStore{settings: map[string]string{"base_currency": "usd"}}
	rt := &fakeRoundTripper{delay: 100 * time.Millisecond}

	svc := newTestService(store, settings, 1*time.Hour, rt)
	svc.Start()
	defer svc.Stop()

	// Wait for initial fetch.
	waitForCalls(t, &rt.calls, 1, 3*time.Second)
	afterInitial := rt.calls.Load()

	// Fire multiple RefreshNow calls — channel is buffered(1), so at most 1 pending.
	for i := 0; i < 10; i++ {
		svc.RefreshNow()
	}

	// Wait for the coalesced fetch.
	waitForCalls(t, &rt.calls, afterInitial+1, 2*time.Second)
	time.Sleep(200 * time.Millisecond) // let any additional fetches complete

	// Should have at most 2 extra calls (1 pending + 1 that might sneak in), not 10.
	totalExtra := rt.calls.Load() - afterInitial
	if totalExtra > 2 {
		t.Errorf("expected at most 2 extra fetches after 10 RefreshNow calls, got %d", totalExtra)
	}
}

func waitForCalls(t *testing.T, calls *atomic.Int32, target int32, timeout time.Duration) {
	t.Helper()
	deadline := time.After(timeout)
	for {
		if calls.Load() >= target {
			return
		}
		select {
		case <-deadline:
			t.Fatalf("timed out waiting for %d calls (got %d)", target, calls.Load())
		default:
			time.Sleep(10 * time.Millisecond)
		}
	}
}
