package pricing

import (
	"context"
	"log/slog"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"privacy-proxy/internal/compliance"
)

// SystemPriceStore defines the database operations needed by the pricing service.
type SystemPriceStore interface {
	ListSystemTokenPrices(ctx context.Context) ([]*compliance.SystemTokenPrice, error)
	UpsertSystemTokenPrice(ctx context.Context, price *compliance.SystemTokenPrice) error
}

// SettingsStore defines the database operations for system settings.
type SettingsStore interface {
	GetSystemSetting(ctx context.Context, key string) (string, error)
}

// Service fetches token prices from CoinGecko on a schedule and updates the system_token_prices table.
type Service struct {
	store               SystemPriceStore
	settingsStore       SettingsStore
	fetcher             *Fetcher
	interval            time.Duration
	cancel              context.CancelFunc
	done                chan struct{}
	refreshCh           chan struct{} // signals immediate re-fetch
	consecutiveFailures int

	// Prometheus metrics (optional, set via SetMetrics)
	fetchesTotal        *prometheus.CounterVec
	fetchDuration       prometheus.Histogram
	consecutiveFailGauge prometheus.Gauge
}

// SetMetrics configures Prometheus metrics for the pricing service.
func (s *Service) SetMetrics(fetches *prometheus.CounterVec, duration prometheus.Histogram, failures prometheus.Gauge) {
	s.fetchesTotal = fetches
	s.fetchDuration = duration
	s.consecutiveFailGauge = failures
}

// NewService creates a new pricing service.
func NewService(store SystemPriceStore, settingsStore SettingsStore, interval time.Duration) *Service {
	return &Service{
		store:         store,
		settingsStore: settingsStore,
		fetcher:       NewFetcher(),
		interval:      interval,
		done:          make(chan struct{}),
		refreshCh:     make(chan struct{}, 1),
	}
}

// Start begins the background price fetching loop.
func (s *Service) Start() {
	ctx, cancel := context.WithCancel(context.Background())
	s.cancel = cancel

	go func() {
		defer close(s.done)

		// Fetch immediately on start
		s.fetchAndUpdate(ctx)

		ticker := time.NewTicker(s.interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				s.fetchAndUpdate(ctx)
			case <-s.refreshCh:
				s.fetchAndUpdate(ctx)
			}
		}
	}()

	slog.Info("pricing service started", "interval", s.interval)
}

// Stop gracefully stops the background fetching.
func (s *Service) Stop() {
	if s.cancel != nil {
		s.cancel()
		<-s.done
	}
	slog.Info("pricing service stopped")
}

// RefreshNow signals an immediate price re-fetch (e.g. after currency change).
// Non-blocking: if a refresh is already pending, this is a no-op.
// All fetches are serialized through the main goroutine, preventing races.
func (s *Service) RefreshNow() {
	select {
	case s.refreshCh <- struct{}{}:
	default:
		// Refresh already pending, skip
	}
}

// allCurrencies is the list of supported currencies to fetch from CoinGecko.
var allCurrencies = func() []string {
	codes := make([]string, 0, len(compliance.ValidCurrencies))
	for code := range compliance.ValidCurrencies {
		codes = append(codes, string(code))
	}
	return codes
}()

func (s *Service) fetchAndUpdate(ctx context.Context) {
	fetchStart := time.Now()

	// Read current system token IDs from DB
	systemPrices, err := s.store.ListSystemTokenPrices(ctx)
	if err != nil {
		slog.Warn("pricing service failed to list system token prices", "error", err)
		return
	}

	if len(systemPrices) == 0 {
		return
	}

	// Collect IDs to fetch — only CoinGecko-sourced tokens
	var ids []string
	priceMap := make(map[string]*compliance.SystemTokenPrice, len(systemPrices))
	for _, sp := range systemPrices {
		if sp.Source != "coingecko" || sp.CoingeckoID == nil {
			continue
		}
		ids = append(ids, *sp.CoingeckoID)
		priceMap[*sp.CoingeckoID] = sp
	}

	if len(ids) == 0 {
		return
	}

	// Read base currency from settings
	activeCurrency := "usd"
	if s.settingsStore != nil {
		if c, err := s.settingsStore.GetSystemSetting(ctx, "base_currency"); err == nil && c != "" {
			activeCurrency = c
		}
	}

	// Fetch all currencies from CoinGecko in a single request
	allPrices, err := s.fetcher.FetchAll(ctx, ids, allCurrencies)
	if s.fetchDuration != nil {
		s.fetchDuration.Observe(time.Since(fetchStart).Seconds())
	}
	if err != nil {
		s.consecutiveFailures++
		if s.fetchesTotal != nil {
			s.fetchesTotal.WithLabelValues("error").Inc()
		}
		if s.consecutiveFailGauge != nil {
			s.consecutiveFailGauge.Set(float64(s.consecutiveFailures))
		}
		if s.consecutiveFailures >= 3 {
			slog.Error("CoinGecko fetch failed multiple times, prices may be stale", "consecutive_failures", s.consecutiveFailures, "error", err)
		} else {
			slog.Warn("CoinGecko fetch failed, keeping existing prices", "error", err)
		}
		return
	}
	s.consecutiveFailures = 0
	if s.consecutiveFailGauge != nil {
		s.consecutiveFailGauge.Set(0)
	}

	// Upsert each result
	updated := 0
	for id, currencyPrices := range allPrices {
		sp, ok := priceMap[id]
		if !ok {
			continue
		}
		// Filter to only valid currencies AND positive prices (defense against
		// compromised/incomplete CoinGecko responses — security audit M17).
		// Zero/negative entries previously silently wrote into
		// prices_by_currency; the next checker fail-closed (safe), but the
		// row carried no usable value until the next fetch with no alert.
		filtered := make(map[string]float64, len(currencyPrices))
		for code, price := range currencyPrices {
			if !compliance.IsValidCurrency(code) {
				continue
			}
			if price <= 0 {
				slog.Warn("pricing: dropping non-positive price from upstream",
					"coingecko_id", id, "currency", code, "price", price)
				continue
			}
			filtered[code] = price
		}
		sp.PricesByCurrency = filtered
		if active, ok := filtered[activeCurrency]; ok {
			sp.PriceFiat = active
		} else {
			sp.PriceFiat = 0
		}
		sp.UpdatedAt = time.Now()
		if err := s.store.UpsertSystemTokenPrice(ctx, sp); err != nil {
			slog.Warn("failed to update system price", "coingecko_id", id, "error", err)
			continue
		}
		updated++
	}

	if s.fetchesTotal != nil {
		s.fetchesTotal.WithLabelValues("success").Inc()
	}

	slog.Info("pricing service: updated token prices from CoinGecko", "updated", updated, "total", len(ids))
}
