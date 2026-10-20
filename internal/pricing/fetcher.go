package pricing

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	coingeckoBaseURL = "https://api.coingecko.com/api/v3/simple/price"
	fetchTimeout     = 10 * time.Second
)

// Fetcher retrieves token prices from the CoinGecko API.
type Fetcher struct {
	client *http.Client
}

// NewFetcher creates a new CoinGecko price fetcher.
func NewFetcher() *Fetcher {
	return &Fetcher{
		client: &http.Client{
			Timeout: fetchTimeout,
		},
	}
}

// FetchResult holds prices for a single CoinGecko token across all requested currencies.
type FetchResult struct {
	Prices map[string]float64 // currency code -> price
}

// FetchAll retrieves fiat prices for the given CoinGecko IDs in all specified currencies.
// Returns a map of coingecko_id -> currency -> price.
func (f *Fetcher) FetchAll(ctx context.Context, ids []string, currencies []string) (map[string]map[string]float64, error) {
	if len(ids) == 0 || len(currencies) == 0 {
		return nil, nil
	}

	params := url.Values{}
	params.Set("ids", strings.Join(ids, ","))
	params.Set("vs_currencies", strings.Join(currencies, ","))
	fetchURL := coingeckoBaseURL + "?" + params.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fetchURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := f.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("CoinGecko request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("CoinGecko returned status %d: %s", resp.StatusCode, string(body))
	}

	// Response format: {"ethereum":{"usd":2500.42,"eur":2300.10},"tether":{"usd":1.0,"eur":0.92}}
	var result map[string]map[string]float64
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode CoinGecko response: %w", err)
	}

	return result, nil
}
