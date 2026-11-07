// Package pricefeedpolicy normalizes approved price-feed definitions and derives
// one immutable request plan from the approved compliance catalog. It performs
// no HTTP, SQL, environment lookup or valuation.
package pricefeedpolicy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"privacy-proxy/internal/compliancepolicy"
)

const (
	MaxIDs             = 512
	MaxCurrencies      = 5
	MaxIDsPerRequest   = 100
	MaxRequests        = 32
	MaxSourceURIBytes  = 2048
	MaxRequestURIBytes = 8192
)

var ErrInvalid = errors.New("invalid approved price feed")

type SecretRef struct {
	FromEnv string `json:"fromEnv"`
}
type Source struct {
	URI                    string     `json:"uri"`
	RefreshIntervalSeconds int64      `json:"refreshIntervalSeconds"`
	Format                 string     `json:"format"`
	Credential             *SecretRef `json:"credential,omitempty" optional:"true"`
}
type Definition struct {
	source Source
	digest string
	valid  bool
}

func (d Definition) Valid() bool    { return d.valid }
func (d Definition) Digest() string { return d.digest }
func (d Definition) Source() Source {
	out := d.source
	if out.Credential != nil {
		copy := *out.Credential
		out.Credential = &copy
	}
	return out
}
func digest(v any) string {
	raw, _ := json.Marshal(v)
	hash := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(hash[:])
}

var secretName = regexp.MustCompile(`^OPS_PRICE_FEED_[A-Z0-9_]{1,64}$`)
var ownedKeys = map[string]bool{"ids": true, "vs_currencies": true, "include_last_updated_at": true, "include_market_cap": true, "include_24hr_vol": true, "include_24hr_change": true}
var rejectedKeys = map[string]bool{"names": true, "symbols": true, "include_tokens": true, "api_key": true, "apikey": true, "key": true, "token": true, "access_token": true, "secret": true, "client_secret": true, "authorization": true, "auth": true, "x_cg_demo_api_key": true, "x_cg_pro_api_key": true}

func safeText(s string, max int) bool {
	if s == "" || len(s) > max || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}
func Normalize(source Source) (Definition, error) {
	if source.Format != "coingecko-simple" || source.RefreshIntervalSeconds < 60 || source.RefreshIntervalSeconds > 86400 || !safeText(source.URI, MaxSourceURIBytes) || strings.TrimSpace(source.URI) != source.URI {
		return Definition{}, ErrInvalid
	}
	u, err := url.Parse(source.URI)
	if err != nil || u.Host == "" || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || strings.Contains(source.URI, "#") || u.Opaque != "" {
		return Definition{}, ErrInvalid
	}
	if port := u.Port(); port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return Definition{}, ErrInvalid
		}
	}
	values, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return Definition{}, ErrInvalid
	}
	seen := map[string]bool{}
	for key, list := range values {
		lower := strings.ToLower(key)
		if !safeText(key, MaxSourceURIBytes) || len(list) != 1 || seen[lower] || rejectedKeys[strings.ReplaceAll(lower, "-", "_")] || ownedKeys[lower] && key != lower || lower == "precision" && key != lower {
			return Definition{}, ErrInvalid
		}
		seen[lower] = true
		if !utf8.ValidString(list[0]) {
			return Definition{}, ErrInvalid
		}
		for _, r := range list[0] {
			if r < 0x20 || r == 0x7f {
				return Definition{}, ErrInvalid
			}
		}
		if key == "precision" && list[0] != "full" {
			n, err := strconv.Atoi(list[0])
			if err != nil || n < 0 || n > 18 || strconv.Itoa(n) != list[0] {
				return Definition{}, ErrInvalid
			}
		}
	}
	if source.Credential != nil {
		if !secretName.MatchString(source.Credential.FromEnv) {
			return Definition{}, ErrInvalid
		}
		copy := *source.Credential
		source.Credential = &copy
	}
	u.RawQuery = values.Encode()
	u.ForceQuery = false
	source.URI = u.String()
	if len(source.URI) > MaxSourceURIBytes {
		return Definition{}, ErrInvalid
	}
	return Definition{source: source, digest: digest(source), valid: true}, nil
}

// Plan owns all IDs, currencies and URLs. Returned slices are detached copies.
type Plan struct {
	sourceDigest, catalogDigest, digest string
	ids, currencies                     []string
	requests                            []Request
	valid                               bool
}
type Request struct {
	URI string
	IDs []string
}

func (p Plan) Valid() bool           { return p.valid }
func (p Plan) Digest() string        { return p.digest }
func (p Plan) SourceDigest() string  { return p.sourceDigest }
func (p Plan) CatalogDigest() string { return p.catalogDigest }
func (p Plan) IDs() []string         { return append([]string{}, p.ids...) }
func (p Plan) Currencies() []string  { return append([]string{}, p.currencies...) }
func (p Plan) Requests() []Request {
	out := make([]Request, len(p.requests))
	for i, r := range p.requests {
		out[i] = Request{r.URI, append([]string{}, r.IDs...)}
	}
	return out
}
func BuildPlan(def Definition, catalog *compliancepolicy.Catalog) (Plan, error) {
	if !def.valid || catalog == nil {
		return Plan{}, ErrInvalid
	}
	ids, currencies := map[string]bool{}, map[string]bool{}
	for _, org := range catalog.DetachedSource().Organizations {
		currencies[org.Spec.Settings.Currency] = true
		native := false
		for _, row := range org.Spec.TokenPrices {
			native = native || row.TokenAddress == "native"
			if row.CoingeckoID != "" {
				if !safeText(row.CoingeckoID, 100) || strings.TrimSpace(row.CoingeckoID) != row.CoingeckoID || strings.Contains(row.CoingeckoID, ",") {
					return Plan{}, ErrInvalid
				}
				ids[row.CoingeckoID] = true
			}
		}
		if !native {
			ids["ethereum"] = true
		}
	}
	if len(ids) > MaxIDs || len(currencies) > MaxCurrencies {
		return Plan{}, ErrInvalid
	}
	p := Plan{sourceDigest: def.digest, catalogDigest: catalog.Digest(), ids: []string{}, currencies: []string{}, requests: []Request{}, valid: true}
	for id := range ids {
		p.ids = append(p.ids, id)
	}
	for currency := range currencies {
		p.currencies = append(p.currencies, currency)
	}
	sort.Strings(p.ids)
	sort.Strings(p.currencies)
	u, _ := url.Parse(def.source.URI)
	query := u.Query()
	query.Set("vs_currencies", strings.Join(p.currencies, ","))
	query.Set("include_last_updated_at", "true")
	for _, key := range []string{"include_market_cap", "include_24hr_vol", "include_24hr_change"} {
		query.Set(key, "false")
	}
	request := func(batch []string) Request {
		query.Set("ids", strings.Join(batch, ","))
		copy := *u
		copy.RawQuery = query.Encode()
		return Request{copy.String(), append([]string{}, batch...)}
	}
	batch := []string{}
	for _, id := range p.ids {
		candidate := append(append([]string{}, batch...), id)
		if len(candidate) > MaxIDsPerRequest || len(request(candidate).URI) > MaxRequestURIBytes {
			if len(batch) == 0 {
				return Plan{}, ErrInvalid
			}
			p.requests = append(p.requests, request(batch))
			batch = []string{id}
			if len(request(batch).URI) > MaxRequestURIBytes {
				return Plan{}, ErrInvalid
			}
		} else {
			batch = candidate
		}
	}
	if len(batch) > 0 {
		p.requests = append(p.requests, request(batch))
	}
	if len(p.requests) > MaxRequests {
		return Plan{}, ErrInvalid
	}
	p.digest = digest(struct {
		Source, Catalog string
		IDs, Currencies []string
	}{p.sourceDigest, p.catalogDigest, p.ids, p.currencies})
	return p, nil
}
