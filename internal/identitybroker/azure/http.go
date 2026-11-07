package azure

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"privacy-proxy/internal/netguard"
)

const ProviderTimeout = 10 * time.Second

type boundedTransport struct {
	base    http.RoundTripper
	allowed map[string]int
}

func (t *boundedTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.URL.Scheme != "https" || r.URL.Host != "login.microsoftonline.com" || r.URL.User != nil || r.URL.Fragment != "" || r.URL.RawQuery != "" || r.URL.ForceQuery {
		return nil, ErrProvider
	}
	limit, ok := t.allowed[r.Method+" "+r.URL.String()]
	if !ok {
		return nil, ErrProvider
	}
	response, err := t.base.RoundTrip(r)
	if err != nil {
		return nil, ErrProvider
	}
	if response.Body == nil {
		return nil, ErrProvider
	}
	if response.ContentLength > int64(limit) {
		_ = response.Body.Close()
		return nil, ErrProvider
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, int64(limit)+1))
	_ = response.Body.Close()
	if err != nil || len(raw) > limit {
		return nil, ErrProvider
	}
	if response.StatusCode == http.StatusOK {
		object, err := jsonObject(raw, 8)
		if err != nil {
			return nil, ErrProvider
		}
		if strings.HasSuffix(r.URL.Path, "/keys") {
			keys, ok := object["keys"].([]any)
			if !ok || len(keys) > 32 {
				return nil, ErrProvider
			}
		}
		if r.Method == http.MethodGet && !strings.HasSuffix(r.URL.Path, "/keys") {
			for key := range object {
				lower := strings.ToLower(key)
				switch lower {
				case "issuer", "authorization_endpoint", "token_endpoint", "jwks_uri", "id_token_signing_alg_values_supported":
					if lower != key {
						return nil, ErrProvider
					}
				}
			}
		}
		if r.Method == http.MethodPost {
			for key := range object {
				lower := strings.ToLower(key)
				switch lower {
				case "access_token", "token_type", "expires_in", "refresh_token", "id_token", "scope":
					if lower != key {
						return nil, ErrProvider
					}
				}
			}
			if value, present := object["id_token"]; present {
				compact, ok := value.(string)
				if !ok || compact == "" {
					return nil, ErrProvider
				}
			}
		}
	}
	copy := new(http.Response)
	*copy = *response
	copy.Header = response.Header.Clone()
	copy.Body = io.NopCloser(bytes.NewReader(raw))
	copy.ContentLength = int64(len(raw))
	return copy, nil
}
func newClient(transport http.RoundTripper, issuers []string) (*http.Client, *http.Transport) {
	var owned *http.Transport
	if transport == nil {
		owned = netguard.GuardedTransport(false)
		owned.MaxConnsPerHost = 8
		owned.MaxIdleConnsPerHost = 8
		owned.MaxIdleConns = 8
		owned.DialTLS = nil
		owned.DialTLSContext = nil
		if owned.TLSClientConfig != nil {
			owned.TLSClientConfig = owned.TLSClientConfig.Clone()
			owned.TLSClientConfig.InsecureSkipVerify = false
		}
		transport = owned
	}
	allowed := map[string]int{}
	for _, issuer := range issuers {
		u, _ := url.Parse(issuer)
		parts := strings.Split(strings.Trim(u.Path, "/"), "/")
		tenant := parts[0]
		root := "https://login.microsoftonline.com/" + tenant
		allowed["GET "+issuer+"/.well-known/openid-configuration"] = 64 << 10
		allowed["GET "+root+"/discovery/v2.0/keys"] = 256 << 10
		allowed["POST "+root+"/oauth2/v2.0/token"] = 256 << 10
	}
	allowed["GET https://login.microsoftonline.com/common/discovery/v2.0/keys"] = 256 << 10
	return &http.Client{Timeout: ProviderTimeout, Transport: &boundedTransport{transport, allowed}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, owned
}
func operation(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, ProviderTimeout)
}
