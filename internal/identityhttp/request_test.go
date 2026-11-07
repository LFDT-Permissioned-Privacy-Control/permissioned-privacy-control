package identityhttp

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	b "privacy-proxy/internal/identitybroker"
)

func TestCanonicalBrowserHostname(t *testing.T) {
	for _, host := range []string{"ops.test", "localhost", "127.0.0.1", "::1", "2001:db8::1", "xn--e1afmkfd.xn--p1ai"} {
		if !canonicalHostname(host) {
			t.Fatalf("canonical supported hostname: %s", host)
		}
	}
	for _, host := range []string{"OPS.test", "127.1", "0177.0.0.1", "0x7f000001", "example.123", "::ffff:127.0.0.1", "fe80::1%lo0", "-ops.test", "ops..test", "\u00e9.test"} {
		if canonicalHostname(host) {
			t.Fatalf("browser-ambiguous/unsupported hostname: %s", host)
		}
	}
}
func TestFractionalCookieExpiryUsesRefreshCutoff(t *testing.T) {
	cutoff := time.Unix(1800000000, 900000000)
	for _, at := range []time.Time{time.Unix(cutoff.Unix(), 0), cutoff.Add(-time.Nanosecond), cutoff} {
		if _, err := cookie(RenewalCookie, "opaque", cutoff, at); err == nil {
			t.Fatal("rounded-down expired refresh cookie published")
		}
	}
	if _, err := cookie(RenewalCookie, "opaque", cutoff, cutoff.Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := cookie(RenewalCookie, strings.Repeat("a", 4096), cutoff, cutoff.Add(-time.Second)); err == nil {
		t.Fatal("oversized header published")
	}
}
func TestErrorNeverPublishesPreparedCookies(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/", nil)
	w := httptest.NewRecorder()
	publish(w, r, map[string]string{"accessToken": "never"}, []string{"prepared=secret"}, func() error { return b.ErrUnauthorized })
	if w.Code != 401 || w.Header().Get("Set-Cookie") != "" || strings.Contains(w.Body.String(), "never") {
		t.Fatal("gate failed after credentials published")
	}
}
