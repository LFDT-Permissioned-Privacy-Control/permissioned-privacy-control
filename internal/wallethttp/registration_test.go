package wallethttp

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"privacy-proxy/internal/walletops"
)

func TestSelectedLinksExcludeOptionalResolverAndUnknownMethods(t *testing.T) {
	h, e := New(&walletops.Service{})
	if e != nil {
		t.Fatal(e)
	}
	mux := http.NewServeMux()
	h.RegisterLinks(mux)
	address := "0x" + strings.Repeat("1", 40)
	for _, item := range []struct {
		method, path string
		want         int
	}{{"GET", "/api/v2/eth/addresses", 401}, {"POST", "/api/v2/eth/link/challenge", 401}, {"POST", "/api/v2/eth/link/verify", 401}, {"DELETE", "/api/v2/eth/addresses/" + address, 401}, {"POST", "/api/v2/eth/addresses/" + address + "/refresh-ens", 404}, {"GET", "/api/v1/eth/addresses", 404}, {"HEAD", "/api/v2/eth/addresses", 405}} {
		r := httptest.NewRequest(item.method, item.path, nil)
		if item.want == 404 {
			r.Header.Set("Authorization", "Bearer deliberately-unused")
		}
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		if w.Code != item.want {
			t.Fatalf("%s route status %d", item.method, w.Code)
		}
	}
}
