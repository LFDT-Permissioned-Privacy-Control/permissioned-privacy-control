package selfhttp

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	f "privacy-proxy/internal/brokertest"
)

func TestSelectedCoreRequiresVerifiedAdministrationAndHasNoSourceContents(t *testing.T) {
	snapshot := f.Snapshot(t, nil)
	h, err := New(Config{Snapshot: snapshot, Origin: "https://ops.test", Clock: func() time.Time { return time.Unix(testNow, 0) }})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	h.Register(mux)
	server := httptest.NewTLSServer(mux)
	defer server.Close()
	for _, tc := range []struct {
		name, token, target, method string
		want                        int
	}{
		{"admin", signed(t, snapshot, false, "Admin"), SelectionPath, "GET", 200},
		{"member", signed(t, snapshot, false, "Reader"), SelectionPath, "GET", 403},
		{"unmapped", signed(t, snapshot, false), SelectionPath, "GET", 403},
		{"unauthenticated", "", SelectionPath, "GET", 401},
		{"query", signed(t, snapshot, false, "Admin"), SelectionPath + "?org=other", "GET", 400},
		{"post", signed(t, snapshot, false, "Admin"), SelectionPath, "POST", 405},
		{"unchanged self", signed(t, snapshot, false, "Admin"), Path, "GET", 200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, _ := http.NewRequest(tc.method, server.URL+tc.target, nil)
			r.Host = "ops.test"
			if tc.token != "" {
				r.Header.Set("Authorization", "Bearer "+tc.token)
			}
			res, e := server.Client().Do(r)
			if e != nil {
				t.Fatal(e)
			}
			defer res.Body.Close()
			raw, _ := io.ReadAll(res.Body)
			if res.StatusCode != tc.want {
				t.Fatalf("status %d, want %d: %s", res.StatusCode, tc.want, raw)
			}
			if res.Header.Get("Cache-Control") != "no-store" {
				t.Fatal("cacheable selection")
			}
			if tc.name == "admin" {
				var got Selection
				if json.Unmarshal(raw, &got) != nil || got.ManifestDigest != string(snapshot.Metadata().ManifestDigest) || got.SourceRevision != snapshot.Metadata().SourceRevision {
					t.Fatal("selection not from verified snapshot")
				}
				var fields map[string]json.RawMessage
				if json.Unmarshal(raw, &fields) != nil || len(fields) != 6 {
					t.Fatal("unexpected selection fields")
				}
				for _, key := range []string{"organizations", "documents", "credentials", "accessToken", "actorId"} {
					if bytes.Contains(raw, []byte(`"`+key+`"`)) {
						t.Fatal("selection leaked", key)
					}
				}
			} else if bytes.Contains(raw, []byte("manifestDigest")) {
				t.Fatal("selection leaked or changed own-self DTO")
			}
		})
	}
}

func TestSelectionRechecksOriginalExpiryBeforeOutput(t *testing.T) {
	snapshot := f.Snapshot(t, nil)
	var calls atomic.Int64
	h, err := New(Config{Snapshot: snapshot, Origin: "https://ops.test", Clock: func() time.Time {
		if calls.Add(1) >= 3 {
			return time.Unix(testNow+300, 0)
		}
		return time.Unix(testNow, 0)
	}})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(h)
	defer server.Close()
	r, _ := http.NewRequest("GET", server.URL+SelectionPath, strings.NewReader(""))
	r.Host = "ops.test"
	r.Header.Set("Authorization", "Bearer "+signed(t, snapshot, false, "Admin"))
	res, err := server.Client().Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(res.Body)
	if res.StatusCode != 401 || bytes.Contains(raw, []byte("manifestDigest")) {
		t.Fatal("expired evidence received selection", res.StatusCode)
	}
}
