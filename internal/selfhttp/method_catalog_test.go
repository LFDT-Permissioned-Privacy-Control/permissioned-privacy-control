package selfhttp

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	f "privacy-proxy/internal/brokertest"
	df "privacy-proxy/internal/disclosuretest"
	"privacy-proxy/internal/policybundle"
)

func TestMethodCatalogActualSnapshotAndAdminBoundary(t *testing.T) {
	groups := []policybundle.Group{
		{ID: df.AuditorGroup, Slug: "reader", Name: "Read-only", IsOrgReadonlyAdmin: true, Claims: []string{}, AllowedMethods: []string{"eth_call"}},
		{ID: df.AdminGroup, Slug: "admin", Name: "Admin", IsOrgAdmin: true, Claims: []string{}, AllowedMethods: []string{"eth_getCode"}},
	}
	snapshot := f.SnapshotWithGroups(t, groups, nil)
	h, err := New(Config{Snapshot: snapshot, Origin: "https://ops.test", Clock: func() time.Time { return time.Unix(testNow, 0) }})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	h.Register(mux)
	server := httptest.NewTLSServer(mux)
	defer server.Close()
	for _, tc := range []struct {
		name, path, method, token, host, origin string
		want                                    int
	}{
		{name: "admin", path: MethodCatalogPath, method: "GET", token: signed(t, snapshot, false, "Admin"), want: 200},
		{name: "readonly", path: MethodCatalogPath, method: "GET", token: signed(t, snapshot, false, "Reader"), want: 200},
		{name: "unmapped", path: MethodCatalogPath, method: "GET", token: signed(t, snapshot, false), want: 403},
		{name: "service admin", path: MethodCatalogPath, method: "GET", token: signed(t, snapshot, true, "Service"), want: 403},
		{name: "unauthenticated", path: MethodCatalogPath, method: "GET", want: 401},
		{name: "post", path: MethodCatalogPath, method: "POST", token: signed(t, snapshot, false, "Admin"), want: 405},
		{name: "query", path: MethodCatalogPath + "?org=other", method: "GET", token: signed(t, snapshot, false, "Admin"), want: 400},
		{name: "bare query", path: MethodCatalogPath + "?", method: "GET", token: signed(t, snapshot, false, "Admin"), want: 400},
		{name: "foreign origin", path: MethodCatalogPath, method: "GET", token: signed(t, snapshot, false, "Admin"), origin: "https://evil.test", want: 403},
		{name: "foreign host", path: MethodCatalogPath, method: "GET", token: signed(t, snapshot, false, "Admin"), host: "evil.test", want: 403},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req, _ := http.NewRequest(tc.method, server.URL+tc.path, nil)
			req.Host = "ops.test"
			if tc.host != "" {
				req.Host = tc.host
			}
			if tc.origin != "" {
				req.Header.Set("Origin", tc.origin)
			}
			if tc.token != "" {
				req.Header.Set("Authorization", "Bearer "+tc.token)
			}
			res, err := server.Client().Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer res.Body.Close()
			raw, _ := io.ReadAll(res.Body)
			if res.StatusCode != tc.want {
				t.Fatalf("status %d want %d: %s", res.StatusCode, tc.want, raw)
			}
			if res.Header.Get("Cache-Control") != "no-store" {
				t.Fatal("catalog must not be cached")
			}
			if tc.want == 200 {
				var got struct {
					Version string `json:"version"`
					Methods []struct {
						Name      string `json:"name"`
						Canonical string `json:"canonical"`
					} `json:"methods"`
				}
				if err := json.Unmarshal(raw, &got); err != nil {
					t.Fatal(err)
				}
				if got.Version != snapshot.Metadata().MethodCatalogVersion {
					t.Fatal("wrong catalog version")
				}
				want := snapshot.Methods()
				if len(got.Methods) != len(want) {
					t.Fatalf("got %d methods, want %d", len(got.Methods), len(want))
				}
				for i, m := range want {
					if got.Methods[i].Name != m.Name || got.Methods[i].Canonical != m.Canonical {
						t.Fatalf("method %d changed: %#v != %#v", i, got.Methods[i], m)
					}
				}
				var fields map[string]json.RawMessage
				if json.Unmarshal(raw, &fields) != nil || len(fields) != 2 || fields["methods"] == nil || fields["version"] == nil {
					t.Fatal("unexpected fields")
				}
				if bytes.Contains(raw, []byte("actorId")) {
					t.Fatal("identity leaked")
				}
			}
		})
	}
}

func TestMethodCatalogRechecksOriginalExpiry(t *testing.T) {
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
	req, _ := http.NewRequest("GET", server.URL+MethodCatalogPath, nil)
	req.Host = "ops.test"
	req.Header.Set("Authorization", "Bearer "+signed(t, snapshot, false, "Admin"))
	res, err := server.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(res.Body)
	if res.StatusCode != 401 || bytes.Contains(raw, []byte(`"methods"`)) {
		t.Fatal("expired evidence received catalog", res.StatusCode, calls.Load())
	}
}

func TestMethodCatalogPreservesAliasesFromSelectedSnapshot(t *testing.T) {
	fixture := df.DefaultStateFixture(t)
	ids := f.IdentitySource()
	fixture.IdentityCatalog = &ids
	fixture.Methods.Assignable = append(fixture.Methods.Assignable, "bank_call")
	fixture.Methods.Aliases["bank_call"] = "eth_call"
	snapshot := df.StateSnapshot(t, fixture)
	h, err := New(Config{Snapshot: snapshot, Origin: "https://ops.test", Clock: func() time.Time { return time.Unix(testNow, 0) }})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(h)
	defer server.Close()
	req, _ := http.NewRequest("GET", server.URL+MethodCatalogPath, nil)
	req.Host = "ops.test"
	req.Header.Set("Authorization", "Bearer "+signed(t, snapshot, false, "Admin"))
	res, err := server.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		t.Fatal("status", res.StatusCode)
	}
	var payload struct {
		Methods []struct {
			Name      string `json:"name"`
			Canonical string `json:"canonical"`
		} `json:"methods"`
	}
	if err := json.NewDecoder(res.Body).Decode(&payload); err != nil {
		t.Fatal(err)
	}
	for _, m := range payload.Methods {
		if m.Name == "bank_call" {
			if m.Canonical != "eth_call" {
				t.Fatal("alias points to wrong method")
			}
			return
		}
	}
	t.Fatal("alias was lost")
}

func TestMethodCatalogDeniesNonAdminHuman(t *testing.T) {
	snapshot := f.Snapshot(t, nil)
	h, err := New(Config{Snapshot: snapshot, Origin: "https://ops.test", Clock: func() time.Time { return time.Unix(testNow, 0) }})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(h)
	defer server.Close()
	req, _ := http.NewRequest("GET", server.URL+MethodCatalogPath, nil)
	req.Host = "ops.test"
	req.Header.Set("Authorization", "Bearer "+signed(t, snapshot, false, "Reader"))
	res, err := server.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != 403 {
		t.Fatalf("non-admin got %d", res.StatusCode)
	}
}
