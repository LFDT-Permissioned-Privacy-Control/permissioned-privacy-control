package protectedsource

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	c "privacy-proxy/internal/disclosurecase"
	d "privacy-proxy/internal/disclosuredata"
	"privacy-proxy/internal/disclosurehttp"
	p "privacy-proxy/internal/disclosurepolicy"
	f "privacy-proxy/internal/disclosuretest"
	"privacy-proxy/internal/operational/disclosuresql"
)

type legacyHTTPQuerySources struct{ plan d.SourcePlan }

func (s legacyHTTPQuerySources) Plan() d.SourcePlan { return s.plan }
func (s legacyHTTPQuerySources) Open(context.Context, d.ReadScope, []d.SourceRef) (d.Snapshot, error) {
	return nil, d.ErrUnavailable
}

func TestRetainedAddressTransactionsThroughActualHTTP(t *testing.T) {
	config := actualFunctionalConfig(t, ownedFunctionalNode(t))
	sources, err := New(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}
	db := ownedFunctionalDB(t)
	ownerDSN, owner := db.database(t, "cases")
	for _, role := range []string{"query_app", "query_retention"} {
		functionalRole(t, owner, role)
	}
	if err = disclosuresql.Migrate(t.Context(), ownerDSN, "query_app", "query_retention"); err != nil {
		t.Fatal(err)
	}
	store, err := disclosuresql.Open(t.Context(), functionalDSN(ownerDSN, "query_app"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(store.Close)
	cfg := c.Config{Snapshot: config.Snapshot, Clock: config.Clock, Store: store, StoreEpoch: "retained-http-query", CursorKeys: c.CursorKeys{Active: c.CursorKey{ID: "admin", Key: bytes.Repeat([]byte{31}, 32)}}}
	data := c.RetainedDataConfig{Network: config.Network, Sources: sources, RenderKeys: config.RenderKeys, CursorKeys: d.Keys{Active: d.Key{ID: "data", Bytes: bytes.Repeat([]byte{32}, 32)}}}
	service, err := c.NewWithRetainedData(cfg, data)
	if err != nil {
		t.Fatal(err)
	}
	server := func(service *c.Service) *httptest.Server {
		t.Helper()
		h, e := disclosurehttp.NewWithData(service)
		if e != nil {
			t.Fatal(e)
		}
		mux := http.NewServeMux()
		h.Register(mux)
		s := httptest.NewTLSServer(mux)
		t.Cleanup(s.Close)
		return s
	}
	serving := server(service)
	token := f.Token(t, config.Snapshot, f.Subject, "Auditor")
	request := func(s *httptest.Server, bearer, path string, body any, status int) []byte {
		t.Helper()
		raw, e := json.Marshal(body)
		if e != nil {
			t.Fatal(e)
		}
		r, e := http.NewRequestWithContext(t.Context(), http.MethodPost, s.URL+path, bytes.NewReader(raw))
		if e != nil {
			t.Fatal(e)
		}
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Authorization", "Bearer "+bearer)
		response, e := s.Client().Do(r)
		if e != nil {
			t.Fatal(e)
		}
		defer response.Body.Close()
		value, e := io.ReadAll(io.LimitReader(response.Body, c.MaxResponseBytes+1))
		if e != nil || response.StatusCode != status {
			t.Fatalf("actual HTTP status=%d want=%d error=%v", response.StatusCode, status, e)
		}
		return value
	}
	create := func() string {
		scope := f.Scope()
		scope.Resources, scope.Level = []p.Resource{p.AddressHistory, p.Transactions}, p.Full
		scope.DataTime = p.Interval{Start: f.Now - 10, End: f.Now + 10}
		raw := request(serving, token, "/api/v1/disclosure/cases", c.CreateRequest{RuleID: "auditor", RecipientActorID: f.Actor(f.Subject), CaseReference: "HTTP-ADDRESS", Purpose: "Protocol regression", Scope: scope, ExpiresAt: f.Now + 120, IdempotencyKey: uuid.NewString()}, http.StatusCreated)
		var opened c.CaseResponse
		if e := json.Unmarshal(raw, &opened); e != nil || opened.CaseID == "" {
			t.Fatal("missing created case", e)
		}
		return opened.CaseID
	}
	id := create()
	path := "/api/v1/disclosure/cases/" + id + "/read"
	raw := request(serving, token, path, map[string]any{"v": 1, "resource": "addresses", "view": "list", "limit": 50}, http.StatusOK)
	var addresses struct {
		Result struct {
			Items []struct {
				AddressID string `json:"addressId"`
			} `json:"items"`
		} `json:"result"`
	}
	if err = json.Unmarshal(raw, &addresses); err != nil || len(addresses.Result.Items) != 1 {
		t.Fatal("real rendered address locator missing", err)
	}
	query := map[string]any{"v": 1, "resource": "transactions", "view": "list", "addressId": addresses.Result.Items[0].AddressID, "limit": 50}
	raw = request(serving, token, path, query, http.StatusOK)
	var transactions struct {
		Result struct {
			Items []json.RawMessage `json:"items"`
		} `json:"result"`
	}
	if err = json.Unmarshal(raw, &transactions); err != nil || len(transactions.Result.Items) != 1 {
		t.Fatal("address-selected real transaction missing", err)
	}
	request(serving, f.Token(t, config.Snapshot, f.AdminSubject, "Admin"), path, query, http.StatusNotFound)
	request(serving, token, "/api/v1/disclosure/cases/"+create()+"/read", query, http.StatusNotFound)
	legacyPlan := sources.Plan()
	legacyPlan.Version, legacyPlan.Profile = 1, "ops.disclosure.data-sources/v1"
	legacy, err := c.NewWithData(cfg, c.DataConfig{Network: config.Network, Sources: legacyHTTPQuerySources{legacyPlan}, RenderKeys: data.RenderKeys, CursorKeys: data.CursorKeys})
	if err != nil {
		t.Fatal(err)
	}
	request(server(legacy), token, path, query, http.StatusBadRequest)
	for _, field := range []string{"activity_logs", "events"} {
		bad := map[string]any{"v": 1, "resource": field, "view": "list", "addressId": query["addressId"]}
		request(serving, token, path, bad, http.StatusBadRequest)
	}
	query["addressId"] = strings.Repeat("a", 129)
	request(serving, token, path, query, http.StatusBadRequest)
}
