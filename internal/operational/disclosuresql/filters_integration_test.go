package disclosuresql_test

import (
	"encoding/json"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	c "privacy-proxy/internal/disclosurecase"
	f "privacy-proxy/internal/disclosuretest"
	"privacy-proxy/internal/operational/disclosuresql"
)

func TestCaseMetadataFiltersHTTPAndPostgres(t *testing.T) {
	_, appDSN, _, owner := database(t)
	store, err := disclosuresql.Open(t.Context(), appDSN)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(store.Close)
	snapshot := f.Snapshot(t, nil)
	var clock atomic.Int64
	clock.Store(f.Now)
	s, _ := server(t, snapshot, store, &clock, "filters")
	admin := f.Token(t, snapshot, f.AdminSubject, "Admin")
	var first c.CaseResponse
	for i := 0; i < 2; i++ {
		requestBody := createRequest()
		requestBody.CaseReference = "FILTERED-" + strings.Repeat("x", i+1)
		status, body := request(t, s, admin, "POST", "/api/v1/disclosure/cases", requestBody)
		if status != 201 || json.Unmarshal(body, &first) != nil {
			t.Fatalf("create %d %s", status, body)
		}
	}
	// More than a complete candidate batch must not hide older matching cases.
	_, err = owner.Exec(t.Context(), `INSERT INTO ops_v2.disclosure_cases(case_id,store_epoch,creator_actor,recipient_actor,rule_id,data_org,original_rule_digest,original_bundle_digest,request_digest,immutable_scope,case_reference,purpose,legal_basis,created_at,expires_at,status,version,idempotency_key) SELECT gen_random_uuid(),store_epoch,creator_actor,$2,rule_id,data_org,original_rule_digest,original_bundle_digest,request_digest,immutable_scope,'NOISE',purpose,legal_basis,created_at+interval '1 second',expires_at,status,version,gen_random_uuid() FROM ops_v2.disclosure_cases CROSS JOIN generate_series(1,501) WHERE case_id=$1::uuid`, first.CaseID, f.Actor(f.AdminSubject))
	if err != nil {
		t.Fatal(err)
	}
	query := "?role=data-org-admin&organizationId=" + f.Org + "&limit=1&status=active&privacyLevel=redacted&recipientActorId=" + url.QueryEscape(f.Actor(f.Subject)) + "&createdFrom=1799999999&createdTo=1800000001"
	var page struct {
		Items []c.CaseResponse `json:"items"`
		Next  string           `json:"nextCursor"`
	}
	status, body := request(t, s, admin, "GET", "/api/v1/disclosure/cases"+query, nil)
	if status != 200 || json.Unmarshal(body, &page) != nil || len(page.Items) != 1 || page.Next == "" || page.Items[0].RecipientActorID != f.Actor(f.Subject) {
		t.Fatalf("filtered list %d %s", status, body)
	}
	id, cursor := page.Items[0].CaseID, page.Next
	status, body = request(t, s, admin, "GET", "/api/v1/disclosure/cases"+query+"&cursor="+url.QueryEscape(cursor), nil)
	if status != 200 || json.Unmarshal(body, &page) != nil || len(page.Items) != 1 || page.Items[0].CaseID == id || page.Next != "" {
		t.Fatalf("filtered continuation %d %s", status, body)
	}
	if status, _ := request(t, s, admin, "GET", "/api/v1/disclosure/cases"+strings.Replace(query, "status=active", "status=expired", 1)+"&cursor="+url.QueryEscape(cursor), nil); status != 409 {
		t.Fatal("different-filter cursor accepted", status)
	}
	for _, bad := range []string{"?status=open", "?privacyLevel=secret", "?recipientActorId=admin", "?createdFrom=01", "?createdFrom=3&createdTo=2", "?status=active&status=expired", "?ignored=1"} {
		if status, _ := request(t, s, admin, "GET", "/api/v1/disclosure/cases"+bad, nil); status != 400 {
			t.Fatal("invalid filter ignored", bad, status)
		}
	}
	foreign := f.Token(t, snapshot, f.AdminSubject, "Foreign")
	if status, _ := request(t, s, foreign, "GET", "/api/v1/disclosure/cases"+query, nil); status != 404 {
		t.Fatal("filter widened organization scope", status)
	}
	status, body = request(t, s, admin, "GET", "/api/v1/disclosure/cases?role=data-org-admin&organizationId="+f.Org+"&status=expired", nil)
	if status != 200 || json.Unmarshal(body, &page) != nil || len(page.Items) != 0 {
		t.Fatalf("status filter ignored %d %s", status, body)
	}
}
