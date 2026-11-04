package server

import (
	"encoding/json"
	"strings"
	"testing"

	"privacy-proxy/internal/server/apispec"
)

// Review finding 7: the generated spec documents the statuses these
// operations answer (the coverage gate checks routes, not status codes).
func TestSpecDocumentsExecutionStatuses(t *testing.T) {
	var doc struct {
		Paths map[string]map[string]struct {
			Responses map[string]json.RawMessage `json:"responses"`
		} `json:"paths"`
	}
	if err := json.Unmarshal(apispec.JSON, &doc); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ path, method, status string }{
		{"/rpc", "post", "409"}, // transaction_conflict, pool_rejected
		{"/rpc", "post", "503"},
		{"/api/v1/admin/orgs/{org_id}/execution/ownership-recovery", "post", "500"},
		{"/ready", "get", "503"},
	} {
		if _, ok := doc.Paths[c.path][c.method].Responses[c.status]; !ok {
			t.Errorf("%s %s does not document %s", c.method, c.path, c.status)
		}
	}
	for status, want := range map[string]string{"503": "delivery failed", "403": "execution node rejected"} {
		if got := string(doc.Paths["/rpc"]["post"].Responses[status]); !strings.Contains(got, want) {
			t.Errorf("/rpc %s does not say %q: %s", status, want, got)
		}
	}
}
