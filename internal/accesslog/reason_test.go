package accesslog

import (
	"encoding/json"
	"net/url"
	a "privacy-proxy/internal/activitylog"
	"strings"
	"testing"

	r "privacy-proxy/internal/activityreasondata"
	f "privacy-proxy/internal/disclosuretest"
)

func TestAdminReasonProjectionPreservesLegacyAndValidatesRecordedPairs(t *testing.T) {
	for _, tc := range []struct {
		name    string
		version uint8
		reason  r.Code
		outcome string
		status  uint16
		want    string
	}{
		{"legacy", 1, "", "success", 200, "not_recorded"},
		{"v2 unclassified", 2, r.NotRecorded, "success", 200, "not_recorded"},
		{"wallet", 2, r.SenderNotLinked, "denied", 403, "sender_not_linked"},
		{"method", 2, r.MethodNotAllowed, "denied", 403, "method_not_allowed"},
		{"policy", 2, r.PolicyArgumentConstraint, "denied", 403, "policy_argument_constraint"},
		{"old reason forbidden", 1, r.SenderNotLinked, "denied", 403, ""},
		{"unknown", 2, "private untrusted text", "denied", 403, ""},
		{"wrong outcome", 2, r.SenderNotLinked, "success", 200, ""},
		{"future version", 3, r.NotRecorded, "success", 200, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			x := newAuditFixture(t)
			row := &x.reader.snapshot.rows[0]
			row.Version, row.Reason, row.Outcome, row.Status = tc.version, tc.reason, tc.outcome, tc.status
			if tc.outcome == "denied" {
				code := int32(-32001)
				row.RPCError = &code
			}
			status, _, body := x.request(t, f.Org, x.token, nil)
			if tc.want == "" {
				if status != 503 || strings.Contains(string(body), row.RecordID) || strings.Contains(string(body), "private untrusted text") {
					t.Fatal("unvalidated reason exposed", status, string(body))
				}
				return
			}
			var page Page
			if status != 200 || json.Unmarshal(body, &page) != nil || len(page.Items) != 1 || page.Items[0].Reason != tc.want {
				t.Fatal("recorded reason missing or fabricated", status, string(body))
			}
		})
	}
}

func TestPreviousReasonFormatCursorRestartsInsteadOfMixingProfiles(t *testing.T) {
	x := newAuditFixture(t)
	x.reader.snapshot.end = false
	row := &x.reader.snapshot.rows[0]
	row.ProducerID = "55555555-5555-4555-8555-555555555555"
	row.RunID = "66666666-6666-4666-8666-666666666666"
	row.Ordinal = "1"
	// Generate a legitimately sealed continuation carrying the old stream
	// metadata, then retain its exact head/context under the dual-reader profile.
	x.service.expected.Format = a.LegacyFormat()
	x.reader.snapshot.cut.Metadata.Format = a.LegacyFormat()
	status, _, body := x.request(t, f.Org, x.token, url.Values{"limit": {"1"}})
	var first Page
	if status != 200 || json.Unmarshal(body, &first) != nil || first.Next == nil {
		t.Fatal("legacy continuation", status, string(body))
	}
	x.service.expected.Format = a.Format()
	x.reader.snapshot.cut.Metadata.Format = a.Format()
	status, _, body = x.request(t, f.Org, x.token, url.Values{"limit": {"1"}, "cursor": {*first.Next}})
	if status != 409 || strings.Contains(string(body), row.RecordID) {
		t.Fatal("old format cursor crossed stream profile", status, string(body))
	}
}
