package historyfacts

import (
	"testing"

	"privacy-proxy/internal/activityreasondata"
	f "privacy-proxy/internal/disclosuretest"
)

func TestBeginObservationRetainsOnlyVerifiedScopeAndNoFailureAuthority(t *testing.T) {
	for _, name := range []string{"invalid bearer", "absent organization", "foreign method", "allowed"} {
		t.Run(name, func(t *testing.T) {
			x := newFixture(t)
			factory, err := New(x.config)
			if err != nil {
				t.Fatal(err)
			}
			token := f.Token(t, x.config.Snapshot, f.Subject, "Auditor", "Foreign")
			org, actor, reason := f.Org, f.Actor(f.Subject), activityreasondata.Code("")
			wantOrg := org
			wantLoads := 0
			switch name {
			case "invalid bearer":
				token, actor, wantOrg = token+"invalid", "", ""
			case "absent organization":
				org, wantOrg = "11111111-1111-1111-1111-111111111119", ""
			case "foreign method":
				org, wantOrg = f.OtherOrg, f.OtherOrg
				reason = activityreasondata.MethodNotAllowed
			case "allowed":
				wantLoads = 1
			}
			current, observed, err := factory.BeginObserved(t.Context(), token, org, "eth_getCode")
			if observed.ActorID != actor || observed.OrganizationID != wantOrg || observed.Reason != reason || x.wallets.loads != wantLoads {
				t.Fatalf("diagnostic scope/I/O: %+v loads=%d, want actor=%s org=%s reason=%s loads=%d", observed, x.wallets.loads, actor, wantOrg, reason, wantLoads)
			}
			if name == "allowed" {
				if err != nil || current == nil || current.Organization() != org || current.Recheck(t.Context()) != nil {
					t.Fatal("observed success lost original authority", err)
				}
			} else if err == nil || current != nil {
				t.Fatal("diagnostic observation manufactured authority on failure")
			}
		})
	}
}
