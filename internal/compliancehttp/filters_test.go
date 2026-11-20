package compliancehttp

import (
	"net/http/httptest"
	"testing"
)

func TestEventFiltersAreClosedAndCannotBeIgnoredOnOtherLists(t *testing.T) {
	for _, row := range []struct {
		query         string
		events, valid bool
	}{
		{"?decision=allowed&transferType=eth&actorId=ops:p1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", true, true},
		{"?decision=monitored", true, true}, {"?decision=approved", true, false}, {"?transferType=other", true, false},
		{"?actorId=admin", true, false}, {"?decision=allowed&decision=denied", true, false}, {"?unknown=ignored", true, false},
		{"?decision=allowed", false, false}, {"?limit=25", false, true},
	} {
		_, err := options(httptest.NewRequest("GET", "/events"+row.query, nil), row.events)
		if (err == nil) != row.valid {
			t.Fatalf("%s events=%v: %v", row.query, row.events, err)
		}
	}
}
