package protectedsource

import (
	"errors"
	"reflect"
	"testing"

	d "privacy-proxy/internal/disclosuredata"
	h "privacy-proxy/internal/historynamespace"
)

func TestPointPrefixPlansUnknownSupportWithoutFetchingRejectedSuffixes(t *testing.T) {
	// An opaque marker suffices for planning. It is not a NamespacePass and
	// grants no authority; real SQL ResolvePass is exercised by assembled tests.
	marker := &h.Requirements{}
	probed := []int{}
	selected, requirements, err := fitPointPrefix(101, 1, true, func(count int) (*h.Requirements, error) { probed = append(probed, count); return marker, nil }, func(*h.Requirements) bool { return probed[len(probed)-1] <= 2 })
	if err != nil || selected != 2 || requirements != marker || !reflect.DeepEqual(probed, []int{101, 51, 26, 13, 7, 4, 2}) {
		t.Fatal("unknown support did not halve bounded transaction prefix", selected, probed, err)
	}
	// The witness stays included, while a non-fitting last transaction cannot
	// become a successful witness-only/empty page.
	probed = nil
	_, _, err = fitPointPrefix(101, 1, true, func(count int) (*h.Requirements, error) { probed = append(probed, count); return marker, nil }, func(*h.Requirements) bool { return false })
	if !errors.Is(err, d.ErrTooBroad) || len(probed) > 8 || probed[len(probed)-1] != 2 {
		t.Fatal("no-progress planner", probed, err)
	}
	// A changed/unavailable metadata source is not an excuse to shrink past it.
	for _, failure := range []error{d.ErrConflict, d.ErrUnavailable} {
		calls := 0
		_, _, err = fitPointPrefix(100, 0, true, func(count int) (*h.Requirements, error) { calls++; return nil, failure }, func(*h.Requirements) bool { return true })
		if !errors.Is(err, failure) || calls != 1 {
			t.Fatal("source failure hidden by prefix", calls, err)
		}
	}
	probed = nil
	_, _, err = fitPointPrefix(100, 0, false, func(count int) (*h.Requirements, error) { probed = append(probed, count); return marker, nil }, func(*h.Requirements) bool { return false })
	if !errors.Is(err, d.ErrTooBroad) || len(probed) != 1 {
		t.Fatal("whole-set caller was silently shortened", probed, err)
	}
}
