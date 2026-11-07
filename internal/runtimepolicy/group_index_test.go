package runtimepolicy

import (
	"fmt"
	"testing"

	"privacy-proxy/internal/policybundle"
)

func TestLargeMembershipIndexAvoidsRepeatedGroupCopies(t *testing.T) {
	o := &OrgView{groups: make([]string, 4096), groupData: map[string]policybundle.Group{}}
	for i := range o.groups {
		id := fmt.Sprintf("group-%04d", i)
		o.groups[i] = id
		o.groupData[id] = policybundle.Group{ID: id}
	}
	refs := make([]string, 128)
	for i := range refs {
		if i%2 == 0 {
			refs[i] = o.groups[i*31]
		} else {
			refs[i] = fmt.Sprintf("missing-%04d", i)
		}
	}
	result := 0
	allocations := testing.AllocsPerRun(10, func() {
		found := 0
		for _, ref := range refs {
			if o.HasGroup(ref) {
				found++
			}
		}
		result = found
	})
	if result != 64 || allocations != 0 {
		t.Fatalf("membership lookup copies/scans aggregate state: hits=%d allocations=%g", result, allocations)
	}
	exported := o.Groups()
	exported[0] = "changed"
	if !o.HasGroup("group-0000") || o.HasGroup("changed") || o.HasGroup("GROUP-0000") {
		t.Fatal("getter mutation or normalization changed membership")
	}
}
