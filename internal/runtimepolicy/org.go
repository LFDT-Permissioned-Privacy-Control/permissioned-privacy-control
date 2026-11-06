package runtimepolicy

import (
	"slices"
	"sort"

	"privacy-proxy/internal/policybundle"
	"privacy-proxy/internal/policycore"
)

// GroupMask is a source operational upper bound, not qualified target-specific
// policycore.Frame.GroupClaims. A later resolver must supply target authority.
type GroupMask struct {
	GroupID string
	Claims  uint8
}
type OrgView struct {
	id              string
	snapshot        *policybundle.CatalogSnapshot
	groups          []string
	groupData       map[string]policybundle.Group
	masks           []GroupMask
	methods         map[string]bool
	claims          uint8
	admin, readonly bool
	native          *policycore.Validated
}

func makeOrg(snapshot *policybundle.CatalogSnapshot, id string, groups []string) (*OrgView, error) {
	native, ok := snapshot.Execution(id)
	if !ok {
		return nil, &Error{InvalidSnapshot}
	}
	o := &OrgView{id: id, snapshot: snapshot, groups: slices.Clone(groups), groupData: map[string]policybundle.Group{}, methods: map[string]bool{}, native: native}
	sort.Strings(o.groups)
	for _, id := range o.groups {
		g, ok := snapshot.Group(o.id, id)
		if !ok {
			return nil, &Error{InvalidSnapshot}
		}
		o.groupData[id] = g
		mask := uint8(0)
		for _, claim := range g.Claims {
			switch claim {
			case "admin":
				mask |= policycore.ClaimAdmin | policycore.ClaimDeploy | policycore.ClaimUpgrade
			case "deploy":
				mask |= policycore.ClaimDeploy
			case "upgrade":
				mask |= policycore.ClaimUpgrade
			}
		}
		if g.IsOrgAdmin {
			mask = policycore.ClaimAdmin | policycore.ClaimDeploy | policycore.ClaimUpgrade
			o.admin = true
		}
		o.readonly = o.readonly || g.IsOrgReadonlyAdmin
		o.masks = append(o.masks, GroupMask{id, mask})
		o.claims |= mask
		for _, name := range g.AllowedMethods {
			o.methods[name] = true
		}
	}
	return o, nil
}

func (o *OrgView) Groups() []string                     { return slices.Clone(o.groups) }
func (o *OrgView) GroupMasks() []GroupMask              { return slices.Clone(o.masks) }
func (o *OrgView) UnionClaims() uint8                   { return o.claims }
func (o *OrgView) IsOrgAdmin() bool                     { return o.admin }
func (o *OrgView) IsOrgReadonlyAdmin() bool             { return o.readonly }
func (o *OrgView) NativeProgram() *policycore.Validated { return o.native }
