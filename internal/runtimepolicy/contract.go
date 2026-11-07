package runtimepolicy

import (
	"encoding/json"
	"slices"
	"sort"

	"github.com/ethereum/go-ethereum/common"

	"privacy-proxy/internal/policybundle"
)

// RegistryMetadata deliberately contains no grants or operational claims.
// It is registry input for later handlers, not an authorization verdict.
type RegistryMetadata struct {
	ID                        string
	Address                   string
	Name                      string
	ABI                       json.RawMessage
	AllowVisibleToUnlock      bool
	EventsAllowDynamicPayload bool
}
type ContractView struct {
	owner             string
	metadata          RegistryMetadata
	associated, admin bool
	grants            []policybundle.ReadGrant
}

func (c ContractView) OwnerOrg() string   { return c.owner }
func (c ContractView) Associated() bool   { return c.associated }
func (c ContractView) AdminForRead() bool { return c.admin }
func (c ContractView) RegistryMetadata() RegistryMetadata {
	m := c.metadata
	m.ABI = slices.Clone(m.ABI)
	return m
}
func (c ContractView) ReadGrants() []policybundle.ReadGrant {
	grants := slices.Clone(c.grants)
	for i := range grants {
		rules := &grants[i].EventRules
		rules.Rules = slices.Clone(rules.Rules)
		for j := range rules.Rules {
			rules.Rules[j].ParamRules = slices.Clone(rules.Rules[j].ParamRules)
		}
	}
	return grants
}

func (v *View) Contract(address common.Address) (ContractView, bool) {
	registered, ok := v.factory.contracts[address]
	if !ok {
		return ContractView{}, false
	}
	c := registered.contract
	view := ContractView{owner: registered.owner, metadata: RegistryMetadata{ID: c.ID, Address: c.Address, Name: c.Name, ABI: c.ABI, AllowVisibleToUnlock: c.AllowVisibleToUnlock, EventsAllowDynamicPayload: c.EventsAllowDynamicPayload}}
	_, view.associated, view.admin, view.grants = v.contractAssociation(registered, true)
	sort.Slice(view.grants, func(i, j int) bool { return view.grants[i].ID < view.grants[j].ID })
	return view, true
}

// ContractAssociation exposes only the same mapped owning-org association used
// by Contract. It copies no ABI or grant payload and grants no native rule.
func (v *View) ContractAssociation(address common.Address) (ownerOrg string, member bool, associated bool, registered bool) {
	c, ok := v.factory.contracts[address]
	if !ok {
		return "", false, false, false
	}
	member, associated, _, _ = v.contractAssociation(c, false)
	return c.owner, member, associated, true
}

func (v *View) contractAssociation(registered registeredContract, collect bool) (member, associated, admin bool, grants []policybundle.ReadGrant) {
	org, member := v.orgs[registered.owner]
	if !member {
		return false, false, false, nil
	}
	associated, admin = org.admin, org.admin
	for _, grant := range registered.contract.ReadGrants {
		g, mapped := org.groupData[grant.GroupID]
		if !mapped {
			continue
		}
		if collect {
			grants = append(grants, grant)
		}
		associated = true
		if g.IsOrgAdmin || slices.Contains(g.Claims, "admin") {
			admin = true
		}
	}
	return true, associated, admin, grants
}
