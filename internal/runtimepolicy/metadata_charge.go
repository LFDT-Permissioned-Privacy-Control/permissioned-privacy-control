package runtimepolicy

import "github.com/ethereum/go-ethereum/common"

// ReadMetadataCharge obtains a conservative size before Contract/Emitter build
// detached grant slices. It walks only the original immutable catalog values.
func (v *View) ReadMetadataCharge(address common.Address) int {
	if v == nil || v.factory == nil {
		return 0
	}
	registered, ok := v.factory.contracts[address]
	if !ok {
		return 0
	}
	c := registered.contract
	n := 256 + len(c.ABI) + len(c.ID) + len(c.Address) + len(c.Name)
	org, mapped := v.orgs[registered.owner]
	if !mapped {
		return n
	}
	for _, grant := range c.ReadGrants {
		if _, mapped := org.groupData[grant.GroupID]; !mapped {
			continue
		}
		n += 256 + len(grant.ID) + len(grant.GroupID) + len(grant.EventRules.Mode)
		for _, rule := range grant.EventRules.Rules {
			n += 256 + len(rule.Topic0) + len(rule.Name)
			for _, p := range rule.ParamRules {
				n += 128 + len(p.MustBe)
			}
		}
	}
	return n
}
