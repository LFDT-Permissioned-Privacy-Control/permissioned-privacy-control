package historyfacts

import (
	"bytes"
	"sort"

	"github.com/ethereum/go-ethereum/common"
	"privacy-proxy/internal/explorerdata"
	"privacy-proxy/internal/policycore"
)

// ForMethod borrows the verified original identity, wallet and deadline while
// checking the ordinary sub-operation's independent method/claim/credential gate.
func (c *Current) ForMethod(method string) (*Current, error) {
	if c == nil || c.owner == nil || c.view == nil || c.fence.Check() != nil || c.view.RequireLive() != nil {
		return nil, ErrUnavailable
	}
	org, ok := c.view.Org(c.org)
	if !ok || !org.GroupAllowsMethod(method) {
		return nil, ErrUnavailable
	}
	declaration, ok := c.owner.config.Snapshot.Method(method)
	if !ok {
		return nil, ErrUnavailable
	}
	for _, claim := range declaration.RequiredClaims {
		mask := map[string]uint8{"admin": policycore.ClaimAdmin, "deploy": policycore.ClaimDeploy, "upgrade": policycore.ClaimUpgrade}[claim]
		if mask == 0 || org.UnionClaims()&mask == 0 {
			return nil, ErrUnavailable
		}
	}
	credential, err := org.SelectCredentialRef(method)
	if err != nil {
		return nil, ErrUnavailable
	}
	next := *c
	next.method, next.credential = method, credential
	next.shares = nil
	next.charged = 1024 + 32*len(c.wallet.Addresses())
	return &next, nil
}

// FullAddressSet is the complete plain-address authority filter. Transaction
// participants, shares, disclosures and derived indexer facts never enter it.
func (c *Current) FullAddressSet(max int) ([]common.Address, error) {
	if c == nil || c.view == nil || max < 1 || max > 4096 || c.fence.Check() != nil || c.view.RequireLive() != nil {
		return nil, ErrUnavailable
	}
	contracts, complete := c.view.AssociatedContractAddresses(c.org, max)
	if !complete {
		return nil, ErrTooBroad
	}
	set := map[common.Address]bool{}
	add := func(a common.Address) bool {
		if c.Address(a).Level != explorerdata.VisibilityFull {
			return true
		}
		set[a] = true
		return len(set) <= max
	}
	for _, a := range c.wallet.Addresses() {
		if !add(a) {
			return nil, ErrTooBroad
		}
	}
	for _, a := range contracts {
		if !add(a) {
			return nil, ErrTooBroad
		}
	}
	for i := 1; i <= 9; i++ {
		var a common.Address
		a[19] = byte(i)
		if !add(a) {
			return nil, ErrTooBroad
		}
	}
	out := make([]common.Address, 0, len(set))
	for a := range set {
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool { return bytes.Compare(out[i][:], out[j][:]) < 0 })
	return out, nil
}
