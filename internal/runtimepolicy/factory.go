// Package runtimepolicy captures one verified request's policy facts from one
// selected immutable bundle. Its method, source claim and read-association data
// are inputs to subsequent admission/response decisions, not forwarding grants.
package runtimepolicy

import (
	"github.com/ethereum/go-ethereum/common"

	"privacy-proxy/internal/identity"
	"privacy-proxy/internal/policybundle"
)

type registeredContract struct {
	owner    string
	contract policybundle.Contract
}
type Factory struct {
	snapshot  *policybundle.CatalogSnapshot
	verifier  *identity.Verifier
	clock     identity.Clock
	contracts map[common.Address]registeredContract
}

// NewFactory binds verification and policy lookup to exactly the same selected
// snapshot. No constructor accepts a principal verified against another catalog.
func NewFactory(snapshot *policybundle.CatalogSnapshot, clock identity.Clock) (*Factory, error) {
	if snapshot == nil {
		return nil, &Error{InvalidSnapshot}
	}
	catalog, ok := snapshot.Identity()
	if !ok {
		return nil, &Error{InvalidSnapshot}
	}
	verifier, err := identity.NewVerifier(catalog, clock)
	if err != nil {
		return nil, &Error{InvalidSnapshot}
	}
	f := &Factory{snapshot: snapshot, verifier: verifier, clock: clock, contracts: map[common.Address]registeredContract{}}
	for _, org := range snapshot.Organizations() {
		native, ok := snapshot.NativeCatalog(org.ID)
		if !ok {
			return nil, &Error{InvalidSnapshot}
		}
		for address := range native.Contracts {
			key := common.HexToAddress(address)
			contract, ok := snapshot.Contract(org.ID, key)
			if !ok {
				return nil, &Error{InvalidSnapshot}
			}
			if _, duplicate := f.contracts[key]; duplicate {
				return nil, &Error{InvalidSnapshot}
			}
			f.contracts[key] = registeredContract{org.ID, contract}
		}
	}
	return f, nil
}

func (f *Factory) Build(rawAccessJWT string) (*View, error) {
	principal, err := f.verifier.VerifyAccess(rawAccessJWT)
	if err != nil {
		return nil, &Error{InvalidAccess}
	}
	view := &View{factory: f, principal: principal, orgs: map[string]*OrgView{}}
	for _, org := range f.snapshot.Organizations() {
		ids := principal.Groups(org.ID)
		if len(ids) == 0 {
			continue
		}
		o, err := makeOrg(f.snapshot, org.ID, ids)
		if err != nil {
			return nil, err
		}
		view.orgs[org.ID] = o
	}
	if err := view.RequireLive(); err != nil {
		return nil, err
	}
	return view, nil
}
