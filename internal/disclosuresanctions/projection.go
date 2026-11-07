// Package disclosuresanctions projects the approved sanctions catalog onto an
// exact supplied address set. It grants no access and proves no history coverage.
package disclosuresanctions

import (
	"bytes"
	"context"
	"encoding/hex"

	d "privacy-proxy/internal/disclosuredata"
	"privacy-proxy/internal/policybundle"
)

const MaxAddresses = 4096

type row struct {
	organization string // empty is the approved global scope
	match        d.SanctionMatch
}

// Projector owns immutable catalog data and is safe for concurrent calls.
type Projector struct {
	bundle, catalog d.Digest
	organizations   map[string]struct{}
	rows            []row
}

// Projection describes only the input population. In particular, zero input
// addresses or matches is not a complete, clear or not-applicable report.
type Projection struct {
	BundleDigest, CatalogDigest d.Digest
	ScopedAddressCount          uint16
	Matches                     []d.SanctionMatch
}

func New(snapshot *policybundle.CatalogSnapshot) (*Projector, error) {
	if snapshot == nil {
		return nil, d.ErrInvalid
	}
	catalog, ok := snapshot.Compliance()
	if !ok || catalog == nil {
		return nil, d.ErrUnsupported
	}
	p := &Projector{bundle: d.Digest(snapshot.Metadata().ManifestDigest), catalog: d.Digest(catalog.Digest()), organizations: map[string]struct{}{}, rows: []row{}}
	for _, org := range snapshot.Organizations() {
		p.organizations[org.ID] = struct{}{}
	}
	// The accepted compiler already validates canonical addresses, unique IDs,
	// exact scopes, limits and ID ordering. Reuse its detached rows once.
	for _, source := range catalog.Sanctions() {
		raw, err := hex.DecodeString(source.Address[2:])
		if err != nil || len(raw) != 20 {
			return nil, d.ErrInvalid
		}
		var address [20]byte
		copy(address[:], raw)
		p.rows = append(p.rows, row{source.OrganizationID, d.SanctionMatch{Address: address, SourceID: source.ID, Reason: source.Reason}})
	}
	return p, nil
}

// Match requires a configured exact organization and strictly increasing unique
// binary addresses. The caller must separately qualify the address population
// and disclosure permission. The returned rows are detached from the projector.
func (p *Projector) Match(ctx context.Context, organization string, addresses [][20]byte) (Projection, error) {
	if p == nil || ctx == nil {
		return Projection{}, d.ErrInvalid
	}
	if _, ok := p.organizations[organization]; !ok {
		return Projection{}, d.ErrInvalid
	}
	if len(addresses) > MaxAddresses {
		return Projection{}, d.ErrTooBroad
	}
	if ctx.Err() != nil {
		return Projection{}, d.ErrUnavailable
	}
	for i := 1; i < len(addresses); i++ {
		if bytes.Compare(addresses[i-1][:], addresses[i][:]) >= 0 {
			return Projection{}, d.ErrInvalid
		}
	}
	selected := make(map[[20]byte]struct{}, len(addresses))
	for _, address := range addresses {
		selected[address] = struct{}{}
	}
	out := Projection{BundleDigest: p.bundle, CatalogDigest: p.catalog, ScopedAddressCount: uint16(len(addresses)), Matches: []d.SanctionMatch{}}
	for _, r := range p.rows {
		if ctx.Err() != nil {
			return Projection{}, d.ErrUnavailable
		}
		if r.organization != "" && r.organization != organization {
			continue
		}
		if _, ok := selected[r.match.Address]; ok {
			out.Matches = append(out.Matches, r.match)
		}
	}
	if ctx.Err() != nil {
		return Projection{}, d.ErrUnavailable
	}
	return out, nil
}
