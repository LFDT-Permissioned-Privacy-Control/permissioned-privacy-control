package runtimepolicy

import (
	"time"

	"privacy-proxy/internal/identity"
	"privacy-proxy/internal/policybundle"
)

type View struct {
	factory   *Factory
	principal *identity.RequestPrincipal
	orgs      map[string]*OrgView
}

func (v *View) ActorID() string                       { return v.principal.ActorID() }
func (v *View) Kind() identity.Kind                   { return v.principal.Kind() }
func (v *View) ExpiresAt() time.Time                  { return v.principal.ExpiresAt() }
func (v *View) Metadata() policybundle.BundleMetadata { return v.factory.snapshot.Metadata() }
func (v *View) Org(orgID string) (*OrgView, bool)     { org, ok := v.orgs[orgID]; return org, ok }
func (v *View) Live() bool                            { return v.factory.clock().Before(v.ExpiresAt()) }

// RequireLive checks original access expiry; it never renews evidence or alters
// issued Guard approvals. Immutable diagnostic getters remain usable afterward.
func (v *View) RequireLive() error {
	if !v.Live() {
		return &Error{Expired}
	}
	return nil
}
