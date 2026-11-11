package rpcactivity

import (
	"encoding/hex"
	"slices"

	"privacy-proxy/internal/activitylog"
	"privacy-proxy/internal/policybundle"
)

// New composes concrete owned operations with one real Recorder and N-slot
// lifetime. Approved history requirements cannot be served by a sibling alone.
func New(c Config) (*Service, error) {
	if c.History == nil {
		if c.Engine != nil && c.Engine.RequiresHistoryConsumer() || c.Metadata != nil && c.Metadata.RequiresHistoryConsumer() || c.State != nil && c.State.RequiresHistoryConsumer() {
			return nil, ErrInvalid
		}
		return newStateService(c)
	}
	key, err := c.Network.Key()
	if err != nil || c.Recorder == nil || c.Recorder.Healthy() != nil {
		return nil, ErrInvalid
	}
	b := c.History.OperationBinding()
	m, n := c.Recorder.Metadata(), c.Recorder.Bounds()
	if b.Profile != policybundle.RuntimeCreationObservedProfileID || b.Environment != c.Network.Environment || b.ChainID != c.Network.ChainID || b.NetworkKey != "sha256:"+hex.EncodeToString(key[:]) || len(b.ManifestDigest) != 71 || len(b.PolicyDigest) != 71 || len(b.OrganizationIDs) == 0 || m.NetworkKey != activitylog.Digest(key) || m.Format != activitylog.Format() || !activitylog.CanonicalUUID(m.SourceID) || !activitylog.CanonicalUUID(m.Generation) || m.Configuration == (activitylog.Digest{}) || !n.Valid() {
		return nil, ErrInvalid
	}
	var service *Service
	if c.Engine != nil || c.Metadata != nil || c.State != nil {
		service, err = newStateService(c)
		if err != nil {
			return nil, err
		}
		if c.Engine != nil && !c.History.SharesSnapshot(c.Engine) || c.Metadata != nil && !c.History.SharesMetadataSnapshot(c.Metadata) || c.State != nil && !c.History.SharesStateSnapshot(c.State) || !slices.Equal(service.organizations, b.OrganizationIDs) {
			return nil, ErrInvalid
		}
	} else {
		service = &Service{recorder: c.Recorder, organizations: slices.Clone(b.OrganizationIDs), slots: make(chan struct{}, n.InFlight)}
	}
	needed := map[string]bool{"rpc.invalid_request": true, "rpc.invalid_transport": true}
	for _, name := range b.Methods {
		needed[name] = true
	}
	if c.Engine != nil {
		for _, name := range labels {
			needed[name] = true
		}
	}
	if c.Metadata != nil {
		for _, name := range c.Metadata.OperationBinding().Methods {
			needed[name] = true
		}
	}
	if c.State != nil {
		for _, name := range c.State.OperationBinding().Methods {
			needed[name] = true
		}
	}
	if len(needed) > 512 {
		return nil, ErrInvalid
	}
	methods := c.Recorder.Methods()
	for name := range needed {
		if !activitylog.ValidMethod(name) || !slices.Contains(methods, name) {
			return nil, ErrInvalid
		}
	}
	service.history = c.History
	service.historyMethods = map[string]bool{}
	for _, name := range b.Methods {
		service.historyMethods[name] = true
	}
	return service, nil
}
