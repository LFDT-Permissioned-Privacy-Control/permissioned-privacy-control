package rpcactivity

import (
	"encoding/hex"
	"slices"

	"privacy-proxy/internal/activitylog"
	"privacy-proxy/internal/policybundle"
)

// New composes concrete operations with one actual recorder and output gate.
// The original native-only and metadata constructors keep their behavior.
func newStateService(c Config) (*Service, error) {
	if c.State == nil {
		return newMetadataService(c)
	}
	key, err := c.Network.Key()
	if err != nil || c.Recorder == nil || c.Recorder.Healthy() != nil {
		return nil, ErrInvalid
	}
	b := c.State.OperationBinding()
	m, n := c.Recorder.Metadata(), c.Recorder.Bounds()
	if b.Profile != policybundle.RuntimeCreationObservedProfileID || b.Environment != c.Network.Environment || b.ChainID != c.Network.ChainID || b.NetworkKey != "sha256:"+hex.EncodeToString(key[:]) || len(b.ManifestDigest) != 71 || len(b.PolicyDigest) != 71 || len(b.OrganizationIDs) == 0 || m.NetworkKey != activitylog.Digest(key) || m.Format != activitylog.Format() || !activitylog.CanonicalUUID(m.SourceID) || !activitylog.CanonicalUUID(m.Generation) || m.Configuration == (activitylog.Digest{}) || !n.Valid() {
		return nil, ErrInvalid
	}
	var service *Service
	if c.Engine != nil || c.Metadata != nil {
		service, err = newMetadataService(c)
		if err != nil {
			return nil, err
		}
		if c.Engine != nil && !c.State.SharesSnapshot(c.Engine) || c.Metadata != nil && !c.State.SharesMetadataSnapshot(c.Metadata) {
			return nil, ErrInvalid
		}
		if !slices.Equal(service.organizations, b.OrganizationIDs) {
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
	if len(needed) > 512 {
		return nil, ErrInvalid
	}
	methods := c.Recorder.Methods()
	for name := range needed {
		if !activitylog.ValidMethod(name) || !slices.Contains(methods, name) {
			return nil, ErrInvalid
		}
	}
	service.state = c.State
	service.stateMethods = map[string]bool{}
	for _, name := range b.Methods {
		service.stateMethods[name] = true
	}
	return service, nil
}
