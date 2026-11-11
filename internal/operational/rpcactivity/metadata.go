package rpcactivity

import (
	"context"
	"encoding/hex"
	"slices"

	"privacy-proxy/internal/activitylog"
	"privacy-proxy/internal/policybundle"
	"privacy-proxy/internal/rpcengine"
)

// New binds the actual engine(s) to one recorder and one output-lifetime gate.
// Metadata-only construction creates no native admission/wallet/Guard resource.
func newMetadataService(c Config) (*Service, error) {
	if c.Metadata == nil {
		return newNativeService(c)
	}
	key, err := c.Network.Key()
	if err != nil || c.Recorder == nil || c.Recorder.Healthy() != nil {
		return nil, ErrInvalid
	}
	binding := c.Metadata.OperationBinding()
	m, bounds := c.Recorder.Metadata(), c.Recorder.Bounds()
	if binding.Profile != policybundle.RuntimeCreationObservedProfileID || binding.Environment != c.Network.Environment || binding.ChainID != c.Network.ChainID || binding.NetworkKey != "sha256:"+hex.EncodeToString(key[:]) || len(binding.ManifestDigest) != 71 || len(binding.PolicyDigest) != 71 || len(binding.OrganizationIDs) == 0 || m.NetworkKey != activitylog.Digest(key) || m.Format != activitylog.Format() || !activitylog.CanonicalUUID(m.SourceID) || !activitylog.CanonicalUUID(m.Generation) || m.Configuration == (activitylog.Digest{}) || !bounds.Valid() {
		return nil, ErrInvalid
	}
	var service *Service
	needed := map[string]bool{"rpc.invalid_request": true, "rpc.invalid_transport": true}
	if c.Engine != nil {
		service, err = newNativeService(c)
		if err != nil || !c.Metadata.SharesSnapshot(c.Engine) {
			return nil, ErrInvalid
		}
		native := c.Engine.OperationBinding()
		if native.Environment != binding.Environment || native.ChainID != binding.ChainID || native.Profile != binding.Profile || native.NetworkKey != binding.NetworkKey || native.ManifestDigest != binding.ManifestDigest || !slices.Equal(native.OrganizationIDs, binding.OrganizationIDs) {
			return nil, ErrInvalid
		}
		for _, name := range labels {
			needed[name] = true
		}
	} else {
		service = &Service{recorder: c.Recorder, organizations: slices.Clone(binding.OrganizationIDs), slots: make(chan struct{}, bounds.InFlight)}
	}
	for _, name := range binding.Methods {
		if !activitylog.ValidMethod(name) {
			return nil, ErrInvalid
		}
		needed[name] = true
	}
	if len(needed) > 512 {
		return nil, ErrInvalid
	}
	methods := c.Recorder.Methods()
	for name := range needed {
		if !slices.Contains(methods, name) {
			return nil, ErrInvalid
		}
	}
	service.metadata = c.Metadata
	return service, nil
}

// The union is private and concrete; callers cannot supply operation callbacks
// or a detached success response to bypass the real owned result and View.
type observedOperation struct {
	native   *rpcengine.OperationResult
	metadata *rpcengine.MetadataOperationResult
	state    *rpcengine.StateOperationResult
}

func (o observedOperation) valid() bool {
	n := 0
	if o.native != nil {
		n++
	}
	if o.metadata != nil {
		n++
	}
	if o.state != nil {
		n++
	}
	return n == 1
}
func (o observedOperation) notification(s *Service) (bool, error) {
	if !o.valid() {
		return false, ErrInvalid
	}
	if o.metadata != nil {
		return o.metadata.IsNotificationFor(s.metadata)
	}
	if o.state != nil {
		return o.state.IsNotificationFor(s.state)
	}
	return false, nil
}
func (o observedOperation) completion(s *Service, remote string) (activitylog.Completion, error) {
	invalid, _ := completion(rpcengine.OperationMetadata{}, remote)
	if !o.valid() {
		return invalid, ErrInvalid
	}
	if o.native != nil {
		m, err := o.native.MetadataFor(s.engine)
		if err != nil {
			return invalid, err
		}
		return completion(m, remote)
	}
	if o.state != nil {
		m, err := o.state.MetadataFor(s.state)
		if err != nil {
			return invalid, err
		}
		c, err := completion(rpcengine.OperationMetadata{Class: m.Class, ActorID: m.ActorID, OrganizationID: m.OrganizationID, PolicyDigest: m.PolicyDigest, RPCErrorCode: m.RPCErrorCode}, remote)
		if err != nil || !activitylog.ValidMethod(m.Method) {
			return c, ErrInvalid
		}
		c.Method = m.Method
		return c, nil
	}
	m, err := o.metadata.MetadataFor(s.metadata)
	if err != nil {
		return invalid, err
	}
	c, err := completion(rpcengine.OperationMetadata{Class: m.Class, ActorID: m.ActorID, OrganizationID: m.OrganizationID, PolicyDigest: m.PolicyDigest, RPCErrorCode: m.RPCErrorCode}, remote)
	if err != nil || !activitylog.ValidMethod(m.Method) {
		return c, ErrInvalid
	}
	c.Method = m.Method
	return c, nil
}
func (o observedOperation) preflight(s *Service) error {
	if !o.valid() {
		return ErrInvalid
	}
	if o.native != nil {
		return o.native.PreflightFor(s.engine)
	}
	if o.state != nil {
		return o.state.PreflightFor(s.state)
	}
	return o.metadata.PreflightFor(s.metadata)
}
func (o observedOperation) marshal(s *Service) ([]byte, error) {
	if !o.valid() {
		return nil, ErrInvalid
	}
	if o.native != nil {
		return o.native.MarshalResponseFor(s.engine)
	}
	if o.state != nil {
		return o.state.MarshalResponseFor(s.state)
	}
	return o.metadata.MarshalResponseFor(s.metadata)
}
func (o observedOperation) recordingFailure(s *Service) ([]byte, error) {
	if !o.valid() {
		return nil, ErrInvalid
	}
	if o.native != nil {
		return o.native.MarshalRecordingFailureFor(s.engine)
	}
	if o.state != nil {
		return o.state.MarshalRecordingFailureFor(s.state)
	}
	return o.metadata.MarshalRecordingFailureFor(s.metadata)
}
func (o observedOperation) deliver(ctx context.Context, s *Service) error {
	if !o.valid() {
		return ErrInvalid
	}
	if o.native != nil {
		return o.native.RequireDeliverable(ctx, s.engine)
	}
	if s.recorder.Healthy() != nil {
		return ErrInvalid
	}
	if o.state != nil {
		return o.state.RequireDeliverable(ctx, s.state)
	}
	return o.metadata.RequireDeliverable(ctx, s.metadata)
}
