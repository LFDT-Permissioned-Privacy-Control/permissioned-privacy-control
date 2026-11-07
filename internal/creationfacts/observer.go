package creationfacts

import "time"

// ObserverState is detached operational state. A lease or ready flag is never
// policy authority or a substitute for original covered capture/canonicality.
type ObserverState struct {
	Network                     Digest
	ObserverEpoch, CaptureEpoch string
	Ready, CaptureReady         bool
	Quarantine                  string
	Floor, Head                 Header
	HeaderVersion, ReorgEpoch   int64
	LeaseOwner                  string
	LeaseFence                  int64
	LeaseExpires                time.Time
	LeaseRemainingTTL           time.Duration
	KnownTip                    Header
	KnownTipSet                 bool
	SourceSet, Reference        Digest
}

type Lease struct {
	Network                            Digest
	State                              State
	Owner, ObserverEpoch, CaptureEpoch string
	Fence                              int64
	SourceSet, Reference               Digest
}

func (l Lease) Valid() bool {
	return l.Network != (Digest{}) && l.State.Valid() && UUID(l.Owner) && UUID(l.ObserverEpoch) && UUID(l.CaptureEpoch) && l.Fence > 0 && l.SourceSet != (Digest{}) && l.Reference != (Digest{})
}

// ObserverSnapshot binds one short-lived worker lease to its exact published
// canonical prefix. It is operational metadata, never a permission verdict.
type ObserverSnapshot struct {
	Lease Lease
	State ObserverState
}

// HeaderUpdate publishes one bounded contiguous suffix after Common. Tip is a
// freshly rechecked reference observation. Only a head equal to Tip can publish
// capture readiness; a partial catch-up remains capture-unready.
type HeaderUpdate struct {
	Before  ObserverSnapshot
	Common  Header
	Headers []Header
	Tip     Header
}
