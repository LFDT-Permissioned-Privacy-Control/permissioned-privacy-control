package rpcengine

import (
	"context"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	f "privacy-proxy/internal/creationfacts"
	df "privacy-proxy/internal/disclosuretest"
	"privacy-proxy/internal/nativeadmission"
	"privacy-proxy/internal/runtimepolicy"
)

// Adapter-shape controls for aggregation bounds, not SQL publication claims.
type boundedAddressShape struct {
	meta  f.AddressReaderMetadata
	epoch string
	head  f.Header
	rows  []f.AddressAssociation
	reads int
}

func (r *boundedAddressShape) Metadata() f.AddressReaderMetadata { return r.meta }
func (r *boundedAddressShape) ReadAddressAssociations(ctx context.Context, target common.Address) (*f.AddressAssociations, error) {
	r.reads++
	rows := append([]f.AddressAssociation{}, r.rows...)
	for i := range rows {
		rows[i].Address = target
	}
	return f.NewAddressAssociations(r.meta.Identity, r.meta.Binding, target, r.epoch, 0, r.head, rows)
}
func (r *boundedAddressShape) RecheckAddressAssociations(context.Context, *f.AddressAssociations) error {
	return nil
}

func TestNativeCurrentAggregateBoundsStampAndHead(t *testing.T) {
	snapshot := df.StateSnapshot(t, df.DefaultStateFixture(t))
	clock := func() time.Time { return time.Unix(df.Now, 0) }
	n, err := nativeadmission.NewCreationObserved(snapshot, clock)
	if err != nil {
		t.Fatal(err)
	}
	factory, err := runtimepolicy.NewFactory(snapshot, clock)
	if err != nil {
		t.Fatal(err)
	}
	view, err := factory.Build(df.Token(t, snapshot, df.Subject, "Auditor"))
	if err != nil {
		t.Fatal(err)
	}
	epoch := "11111111-1111-1111-1111-111111111111"
	b := f.AddressReadBinding{Network: f.Network{Key: f.Digest{1}, Environment: "test", ChainID: "1", Genesis: common.Hash{1}, Deployment: "shape"}, State: f.State{Generation: epoch}, SourceSet: f.Digest{2}, Reference: f.Digest{3}, Profile: f.CurrentAddressProfile, Limits: f.DefaultAddressReadLimits()}
	newPass := func() (*nativeAddressPass, *boundedAddressShape) {
		r := &boundedAddressShape{meta: f.AddressReaderMetadata{Binding: b, Identity: f.NewAddressReaderIdentity()}, epoch: epoch, head: f.Header{Number: 2, Hash: common.Hash{3}}}
		e := &Engine{snapshot: snapshot, native: n, current: &nativeAddressSource{reader: r, metadata: r.meta, limits: DefaultNativeAddressLimits()}}
		return e.currentPass(view), r
	}
	addr := func(i int) common.Address { v := 1000 + i; return common.BytesToAddress([]byte{byte(v >> 8), byte(v)}) }
	t.Run("64-deduplicated-65th-rejected", func(t *testing.T) {
		p, r := newPass()
		for i := 0; i < 64; i++ {
			if err := p.lookup(t.Context(), addr(i)); err != nil {
				t.Fatal(i, err)
			}
			if err := p.lookup(t.Context(), addr(i)); err != nil {
				t.Fatal(err)
			}
		}
		if r.reads != 64 {
			t.Fatal("repeated frames multiplied source reads", r.reads)
		}
		if p.lookup(t.Context(), addr(65)) == nil || r.reads != 64 {
			t.Fatal("address cap spent extra source read", r.reads)
		}
	})
	t.Run("one-original-observer-stamp", func(t *testing.T) {
		p, r := newPass()
		if p.lookup(t.Context(), addr(1)) != nil {
			t.Fatal("first")
		}
		r.epoch = "22222222-2222-2222-2222-222222222222"
		if p.lookup(t.Context(), addr(2)) == nil {
			t.Fatal("mixed observer generations")
		}
	})
	t.Run("ordinary-head-advance-and-conflicting-height", func(t *testing.T) {
		p, r := newPass()
		if p.lookup(t.Context(), addr(1)) != nil {
			t.Fatal("first")
		}
		r.head = f.Header{Number: 3, Hash: common.Hash{4}}
		if p.lookup(t.Context(), addr(2)) != nil || p.head != r.head {
			t.Fatal("normal observer progress rejected")
		}
		r.head.Hash = common.Hash{5}
		if p.lookup(t.Context(), addr(3)) == nil {
			t.Fatal("conflicting same-height heads joined")
		}
	})
	t.Run("aggregate-canonical-byte-boundary", func(t *testing.T) {
		p, r := newPass()
		anchor := f.Header{Number: 1, Hash: common.Hash{2}}
		at := time.Unix(100, 0)
		c := f.CoverageRecord{Version: 1, Policy: f.CaptureProfile, Network: b.Network.Key, State: b.State, ObserverEpoch: epoch, CaptureEpoch: epoch, SourceSet: f.Digest{4}, Reference: f.Digest{5}, Ingress: f.Digest{6}, HighWater: anchor, Latest: anchor, HeaderVersion: 1, LeaseFence: 1, ProbeStarted: at, ProbeFinished: at.Add(time.Millisecond), ValidUntil: at.Add(time.Second)}
		r.rows = []f.AddressAssociation{{Namespace: df.Org, Kind: "FACTORY", Creator: common.Address{2}, CreationKind: "CREATE", Record: 1, Inclusion: r.head, TransactionHash: common.Hash{4}, OutputHash: common.Hash{5}, Proof: common.Hash{6}, OutputLength: 2, Seed: f.Digest{7}, Plan: f.Digest{8}, Manifest: f.Digest{9}, Runtime: f.Digest{10}, Qualification: f.Digest{11}, OriginalProfile: "geth-prague-lifecycle-signed/v1", OriginalAnchor: anchor, OriginalCoverage: c, Branch: 1}}
		pass, err := r.ReadAddressAssociations(t.Context(), addr(1))
		if err != nil {
			t.Fatal(err)
		}
		p.owner.current.limits.MaxBytes = pass.CandidateBytes()
		if p.lookup(t.Context(), addr(1)) != nil {
			t.Fatal("exact byte boundary rejected")
		}
		if p.lookup(t.Context(), addr(2)) == nil {
			t.Fatal("aggregate byte budget restarted per point read")
		}
	})
}
