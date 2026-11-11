package nativeadmission_test

import (
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	f "privacy-proxy/internal/creationfacts"
	df "privacy-proxy/internal/disclosuretest"
	n "privacy-proxy/internal/nativeadmission"
	"privacy-proxy/internal/policybundle"
	"privacy-proxy/internal/runtimepolicy"
)

// These are pure adapter-shape/compiler controls. Actual SQL publication and
// serving/probe provenance are tested separately, not claimed by this fixture.
func TestCurrentNativeOverlayOwnedScopeActorAndPriority(t *testing.T) {
	target := common.HexToAddress("0x1234000000000000000000000000000000000000")
	scoped := common.HexToAddress("0x5678000000000000000000000000000000000000")
	fixture := df.DefaultStateFixture(t)
	fixture.Contracts[df.Org] = []policybundle.Contract{df.ReadContract(target.Hex())}
	fixture.Runtime = &policybundle.RuntimeCreationObservedSource{APIVersion: policybundle.RuntimeCreationObservedAPIVersion, Kind: policybundle.RuntimeKind, ReadProfile: "standard", IntraOrgGrantTracing: true, SharedInfrastructure: []policybundle.SharedInfrastructure{}, AddressScopes: []policybundle.AddressScope{{Address: scoped.Hex(), OrganizationID: df.Org}}, NodeEvidenceProfile: policybundle.RuntimeSimulationNodeEvidenceProfileID, RawSubmissionMode: policybundle.RawSubmissionOPSPreflight, CreationAttribution: policybundle.CreationAttribution{Factories: []policybundle.FactoryAttribution{}}, CaptureReadinessProfile: "same-node-caught-up/v1"}
	snapshot := df.StateSnapshot(t, fixture)
	clock := func() time.Time { return time.Unix(df.Now, 0) }
	engine, err := n.NewCreationObserved(snapshot, clock)
	if err != nil {
		t.Fatal(err)
	}
	factory, err := runtimepolicy.NewFactory(snapshot, clock)
	if err != nil {
		t.Fatal(err)
	}
	token := df.Token(t, snapshot, df.Subject, "Auditor")
	view, err := factory.Build(token)
	if err != nil {
		t.Fatal(err)
	}
	epoch := "11111111-1111-1111-1111-111111111111"
	network := f.Network{Key: f.Digest{1}, Environment: "test", ChainID: "1", Genesis: common.Hash{1}, Deployment: "shape-fixture"}
	b := f.AddressReadBinding{Network: network, State: f.State{Generation: epoch}, SourceSet: f.Digest{2}, Reference: f.Digest{3}, Profile: f.CurrentAddressProfile, Limits: f.DefaultAddressReadLimits()}
	m := f.AddressReaderMetadata{Binding: b, Identity: f.NewAddressReaderIdentity()}
	anchor := f.Header{Number: 1, Hash: common.Hash{2}}
	at := time.Unix(100, 0)
	coverage := f.CoverageRecord{Version: 1, Policy: f.CaptureProfile, Network: network.Key, State: b.State, ObserverEpoch: epoch, CaptureEpoch: epoch, SourceSet: f.Digest{4}, Reference: f.Digest{5}, Ingress: f.Digest{6}, HighWater: anchor, Latest: anchor, HeaderVersion: 1, LeaseFence: 1, ProbeStarted: at, ProbeFinished: at.Add(time.Millisecond), ValidUntil: at.Add(time.Second)}
	row := f.AddressAssociation{Namespace: df.Org, Kind: "FACTORY", Address: scoped, Creator: common.Address{2}, CreationKind: "CREATE", Record: 1, Inclusion: f.Header{Number: 2, Hash: common.Hash{3}}, TransactionHash: common.Hash{4}, OutputHash: common.Hash{5}, Proof: common.Hash{6}, OutputLength: 2, Seed: f.Digest{7}, Plan: f.Digest{8}, Manifest: f.Digest{9}, Runtime: f.Digest{10}, Qualification: f.Digest{11}, OriginalProfile: "geth-prague-lifecycle-signed/v1", OriginalAnchor: anchor, OriginalCoverage: coverage, Branch: 1}
	pass := func(rows []f.AddressAssociation, stamp string) *f.AddressAssociations {
		t.Helper()
		p, err := f.NewAddressAssociations(m.Identity, b, scoped, stamp, 0, f.Header{Number: 2, Hash: common.Hash{3}}, rows)
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	for _, item := range []struct {
		name                  string
		rows                  []f.AddressAssociation
		qualified, associated bool
	}{
		{"scope-only", nil, false, false},
		{"factory", []f.AddressAssociation{row}, true, false},
		{"wallet", func() []f.AddressAssociation {
			r := row
			r.Kind = "WALLET"
			r.WalletActor = view.ActorID()
			return []f.AddressAssociation{r}
		}(), true, true},
		{"old-wallet-other-namespace", func() []f.AddressAssociation {
			r := row
			r.Namespace = df.OtherOrg
			r.Kind = "WALLET"
			r.WalletActor = view.ActorID()
			return []f.AddressAssociation{r}
		}(), false, true},
	} {
		t.Run(item.name, func(t *testing.T) {
			owned, err := engine.WithCurrentAddressFacts(view, m, b, []*f.AddressAssociations{pass(item.rows, epoch)})
			if err != nil {
				t.Fatal(err)
			}
			if owner, err := owned.CurrentOwner(view, scoped); err != nil || owner != df.Org {
				t.Fatal("scope lost", owner, err)
			}
			qualified, member, associated := owned.CurrentFactsForTest(view, scoped)
			if (qualified != "") != item.qualified {
				t.Fatal("scope invented or lost candidate namespace", qualified)
			}
			if !member || associated != item.associated {
				t.Fatal("actor association/FACTORY distinction", member, associated)
			}
			original, err := engine.WithCurrentAddressFacts(view, m, b, nil)
			if err != nil {
				t.Fatal(err)
			}
			q, _, a := original.CurrentFactsForTest(view, scoped)
			if q != "" || a {
				t.Fatal("global engine mutated")
			}
			other, _ := factory.Build(token)
			if _, err := owned.CurrentOwner(other, scoped); err == nil {
				t.Fatal("same-token different View accepted")
			}
			if _, err := owned.WithCurrentAddressFacts(view, m, b, nil); err == nil {
				t.Fatal("overlay rebound")
			}
		})
	}
	t.Run("current-git-positive-wins-old-owner", func(t *testing.T) {
		r := row
		r.Address = target
		r.Namespace = df.OtherOrg
		p, err := f.NewAddressAssociations(m.Identity, b, target, epoch, 0, f.Header{Number: 2, Hash: common.Hash{3}}, []f.AddressAssociation{r})
		if err != nil {
			t.Fatal(err)
		}
		owned, err := engine.WithCurrentAddressFacts(view, m, b, []*f.AddressAssociations{p})
		if err != nil {
			t.Fatal(err)
		}
		if q, _, _ := owned.CurrentFactsForTest(view, target); q != df.Org {
			t.Fatal("old namespace overrode current Git")
		}
	})
	t.Run("conflicting-runtime-fingerprints", func(t *testing.T) {
		for _, change := range []func(*f.AddressAssociation){
			func(r *f.AddressAssociation) { r.OutputHash[0]++ },
			func(r *f.AddressAssociation) { r.OutputLength++ },
			func(r *f.AddressAssociation) { r.Index++ },
		} {
			r := row
			change(&r)
			if _, err := engine.WithCurrentAddressFacts(view, m, b, []*f.AddressAssociations{pass([]f.AddressAssociation{row, r}, epoch)}); err == nil {
				t.Fatal("same birth with conflicting runtime fingerprint accepted")
			}
		}
	})
	t.Run("different-reader-and-conflicting-births", func(t *testing.T) {
		bad := m
		bad.Identity = f.NewAddressReaderIdentity()
		if _, err := engine.WithCurrentAddressFacts(view, bad, b, []*f.AddressAssociations{pass([]f.AddressAssociation{row}, epoch)}); err == nil {
			t.Fatal("foreign source")
		}
		r := row
		r.Record++
		if _, err := engine.WithCurrentAddressFacts(view, m, b, []*f.AddressAssociations{pass([]f.AddressAssociation{row, r}, epoch)}); err == nil {
			t.Fatal("conflicting births")
		}
	})
}
