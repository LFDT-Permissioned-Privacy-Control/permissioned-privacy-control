package creationfacts

import (
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
)

func TestCurrentAddressOwnedBoundedOriginalCaptureIsNotReadExpiry(t *testing.T) {
	epoch := "11111111-1111-1111-1111-111111111111"
	target := common.Address{1}
	network := Network{Key: Digest{1}, Environment: "test", ChainID: "1", Genesis: common.Hash{1}, Deployment: "fixture"}
	binding := AddressReadBinding{Network: network, State: State{Generation: epoch}, SourceSet: Digest{2}, Reference: Digest{3}, Profile: CurrentAddressProfile, Limits: DefaultAddressReadLimits()}
	anchor := Header{Number: 1, Hash: common.Hash{2}}
	at := time.Unix(100, 0)
	coverage := CoverageRecord{Version: 1, Policy: CaptureProfile, Network: network.Key, State: State{Generation: epoch}, ObserverEpoch: epoch, CaptureEpoch: epoch, SourceSet: Digest{4}, Reference: Digest{5}, Ingress: Digest{6}, HighWater: anchor, Latest: anchor, HeaderVersion: 1, LeaseFence: 1, ProbeStarted: at, ProbeFinished: at.Add(time.Millisecond), ValidUntil: at.Add(time.Second)}
	row := AddressAssociation{Namespace: epoch, Kind: "FACTORY", Address: target, Creator: common.Address{2}, CreationKind: "CREATE", Record: 1, Inclusion: Header{Number: 2, Hash: common.Hash{3}}, TransactionHash: common.Hash{4}, OutputHash: common.Hash{5}, Proof: common.Hash{6}, OutputLength: 2, Seed: Digest{7}, Plan: Digest{8}, Manifest: Digest{9}, Runtime: Digest{10}, Qualification: Digest{11}, OriginalProfile: "geth-prague-lifecycle-signed/v1", OriginalAnchor: anchor, OriginalCoverage: coverage, Branch: 1}
	owner := NewAddressReaderIdentity()
	input := []AddressAssociation{row}
	pass, err := NewAddressAssociations(owner, binding, target, epoch, 0, Header{Number: row.Inclusion.Number, Hash: row.Inclusion.Hash}, input)
	if err != nil {
		t.Fatal("original1970 diagnostic expiry became deployer expiry", err)
	}
	input[0].Namespace = "mutated"
	get := pass.Candidates()
	get[0].Kind = "mutated"
	if pass.Candidates()[0].Namespace != epoch || pass.Candidates()[0].Kind != "FACTORY" {
		t.Fatal("candidate data aliases")
	}
	if pass.ValidateFor(NewAddressReaderIdentity(), binding, target) == nil || pass.ValidateFor(owner, binding, common.Address{3}) == nil || (&AddressAssociations{}).ValidateFor(owner, binding, target) == nil {
		t.Fatal("foreign/zero result accepted")
	}
	for _, identity := range []*AddressReaderIdentity{nil, {}} {
		if _, err := NewAddressAssociations(identity, binding, target, epoch, 0, Header{Number: row.Inclusion.Number, Hash: row.Inclusion.Hash}, []AddressAssociation{row}); err == nil {
			t.Fatal("zero source owner")
		}
	}
	for _, change := range []func(*AddressAssociation){func(r *AddressAssociation) { r.Kind = "WALLET" }, func(r *AddressAssociation) { r.WalletActor = "ops:p1:wrong" }, func(r *AddressAssociation) {
		r.OriginalCoverage.ProbeFinished = r.OriginalCoverage.ProbeStarted.Add(CaptureTimeout + time.Second)
	}, func(r *AddressAssociation) { r.OriginalAnchor.Number = 2 }, func(r *AddressAssociation) { r.Proof = common.Hash{} }} {
		bad := row
		change(&bad)
		if _, err := NewAddressAssociations(owner, binding, target, epoch, 0, Header{Number: row.Inclusion.Number, Hash: row.Inclusion.Hash}, []AddressAssociation{bad}); err == nil {
			t.Fatal("malformed positive fact accepted")
		}
	}
	low := binding
	low.Limits.MaxCandidates = 1
	if _, err := NewAddressAssociations(owner, low, target, epoch, 0, Header{Number: row.Inclusion.Number, Hash: row.Inclusion.Hash}, []AddressAssociation{row, row}); err == nil {
		t.Fatal("candidate bound reset")
	}
	low = binding
	low.Limits.MaxBytes = 1
	if _, err := NewAddressAssociations(owner, low, target, epoch, 0, Header{Number: row.Inclusion.Number, Hash: row.Inclusion.Hash}, []AddressAssociation{row}); err == nil {
		t.Fatal("byte ceiling ignored")
	}
	empty, err := NewAddressAssociations(owner, binding, target, epoch, 0, Header{Number: row.Inclusion.Number, Hash: row.Inclusion.Hash}, []AddressAssociation{})
	if err != nil || len(empty.Candidates()) != 0 {
		t.Fatal("empty positive projection", err)
	}
	other, err := NewAddressAssociations(owner, binding, target, epoch, 1, Header{Number: row.Inclusion.Number, Hash: row.Inclusion.Hash}, []AddressAssociation{row})
	if err != nil || pass.SameCurrent(other) {
		t.Fatal("reorg currentness ignored", err)
	}
	advanced, err := NewAddressAssociations(owner, binding, target, epoch, 0, Header{Number: 3, Hash: common.Hash{9}}, []AddressAssociation{row})
	if err != nil || !pass.SameCurrent(advanced) || pass.ObserverHead() == advanced.ObserverHead() {
		t.Fatal("head provenance contaminated target-facts digest", err)
	}
	for _, head := range []Header{{}, {Number: 1, Hash: common.Hash{1}}, {Number: 2, Hash: common.Hash{9}}, {Number: 3, Hash: common.Hash{9}, Timestamp: 1}} {
		if _, err := NewAddressAssociations(owner, binding, target, epoch, 0, head, []AddressAssociation{row}); err == nil {
			t.Fatal("invalid observer head provenance")
		}
	}
}
