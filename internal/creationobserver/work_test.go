package creationobserver

import (
	"encoding/json"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/google/uuid"
	a "privacy-proxy/internal/admission"
	f "privacy-proxy/internal/creationfacts"
	"privacy-proxy/internal/nativeadmission"
	"privacy-proxy/internal/policybundle"
	"privacy-proxy/internal/rpcexecution"
)

func testStoredWork(t *testing.T) StoredWork {
	t.Helper()
	org := "11111111-1111-4111-8111-111111111111"
	binding := a.NetworkBinding{Environment: "test", ChainID: "1", GenesisHash: common.HexToHash("0x1").Hex(), DeploymentID: "deployment"}
	key, err := binding.Key()
	if err != nil {
		t.Fatal(err)
	}
	n := f.Network{Key: f.Digest(key), Environment: binding.Environment, ChainID: binding.ChainID, Genesis: common.HexToHash(binding.GenesisHash), Deployment: binding.DeploymentID}
	anchor := f.Header{Number: 10, Hash: common.HexToHash("0xa"), Timestamp: 100}
	head := f.Header{Number: 11, Hash: common.HexToHash("0xb"), Parent: anchor.Hash, Timestamp: 101}
	source := f.Source{Network: n, URL: "https://node.invalid", Profile: rpcexecution.IncludedProfileID, PragueStart: 1, PragueEnd: 10000}
	state := f.State{Generation: uuid.NewString(), Coverage: f.Hash("empty", nil)}
	lease := f.Lease{Network: n.Key, State: state, Owner: uuid.NewString(), ObserverEpoch: uuid.NewString(), CaptureEpoch: uuid.NewString(), Fence: 1, SourceSet: f.Hash("source", nil), Reference: source.Digest()}
	before := f.ObserverSnapshot{Lease: lease, State: f.ObserverState{Network: n.Key, ObserverEpoch: lease.ObserverEpoch, CaptureEpoch: lease.CaptureEpoch, Ready: true, Quarantine: "none", Floor: anchor, Head: head, HeaderVersion: 1, LeaseOwner: lease.Owner, LeaseFence: lease.Fence, SourceSet: lease.SourceSet, Reference: lease.Reference}}
	creator := common.HexToAddress("0x1111111111111111111111111111111111111111")
	p := nativeadmission.CreationPlanData{Version: nativeadmission.CapturedCreationPlanVersion, CaptureProfile: f.CaptureProfile, Hash: common.HexToHash("0x123"), RootOrg: org, Manifest: a.HashParts("manifest").String(), Runtime: a.HashParts("runtime").String(), Chain: "1", Evidence: rpcexecution.LifecycleSignedProfileID,
		Entries: []nativeadmission.CreationEntry{{Address: common.HexToAddress("0x2222222222222222222222222222222222222222"), Creator: creator, Caller: creator, Kind: "CREATE", Namespace: org, InputHash: crypto.Keccak256Hash([]byte{0x60, 1}), Value: "0x0", Depth: 1, Record: 1, CreationParent: -1, FactoryRoot: 0}}, Declarations: []policybundle.FactoryAttribution{{Address: a.AddressString(creator), OrganizationID: org, CodeHash: crypto.Keccak256Hash([]byte{0x60, 0}).Hex(), Scope: policybundle.FactoryCreationSubtree}}, FactoryRoots: []nativeadmission.CreationFactoryRoot{{Entry: 0, Declaration: 0}}}
	raw, _ := json.Marshal(p)
	digest := a.Digest(nativeadmission.CapturedCreationPlanDigest(raw))
	now := time.Unix(200, 0).UTC()
	manifest, _ := a.ParseDigest(p.Manifest)
	runtime, _ := a.ParseDigest(p.Runtime)
	i := a.CreationIntent{Plan: raw, PlanDigest: digest, Anchor: rpcexecution.Anchor{Hash: anchor.Hash, Number: anchor.Number, Timestamp: anchor.Timestamp, Profile: p.Evidence}, Factory: true, CapturedAt: now}
	c := f.CoverageRecord{Version: 1, Policy: f.CaptureProfile, Network: n.Key, State: state, ObserverEpoch: lease.ObserverEpoch, CaptureEpoch: lease.CaptureEpoch, SourceSet: lease.SourceSet, Reference: lease.Reference, Ingress: f.Hash("ingress", nil), HighWater: anchor, Latest: anchor, HeaderVersion: 1, LeaseFence: 1, ProbeStarted: now, ProbeFinished: now.Add(time.Millisecond), ValidUntil: now.Add(time.Second)}
	return StoredWork{Network: n, Before: before, Hash: p.Hash, Generation: 1, Plans: []StoredPlan{{Digest: digest, Version: 2, EntryCount: 1, Payload: raw, RootOrg: org, Chain: "1", Evidence: p.Evidence, Manifest: manifest, Runtime: runtime, CreatedAt: now}}, References: []StoredReference{{Seed: i.SeedDigest("FACTORY"), Plan: digest, Kind: "FACTORY", Branch: 1, Anchor: anchor, Profile: p.Evidence, Manifest: manifest, Runtime: runtime, CapturedAt: now, Coverage: &c, AnchorCanonical: true}}}
}

func TestWorkSnapshotCopiesAndChecksImmutableSubset(t *testing.T) {
	raw := testStoredWork(t)
	s, err := CompileStoredWork(raw)
	if err != nil {
		t.Fatal(err)
	}
	digest := s.Digest()
	raw.Plans[0].Payload[0] = 'x'
	raw.References[0].Coverage.CaptureEpoch = uuid.NewString()
	if s.Digest() != digest || !s.HasEligibleCoverage() {
		t.Fatal("caller mutated owned snapshot")
	}
	currentRaw := StoredWork{Network: s.network, Before: s.before, Hash: s.hash, Generation: s.generation, Plans: []StoredPlan{}, References: []StoredReference{}}
	for _, p := range s.plans {
		currentRaw.Plans = append(currentRaw.Plans, p.stored)
	}
	for _, r := range s.refs {
		r.Revoked = true
		r.AnchorCanonical = false
		currentRaw.References = append(currentRaw.References, r)
	}
	current, err := CompileStoredWork(currentRaw)
	if err != nil {
		t.Fatal(err)
	}
	if s.RequireCurrent(current) != nil || current.CurrentlyEligible(s.refs[0].Seed) {
		t.Fatal("mutable deny flags changed immutable identity or allowed revoked seed")
	}
	currentRaw.References[0].CapturedAt = currentRaw.References[0].CapturedAt.Add(time.Second)
	current, err = CompileStoredWork(currentRaw)
	if err != nil {
		t.Fatal(err)
	}
	if !errors.Is(s.RequireCurrent(current), a.ErrCoverage) {
		t.Fatal("first immutable audit metadata changed")
	}
}

func TestPlannedPathHashLinearBudgetAndExactParent(t *testing.T) {
	w := testStoredWork(t)
	p, err := a.DecodeCapturedCreationPlan(w.Plans[0].Payload, w.Plans[0].Digest)
	if err != nil {
		t.Fatal(err)
	}
	first := p.Entries[0]
	p.Entries = nil
	for i := 0; i < 128; i++ {
		e := first
		e.Address = common.BigToAddress(big.NewInt(int64(1000 + i)))
		e.CreationParent = i - 1
		e.Record = i
		e.Depth = i
		p.Entries = append(p.Entries, e)
	}
	paths, work, err := creationPaths(p, 2000000)
	if err != nil || len(paths) != 128 {
		t.Fatal(err)
	}
	half := p
	half.Entries = half.Entries[:64]
	_, halfWork, err := creationPaths(half, 2000000)
	if err != nil || work > halfWork*21/10 {
		t.Fatal("path work grows faster than linear", work, halfWork, err)
	}
	if _, _, err := creationPaths(p, work-1); !errors.Is(err, a.ErrCoverage) {
		t.Fatal("path hash work cap ignored", err)
	}
	old := paths[127]
	p.Entries[127].CreationParent = 0
	changed, _, err := creationPaths(p, 2000000)
	if err != nil || changed[127] == old {
		t.Fatal("changed ancestor did not bind path")
	}
	p.Entries[127].CreationParent = 127
	if _, _, err := creationPaths(p, 2000000); !errors.Is(err, a.ErrCoverage) {
		t.Fatal("cyclic parent accepted")
	}
}

func TestPlannedPathIndependentSHA256Goldens(t *testing.T) {
	e := nativeadmission.CreationEntry{Address: common.HexToAddress("0x11"), Creator: common.HexToAddress("0x22"), Kind: "CREATE", Namespace: "11111111-1111-4111-8111-111111111111", InputHash: common.HexToHash("0x1"), Value: "0x0", Caller: common.HexToAddress("0x33"), Depth: 0, Record: 987, CreationParent: -1, FactoryRoot: -1}
	p := nativeadmission.CreationPlanData{Entries: []nativeadmission.CreationEntry{e}}
	e.Address = common.HexToAddress("0x44")
	e.Kind = "CREATE2"
	e.Depth = 1
	e.Record = 999
	e.CreationParent = 0
	p.Entries = append(p.Entries, e)
	paths, _, err := creationPaths(p, 2000000)
	if err != nil {
		t.Fatal(err)
	}
	// Produced independently with Python stdlib JSON and SHA-256 framing.
	want := []string{"sha256:dd2c7cc41feaa4b0a84d894f4c8697455dcc32ac161534eb287b1b16de19f519", "sha256:fda4d8d4d390fafbc026d8a033f06ef13dcff0376c6f190c3f59617e440b865e"}
	for i := range paths {
		if paths[i].String() != want[i] {
			t.Fatal("path golden", i, paths[i], want[i])
		}
	}
	p.Entries[0], p.Entries[1] = p.Entries[1], p.Entries[0]
	if _, _, err := creationPaths(p, 2000000); !errors.Is(err, a.ErrCoverage) {
		t.Fatal("reordered parent chain accepted", err)
	}
}

func TestWorkSnapshotRejectsBrokenCoverageAndBoundedPayloads(t *testing.T) {
	cases := map[string]func(*StoredWork){
		"v2 missing coverage":        func(w *StoredWork) { w.References[0].Coverage = nil },
		"wrong network":              func(w *StoredWork) { w.Network.Deployment = "another" },
		"wrong seed":                 func(w *StoredWork) { w.References[0].Seed = a.HashParts("wrong") },
		"sparse branch":              func(w *StoredWork) { w.References[0].Branch = 2 },
		"future coverage high water": func(w *StoredWork) { w.References[0].Coverage.HighWater.Number = 11 },
		"giant payload":              func(w *StoredWork) { w.Plans[0].Payload = make([]byte, nativeadmission.MaxCreationPlanBytes+1) },
		"extra unreferenced plan":    func(w *StoredWork) { w.Plans = append(w.Plans, w.Plans[0]) },
		"too many refs":              func(w *StoredWork) { w.References = make([]StoredReference, 17) },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			w := testStoredWork(t)
			change(&w)
			if s, err := CompileStoredWork(w); !errors.Is(err, a.ErrCoverage) || s != nil {
				t.Fatal("invalid snapshot accepted", err)
			}
		})
	}
}

func TestUniqueIncludedCreationAncestryAndIndependentAuthority(t *testing.T) {
	raw := testStoredWork(t)
	s, err := CompileStoredWork(raw)
	if err != nil {
		t.Fatal(err)
	}
	p := s.plans[s.refs[0].Plan]
	parent := p.decoded.Entries[0]
	child := parent
	child.Address = common.HexToAddress("0x3333333333333333333333333333333333333333")
	child.Creator = parent.Address
	child.Caller = parent.Address
	child.Record = 90
	child.Depth = 3
	child.CreationParent = 0
	p.decoded.Entries = append(p.decoded.Entries, child)
	s.plans[s.refs[0].Plan] = p
	actual := func(e nativeadmission.CreationEntry, record, parent int, survives bool) rpcexecution.IncludedCreationRecord {
		return rpcexecution.IncludedCreationRecord{Record: record, Parent: parent, Depth: e.Depth, Kind: e.Kind, Address: e.Address, Creator: e.Creator, Caller: e.Caller, AddressKnown: true, CallerKnown: true, InputHash: e.InputHash, Value: e.Value, OutputHash: crypto.Keccak256Hash([]byte{0x60, 0}), OutputLength: 2, Survives: survives}
	}
	base := []rpcexecution.IncludedCreationRecord{actual(parent, 4, -1, false), actual(child, 12, 4, true)}
	proof := common.HexToHash("0x999")
	qualify := func(t *testing.T, w *WorkSnapshot, records []rpcexecution.IncludedCreationRecord, want int) {
		t.Helper()
		d, err := matchCreations(w, records, proof, w.before.State.Head, 0)
		if err != nil || len(d.Associations) != want {
			t.Fatal("association count", len(d.Associations), err)
		}
		if want > 0 && (d.Associations[0].Record != 12 || d.Associations[0].FactoryRoot != 0 || d.Associations[0].WalletActor != "") {
			t.Fatal("preflight ordinal or actor became factory authority", d)
		}
	}
	qualify(t, s, base, 1) // successful empty parent need not itself be an ordinary birth
	for _, name := range []string{"unplanned creation ancestor", "different caller", "different value", "failed ancestor", "uncovered", "revoked", "orphan anchor", "anchor at inclusion", "ambiguous tuple", "missing factory root"} {
		t.Run(name, func(t *testing.T) {
			w := *s
			w.refs = append([]StoredReference{}, s.refs...)
			w.plans = map[a.Digest]workPlan{}
			for k, v := range s.plans {
				w.plans[k] = v
			}
			records := append([]rpcexecution.IncludedCreationRecord{}, base...)
			switch name {
			case "unplanned creation ancestor":
				extra := records[0]
				extra.Record = 8
				extra.Parent = 4
				extra.Address = common.HexToAddress("0x44")
				extra.Depth = 2
				records = []rpcexecution.IncludedCreationRecord{records[0], extra, records[1]}
				records[2].Parent = 8
			case "different caller":
				records[1].Caller = common.HexToAddress("0x55")
			case "different value":
				records[1].Value = "0x1"
			case "failed ancestor":
				records[0].AncestorFailed = true
				records[1].AncestorFailed = true
				records[1].Survives = false
			case "uncovered":
				w.refs[0].Coverage = nil
			case "revoked":
				w.refs[0].Revoked = true
			case "orphan anchor":
				w.refs[0].AnchorCanonical = false
			case "anchor at inclusion":
				w.refs[0].Anchor = w.before.State.Head
			case "ambiguous tuple":
				dupe := records[1]
				dupe.Record = 13
				records = append(records, dupe)
			case "missing factory root":
				records = records[1:]
				records[0].Parent = -1
			}
			qualify(t, &w, records, 0)
		})
	}
}
