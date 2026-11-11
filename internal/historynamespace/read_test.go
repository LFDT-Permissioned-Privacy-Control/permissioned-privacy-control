package historynamespace

import (
	"context"
	"encoding/binary"
	"errors"
	"slices"
	"testing"
)

func readFixture(t *testing.T) (TrustedRootScope, Snapshot, []CanonicalBlock) {
	t.Helper()
	artifact, err := ParseArtifact(artifactBytes(t, finiteInput()))
	if err != nil {
		t.Fatal(err)
	}
	compiled, err := artifact.Compile(nil)
	if err != nil {
		t.Fatal(err)
	}
	lives, ids := compiled.Lifetimes()
	address := Address{8}
	scope := TrustedRootScope{Network: artifact.NetworkKey(), Era: testEra(), CanonicalViewID: Digest{4}, Head: CanonicalBlock{Number: 200, Hash: Hash{6}, Timestamp: 1900}, Roots: []Root{{Hash: Hash{20}, BlockHash: Hash{5}, Number: 120, Index: 0, Timestamp: 1200, To: &address}}}
	snapshot := Snapshot{Network: scope.Network, Era: scope.Era, Generation: testOrg, NamespaceRevision: 1, Completeness: Digest{7}, AdmissionCoverage: Digest{8}, Ready: true, Lifetimes: []LifetimeFact{{ID: ids[0], CohortID: testOrg, CohortDigest: compiled.Digest(), Lifetime: lives[0]}}}
	count := uint32(3)
	blocks := []CanonicalBlock{{Number: 100, Hash: Hash{1}, Timestamp: 1000, TxCount: &count}, {Number: 120, Hash: Hash{5}, Timestamp: 1200, TxCount: &count}, {Number: 150, Hash: Hash{2}, Timestamp: 1500, TxCount: &count}, scope.Head}
	return scope, snapshot, blocks
}
func readRequirements(t *testing.T, scope TrustedRootScope, facts Snapshot) *Requirements {
	t.Helper()
	s, err := PrepareRootScope(scope, DefaultReadLimits())
	if err != nil {
		t.Fatal(err)
	}
	r, err := DiscoverRequirements(t.Context(), s, facts, DefaultReadLimits())
	if err != nil {
		t.Fatal(err)
	}
	return r
}
func readResolve(t *testing.T, scope TrustedRootScope, facts Snapshot, blocks []CanonicalBlock) (*NamespacePass, error) {
	t.Helper()
	requirements := readRequirements(t, scope, facts)
	p, err := PrepareRootPass(TrustedRootPass{Scope: scope, CanonicalBlocks: blocks, ExpectedScopeDigest: requirements.ScopeDigest(), ExpectedRequirementsDigest: requirements.Digest()}, DefaultReadLimits())
	if err != nil {
		return nil, err
	}
	return ResolvePass(t.Context(), p, facts, DefaultReadLimits())
}
func requireKnown(t *testing.T, p *NamespacePass, err error, kind ResolutionKind) {
	t.Helper()
	if err != nil || p == nil || len(p.Results()) != 1 || p.Results()[0].Kind != kind {
		t.Fatal("unexpected namespace result", p, err, kind)
	}
}
func addReadTransfer(t *testing.T, facts *Snapshot, segment Digest, at Cut) {
	t.Helper()
	org := testOrg
	tr := Transfer{Kind: "transfer", Address: Address{8}, SegmentKind: "prague", Segment: segment, Initial: Label{Kind: "org", OrganizationID: &org}, Previous: Label{Kind: "org", OrganizationID: &org}, New: Label{Kind: "public"}, EffectiveFrom: at}
	id, err := TransferDigest(facts.Network, facts.Era, tr)
	if err != nil {
		t.Fatal(err)
	}
	facts.Transfers = append(facts.Transfers, TransferFact{ID: id, CohortID: testOrg, CohortDigest: Digest{90}, Transfer: tr})
}

func TestRootDiscoveryAndPassCopyPairingAndStableIdentity(t *testing.T) {
	scope, facts, blocks := readFixture(t)
	prepared, err := PrepareRootScope(scope, DefaultReadLimits())
	if err != nil {
		t.Fatal(err)
	}
	scope.Roots[0].To[0] = 99
	if prepared.Data().Roots[0].To[0] != 8 {
		t.Fatal("scope aliases caller")
	}
	scope = prepared.Data()
	requirements, err := DiscoverRequirements(t.Context(), prepared, facts, DefaultReadLimits())
	if err != nil {
		t.Fatal(err)
	}
	copy := requirements.Blocks()
	copy[0].ClaimedHashes[0] = Hash{}
	if requirements.Blocks()[0].ClaimedHashes[0] == (Hash{}) {
		t.Fatal("requirements getter aliases")
	}
	pass, err := PrepareRootPass(TrustedRootPass{scope, blocks, requirements.ScopeDigest(), requirements.Digest()}, DefaultReadLimits())
	if err != nil {
		t.Fatal(err)
	}
	*blocks[0].TxCount = 0
	result, err := ResolvePass(t.Context(), pass, facts, DefaultReadLimits())
	requireKnown(t, result, err, KnownOrg)
	values := result.Results()
	values[0].Root.To[0] = 99
	*values[0].OrganizationID = "changed"
	values[0].BasisDigests[0] = Digest{}
	if *result.Results()[0].OrganizationID != testOrg || result.Results()[0].Root.To[0] != 8 || result.Results()[0].BasisDigests[0] == (Digest{}) {
		t.Fatal("pass getter aliases")
	}
	changed := facts
	changed.Lifetimes = slices.Clone(facts.Lifetimes)
	changed.Lifetimes[0].Revoked = true
	if _, err := ResolvePass(t.Context(), pass, changed, DefaultReadLimits()); !errors.Is(err, ErrUnavailable) {
		t.Fatal("discovery change accepted", err)
	}
}

func TestCanonicalContextCountsAndFiniteModelIntersection(t *testing.T) {
	scope, facts, blocks := readFixture(t)
	// The exact canonical End beyond model end remains boundary metadata;
	// support applies only at each in-model ROOT or edge.
	blocks[2].Timestamp = 2500
	blocks[3].Timestamp = 3000
	scope.Head.Timestamp = 3000
	p, err := readResolve(t, scope, facts, blocks)
	requireKnown(t, p, err, KnownOrg)
	for _, name := range []string{"missing end", "wrong end", "missing root count", "root outside model"} {
		t.Run(name, func(t *testing.T) {
			s := scope
			s.Roots = slices.Clone(scope.Roots)
			bs := slices.Clone(blocks)
			switch name {
			case "missing end":
				bs = append(bs[:2], bs[3:]...)
			case "wrong end":
				bs[2].Hash = Hash{99}
			case "missing root count":
				bs[1].TxCount = nil
			case "root outside model":
				s.Roots[0].Timestamp = 2000
				bs[1].Timestamp = 2000
			}
			result, err := readResolve(t, s, facts, bs)
			if err == nil && (result == nil || result.Results()[0].Kind != Unknown) {
				t.Fatal("unqualified/outside-model source granted", result, err)
			}
		})
	}
	org := testOrg
	transfer := Transfer{Kind: "transfer", Address: Address{8}, SegmentKind: "prague", Segment: facts.Lifetimes[0].Lifetime.Segment, Initial: Label{Kind: "org", OrganizationID: &org}, Previous: Label{Kind: "org", OrganizationID: &org}, New: Label{Kind: "public"}, EffectiveFrom: Cut{150, Hash{2}, 0}}
	id, _ := TransferDigest(facts.Network, facts.Era, transfer)
	facts.Transfers = []TransferFact{{ID: id, CohortID: testOrg, CohortDigest: Digest{90}, Transfer: transfer}}
	// A post-era edge never supplies a namespace transfer to an earlier ROOT.
	p, err = readResolve(t, scope, facts, blocks)
	requireKnown(t, p, err, KnownOrg)
}

func checkpointFact(t *testing.T, network Digest, era ModelEra, runtime Hash, k uint64, hash Hash) LifetimeFact {
	t.Helper()
	org := testOrg
	proof := Digest{80}
	physical := &PhysicalStart{Kind: "preexisting"}
	l := Lifetime{Kind: "prague-checkpoint", Address: Address{8}, RuntimeHash: runtime, RuntimeLength: 1, Initial: Label{Kind: "org", OrganizationID: &org}, Physical: physical, Checkpoint: &CheckpointRef{k, hash}, ProofDigest: &proof}
	l.Segment, _ = PragueSegmentKey(network, l.Address, runtime, 1)
	id, err := LifetimeDigest(network, era, l)
	if err != nil {
		t.Fatal(err)
	}
	return LifetimeFact{ID: id, CohortID: testOrg, CohortDigest: Digest{81}, Lifetime: l}
}

func TestTransferCannotResurrectInitialOrForgetCrossKeyBarrier(t *testing.T) {
	scope, facts, blocks := readFixture(t)
	original := facts.Lifetimes[0]
	facts.Lifetimes[0].Revoked = true
	checkpoint := checkpointFact(t, facts.Network, facts.Era, Hash{10}, 105, Hash{10})
	facts.Lifetimes = append(facts.Lifetimes, checkpoint)
	addReadTransfer(t, &facts, original.Lifetime.Segment, Cut{110, Hash{11}, 0})
	count := uint32(3)
	blocks = append(blocks, CanonicalBlock{Number: 105, Hash: Hash{10}, Timestamp: 1050, TxCount: &count}, CanonicalBlock{Number: 110, Hash: Hash{11}, Timestamp: 1100, TxCount: &count}, CanonicalBlock{Number: 108, Hash: Hash{12}, Timestamp: 1080, TxCount: &count})
	slices.SortFunc(blocks, func(a, b CanonicalBlock) int {
		if a.Number < b.Number {
			return -1
		}
		if a.Number > b.Number {
			return 1
		}
		return 0
	})
	before := scope
	before.Roots = slices.Clone(scope.Roots)
	before.Roots[0].Number = 108
	before.Roots[0].BlockHash = Hash{12}
	before.Roots[0].Timestamp = 1080
	p, err := readResolve(t, before, facts, blocks)
	requireKnown(t, p, err, KnownOrg)
	if _, err := readResolve(t, scope, facts, blocks); !errors.Is(err, ErrUnavailable) {
		t.Fatal("cross-key known barrier disappeared", err)
	}
	orphan := facts
	orphan.Transfers = slices.Clone(facts.Transfers)
	orphan.Transfers[0].Transfer.EffectiveFrom.Hash = Hash{99}
	orphan.Transfers[0].ID, _ = TransferDigest(orphan.Network, orphan.Era, orphan.Transfers[0].Transfer)
	p, err = readResolve(t, scope, orphan, blocks)
	requireKnown(t, p, err, KnownOrg)
	// Same-key later checkpoint cannot supply earlier edge support either.
	same := facts
	same.Lifetimes = slices.Clone(facts.Lifetimes)
	same.Lifetimes[1] = checkpointFact(t, facts.Network, facts.Era, original.Lifetime.RuntimeHash, 115, Hash{13})
	blocks = append(blocks, CanonicalBlock{Number: 115, Hash: Hash{13}, Timestamp: 1150, TxCount: &count})
	slices.SortFunc(blocks, func(a, b CanonicalBlock) int {
		if a.Number < b.Number {
			return -1
		}
		if a.Number > b.Number {
			return 1
		}
		return 0
	})
	if _, err := readResolve(t, scope, same, blocks); !errors.Is(err, ErrUnavailable) {
		t.Fatal("later checkpoint backdated edge support", err)
	}
	same.Lifetimes[0].Revoked = false
	p, err = readResolve(t, scope, same, blocks)
	requireKnown(t, p, err, KnownPublic)
}

func TestRootReadBoundsAndCancellation(t *testing.T) {
	scope, facts, _ := readFixture(t)
	limits := DefaultReadLimits()
	for _, bad := range []TrustedRootScope{
		{Network: scope.Network, Era: scope.Era, Head: scope.Head, Roots: scope.Roots},
		{Network: scope.Network, Era: scope.Era, Head: scope.Head, CanonicalViewID: scope.CanonicalViewID, Roots: append(slices.Clone(scope.Roots), scope.Roots[0])},
	} {
		if _, err := PrepareRootScope(bad, limits); err == nil {
			t.Fatal("invalid scope accepted")
		}
	}
	prepared, err := PrepareRootScope(scope, limits)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := DiscoverRequirements(ctx, prepared, facts, limits); !errors.Is(err, ErrUnavailable) {
		t.Fatal("canceled discovery", err)
	}
	for _, change := range []func(*ReadLimits){func(l *ReadLimits) { l.MaxBlocks = 1 }, func(l *ReadLimits) { l.MaxCandidateBytes = 1 }, func(l *ReadLimits) { l.MaxRequirementsBytes = 1 }, func(l *ReadLimits) { l.MaxWork = 1 }} {
		lower := limits
		change(&lower)
		if _, err := DiscoverRequirements(t.Context(), prepared, facts, lower); !errors.Is(err, ErrTooBroad) {
			t.Fatal("lower limit ignored", lower, err)
		}
	}
}

func automaticReadFixture(t *testing.T) (TrustedRootScope, Snapshot, []CanonicalBlock) {
	t.Helper()
	scope, facts, blocks := readFixture(t)
	count := uint32(3)
	facts.Observer = &ObserverTrust{Epoch: testOrg, Ready: true, Quarantine: "none", Floor: CanonicalBlock{Number: 90, Hash: Hash{90}, Timestamp: 900}, Head: scope.Head, SourceSet: Digest{33}, Reference: Digest{34}}
	facts.Automatic = []AutomaticFact{{Address: Address{8}, RuntimeHash: Hash{9}, RuntimeLength: 1, Namespace: testOrg,
		Birth:  BirthCoordinate{Number: 130, Hash: Hash{13}, TransactionHash: Hash{88}, Index: 0, Record: 0},
		Anchor: CanonicalBlock{Number: 110, Hash: Hash{11}, Timestamp: 1100},
		Seed:   Digest{40}, Coverage: Digest{41}, Qualification: Digest{42}, Proof: Hash{43}, Plan: Digest{44}, Manifest: Digest{45}, Runtime: Digest{46}, Branch: 1,
		OriginalProfile: "geth-prague-lifecycle-signed/v1", OriginalGeneration: facts.Generation, OriginalStateCoverage: facts.AdmissionCoverage, Kind: "FACTORY", StoredAnchorCanonical: true, StoredBirthCanonical: true}}
	blocks = append(blocks, facts.Observer.Floor, CanonicalBlock{Number: 110, Hash: Hash{11}, Timestamp: 1100, TxCount: &count}, CanonicalBlock{Number: 130, Hash: Hash{13}, Timestamp: 1300, TxCount: &count})
	slices.SortFunc(blocks, func(a, b CanonicalBlock) int {
		if a.Number < b.Number {
			return -1
		}
		if a.Number > b.Number {
			return 1
		}
		return 0
	})
	return scope, facts, blocks
}

func TestLaterAutomaticBirthConflictsWithoutBackdatingRuntime(t *testing.T) {
	scope, facts, blocks := automaticReadFixture(t)
	p, err := readResolve(t, scope, facts, blocks)
	requireKnown(t, p, err, Conflict)
	facts.Lifetimes = nil
	p, err = readResolve(t, scope, facts, blocks)
	requireKnown(t, p, err, Unknown)
	scope.Roots[0].Number = 130
	scope.Roots[0].BlockHash = Hash{13}
	scope.Roots[0].Timestamp = 1300
	p, err = readResolve(t, scope, facts, blocks)
	requireKnown(t, p, err, Unknown)
	scope.Roots[0].Index = 1
	p, err = readResolve(t, scope, facts, blocks)
	requireKnown(t, p, err, KnownOrg)
	facts.Automatic[0].Revoked = true
	p, err = readResolve(t, scope, facts, blocks)
	requireKnown(t, p, err, Unknown)
	facts.Automatic[0].Revoked = false
	facts.Observer.Ready = false
	if _, err := readResolveUnchecked(scope, facts, blocks); !errors.Is(err, ErrUnavailable) {
		t.Fatal("automatic source unready fell back", err)
	}
}

func readResolveUnchecked(scope TrustedRootScope, facts Snapshot, blocks []CanonicalBlock) (*NamespacePass, error) {
	s, err := PrepareRootScope(scope, DefaultReadLimits())
	if err != nil {
		return nil, err
	}
	req, err := DiscoverRequirements(context.Background(), s, facts, DefaultReadLimits())
	if err != nil {
		return nil, err
	}
	pass, err := PrepareRootPass(TrustedRootPass{scope, blocks, req.ScopeDigest(), req.Digest()}, DefaultReadLimits())
	if err != nil {
		return nil, err
	}
	return ResolvePass(context.Background(), pass, facts, DefaultReadLimits())
}

func TestExactRootCreationAndStableHistoricalTrust(t *testing.T) {
	scope, facts, blocks := automaticReadFixture(t)
	facts.Lifetimes = nil
	scope.Roots[0].Number = 130
	scope.Roots[0].BlockHash = Hash{13}
	scope.Roots[0].Timestamp = 1300
	scope.Roots[0].Index = 2
	scope.Roots[0].Hash = Hash{88}
	scope.Roots[0].CreatedAddress = scope.Roots[0].To
	scope.Roots[0].To = nil
	facts.Automatic[0].Birth.Index = 2
	// Equivalent checkpoint shares END-K/start with a last-tx birth. It
	// cannot hide the exact automatic root0 record during support coalescing.
	checkpoint := checkpointFact(t, facts.Network, facts.Era, Hash{9}, 130, Hash{13})
	birth := facts.Automatic[0].Birth
	checkpoint.Lifetime.Physical = &PhysicalStart{Kind: "born", Birth: &birth}
	checkpoint.ID, _ = LifetimeDigest(facts.Network, facts.Era, checkpoint.Lifetime)
	facts.Lifetimes = []LifetimeFact{checkpoint}
	p, err := readResolve(t, scope, facts, blocks)
	requireKnown(t, p, err, KnownOrg)
	scope.Roots[0].Hash = Hash{89}
	p, err = readResolve(t, scope, facts, blocks)
	requireKnown(t, p, err, Unknown)
	scope.Roots[0].Hash = Hash{88}
	req := readRequirements(t, scope, facts)
	// Durable prefix progress that changes no relevant fact is not a
	// historical-expiry or permission epoch. No lease/heartbeat is input.
	facts.Observer.Head = CanonicalBlock{Number: 250, Hash: Hash{50}, Timestamp: 2400}
	next := readRequirements(t, scope, facts)
	if req.Digest() != next.Digest() {
		t.Fatal("unrelated head progress invalidated historical truth")
	}
	facts.Observer.ReorgEpoch++
	if req.Digest() == readRequirements(t, scope, facts).Digest() {
		t.Fatal("reorg trust change omitted")
	}
}

func TestCheckpointEndAndEmptyBlockCuts(t *testing.T) {
	scope, facts, blocks := readFixture(t)
	facts.Lifetimes = []LifetimeFact{checkpointFact(t, facts.Network, facts.Era, Hash{9}, 120, Hash{5})}
	p, err := readResolve(t, scope, facts, blocks)
	requireKnown(t, p, err, Unknown)
	scope.Roots[0].Index = 2
	p, err = readResolve(t, scope, facts, blocks)
	requireKnown(t, p, err, Unknown)
	one, three, zero := uint32(1), uint32(3), uint32(0)
	blocks = append(blocks, CanonicalBlock{Number: 121, Hash: Hash{21}, ParentHash: Hash{5}, Timestamp: 1201, TxCount: &one})
	slices.SortFunc(blocks, func(a, b CanonicalBlock) int {
		if a.Number < b.Number {
			return -1
		}
		if a.Number > b.Number {
			return 1
		}
		return 0
	})
	scope.Roots[0].Number = 121
	scope.Roots[0].BlockHash = Hash{21}
	scope.Roots[0].Timestamp = 1201
	scope.Roots[0].Index = 0
	p, err = readResolve(t, scope, facts, blocks)
	requireKnown(t, p, err, KnownOrg)
	addReadTransfer(t, &facts, facts.Lifetimes[0].Lifetime.Segment, Cut{120, Hash{5}, three})
	p, err = readResolve(t, scope, facts, blocks)
	requireKnown(t, p, err, KnownPublic)
	facts.Transfers[0].Transfer.EffectiveFrom.Index = 2
	facts.Transfers[0].ID, _ = TransferDigest(facts.Network, facts.Era, facts.Transfers[0].Transfer)
	if _, err := readResolve(t, scope, facts, blocks); !errors.Is(err, ErrUnavailable) {
		t.Fatal("checkpoint lent earlier same-block cut", err)
	}
	facts.Transfers[0].Transfer.EffectiveFrom.Index = 0
	facts.Transfers[0].ID, _ = TransferDigest(facts.Network, facts.Era, facts.Transfers[0].Transfer)
	for i := range blocks {
		if blocks[i].Number == 120 {
			blocks[i].TxCount = &zero
		}
	}
	p, err = readResolve(t, scope, facts, blocks)
	requireKnown(t, p, err, KnownPublic)
	for i := range blocks {
		if blocks[i].Number == 121 {
			blocks[i].ParentHash = Hash{99}
		}
	}
	if _, err := readResolve(t, scope, facts, blocks); !errors.Is(err, ErrUnavailable) {
		t.Fatal("unlinked next start accepted", err)
	}
}

func TestTransferDivergenceAndParentChainAreOrderIndependent(t *testing.T) {
	scope, facts, blocks := readFixture(t)
	count := uint32(3)
	blocks = append(blocks, CanonicalBlock{Number: 110, Hash: Hash{11}, Timestamp: 1100, TxCount: &count}, CanonicalBlock{Number: 115, Hash: Hash{15}, Timestamp: 1150, TxCount: &count})
	slices.SortFunc(blocks, func(a, b CanonicalBlock) int {
		if a.Number < b.Number {
			return -1
		}
		if a.Number > b.Number {
			return 1
		}
		return 0
	})
	addReadTransfer(t, &facts, facts.Lifetimes[0].Lifetime.Segment, Cut{110, Hash{11}, 0})
	addReadTransfer(t, &facts, facts.Lifetimes[0].Lifetime.Segment, Cut{115, Hash{15}, 0})
	first, err := readResolve(t, scope, facts, blocks)
	requireKnown(t, first, err, Conflict)
	slices.Reverse(facts.Transfers)
	second, err := readResolve(t, scope, facts, blocks)
	requireKnown(t, second, err, Conflict)
	if first.AuthorityDigest() != second.AuthorityDigest() {
		t.Fatal("insertion order changed divergence")
	}
	parent := facts.Transfers[1]
	child := facts.Transfers[0]
	child.Transfer.Parent = &parent.ID
	child.Transfer.Previous = Label{Kind: "public"}
	organization := "12345678-1234-4234-8234-123456789abd"
	child.Transfer.New = Label{Kind: "org", OrganizationID: &organization}
	child.ID, _ = TransferDigest(facts.Network, facts.Era, child.Transfer)
	facts.Transfers[0] = child
	resolved, err := readResolve(t, scope, facts, blocks)
	requireKnown(t, resolved, err, KnownOrg)
	if *resolved.Results()[0].OrganizationID != organization || len(resolved.Results()[0].TransferDigests) != 2 {
		t.Fatal("qualified parent history lost")
	}
}

func preEraReadFact(t *testing.T, network Digest, id string, start, end Cut) LifetimeFact {
	t.Helper()
	organization := testOrg
	l := Lifetime{Kind: "pre-era-finite", Address: Address{8}, LifetimeID: &id, RuntimeHash: Hash{9}, RuntimeLength: 1, Initial: Label{Kind: "org", OrganizationID: &organization}, Start: &start, End: &end}
	l.Segment, _ = PreEraSegmentKey(network, l.Address, id)
	digest, err := LifetimeDigest(network, testEra(), l)
	if err != nil {
		t.Fatal(err)
	}
	return LifetimeFact{ID: digest, CohortID: testOrg, CohortDigest: Digest{80}, Lifetime: l}
}

func TestExplicitPreEraIdentityAndNoImplicitEraBridge(t *testing.T) {
	scope, facts, blocks := readFixture(t)
	count := uint32(3)
	id1 := "12345678-1234-4234-8234-123456789ab1"
	id2 := "12345678-1234-4234-8234-123456789ab2"
	first := preEraReadFact(t, facts.Network, id1, Cut{10, Hash{10}, 0}, Cut{90, Hash{90}, 0})
	facts.Lifetimes = []LifetimeFact{first}
	for _, n := range []byte{10, 20, 50, 70, 80, 90} {
		blocks = append(blocks, CanonicalBlock{Number: uint64(n), Hash: Hash{n}, Timestamp: uint64(n) * 10, TxCount: &count})
	}
	slices.SortFunc(blocks, func(a, b CanonicalBlock) int {
		if a.Number < b.Number {
			return -1
		}
		if a.Number > b.Number {
			return 1
		}
		return 0
	})
	scope.Roots[0].Number = 70
	scope.Roots[0].BlockHash = Hash{70}
	scope.Roots[0].Timestamp = 700
	p, err := readResolve(t, scope, facts, blocks)
	requireKnown(t, p, err, KnownOrg)
	facts.Lifetimes = append(facts.Lifetimes, preEraReadFact(t, facts.Network, id2, Cut{20, Hash{20}, 0}, Cut{80, Hash{80}, 0}))
	p, err = readResolve(t, scope, facts, blocks)
	requireKnown(t, p, err, Conflict)
	facts.Lifetimes[1] = preEraReadFact(t, facts.Network, id1, Cut{20, Hash{20}, 0}, Cut{80, Hash{80}, 0})
	p, err = readResolve(t, scope, facts, blocks)
	requireKnown(t, p, err, KnownOrg)
	scope.Roots[0].Number = 120
	scope.Roots[0].BlockHash = Hash{5}
	scope.Roots[0].Timestamp = 1200
	p, err = readResolve(t, scope, facts, blocks)
	requireKnown(t, p, err, Unknown)
	// A separate approved in-era assertion bridges the model entry; the
	// earlier UUID/transfer cannot automatically relabel that new initial.
	_, bridge, _ := readFixture(t)
	facts.Lifetimes = append(facts.Lifetimes, bridge.Lifetimes[0])
	organization := testOrg
	edge := Transfer{Kind: "transfer", Address: Address{8}, SegmentKind: "legacy", Segment: first.Lifetime.Segment, LegacyBasis: &first.ID, Initial: Label{Kind: "org", OrganizationID: &organization}, Previous: Label{Kind: "org", OrganizationID: &organization}, New: Label{Kind: "public"}, EffectiveFrom: Cut{50, Hash{50}, 0}}
	edgeID, _ := TransferDigest(facts.Network, facts.Era, edge)
	facts.Transfers = []TransferFact{{ID: edgeID, CohortID: testOrg, CohortDigest: Digest{80}, Revoked: true, Transfer: edge}}
	p, err = readResolve(t, scope, facts, blocks)
	requireKnown(t, p, err, KnownOrg)
}

func TestWholeScopeRootCeilingAndCanonicalContextPairing(t *testing.T) {
	scope, facts, blocks := readFixture(t)
	scope.Roots = make([]Root, 10000)
	address := Address{8}
	for i := range scope.Roots {
		hash := Hash{}
		binary.BigEndian.PutUint64(hash[24:], uint64(i+1))
		scope.Roots[i] = Root{Hash: hash, BlockHash: Hash{5}, Number: 120, Index: uint32(i), Timestamp: 1200, To: &address}
	}
	if _, err := PrepareRootScope(scope, DefaultReadLimits()); err != nil {
		t.Fatal("maximum scope shape", err)
	}
	scope.Roots = append(scope.Roots, Root{})
	if _, err := PrepareRootScope(scope, DefaultReadLimits()); !errors.Is(err, ErrTooBroad) {
		t.Fatal("root ceiling ignored", err)
	}
	scope, facts, blocks = readFixture(t)
	first, err := readResolve(t, scope, facts, blocks)
	requireKnown(t, first, err, KnownOrg)
	n := uint32(4)
	blocks[1].TxCount = &n
	second, err := readResolve(t, scope, facts, blocks)
	requireKnown(t, second, err, KnownOrg)
	if first.CanonicalContextDigest() == second.CanonicalContextDigest() || first.AuthorityDigest() == second.AuthorityDigest() {
		t.Fatal("actual canonical count context lost from pairing")
	}
}
