package historynamespace

import (
	"context"
	"encoding/binary"
	"errors"
	"reflect"
	"slices"
	"testing"
	"time"
)

func rangeInput(s TrustedRootScope, from, through uint64) TrustedRangeScope {
	return TrustedRangeScope{Network: s.Network, Era: s.Era, CanonicalViewID: s.CanonicalViewID, Head: s.Head,
		FromNumber: from, ThroughNumber: through, Addresses: []Address{{8}}}
}

func resolveRangeFixture(ctx context.Context, input TrustedRangeScope, facts Snapshot, blocks []CanonicalBlock, limits RangeLimits) (*NamespaceRangePass, error) {
	s, err := PrepareRangeScope(input, limits)
	if err != nil {
		return nil, err
	}
	req, err := DiscoverRangeRequirements(ctx, s, facts, limits)
	if err != nil {
		return nil, err
	}
	// The range consumer receives only its actual required sparse headers.
	// Point equivalence below receives the remaining real fixture headers.
	needed := map[uint64]bool{}
	for _, b := range req.Blocks() {
		needed[b.Number] = true
	}
	var sparse []CanonicalBlock
	for _, b := range blocks {
		if needed[b.Number] {
			sparse = append(sparse, b)
		}
	}
	p, err := PrepareRangePass(TrustedRangePass{input, sparse, req.ScopeDigest(), req.Digest()}, limits)
	if err != nil {
		return nil, err
	}
	return ResolveRangePass(ctx, p, facts, limits)
}

func intervalAt(t *testing.T, p *NamespaceRangePass, address Address, pos Position) IntervalResolution {
	t.Helper()
	var found *IntervalResolution
	for _, cell := range p.Intervals() {
		if cell.Address == address && comparePositions(cell.From, pos) <= 0 && comparePositions(pos, cell.Before) < 0 {
			if found != nil {
				t.Fatal("overlapping result cells")
			}
			c := cell
			found = &c
		}
	}
	if found == nil {
		t.Fatalf("missing interval at %+v", pos)
	}
	return *found
}

func TestRangeMatchesExistingPointClassificationAtActualPositions(t *testing.T) {
	for _, name := range []string{"finite", "transfer", "checkpoint", "automatic", "conflict", "revoked", "pre-era"} {
		t.Run(name, func(t *testing.T) {
			s, facts, blocks := readFixture(t)
			if name == "automatic" || name == "conflict" {
				s, facts, blocks = automaticReadFixture(t)
			}
			switch name {
			case "transfer":
				addReadTransfer(t, &facts, facts.Lifetimes[0].Lifetime.Segment, Cut{120, Hash{5}, 1})
			case "checkpoint":
				facts.Lifetimes = []LifetimeFact{checkpointFact(t, facts.Network, facts.Era, Hash{9}, 120, Hash{5})}
			case "automatic":
				facts.Lifetimes = nil
			case "revoked":
				facts.Lifetimes[0].Revoked = true
			case "pre-era":
				v := finiteInput()
				v["kind"], v["lifetimeId"], v["start"], v["end"] = "pre-era-finite", testOrg, Cut{90, Hash{3}, 0}, Cut{100, Hash{1}, 0}
				delete(v, "physical")
				a, err := ParseArtifact(artifactBytes(t, v))
				if err != nil {
					t.Fatal(err)
				}
				c, err := a.Compile(nil)
				if err != nil {
					t.Fatal(err)
				}
				lives, ids := c.Lifetimes()
				facts.Lifetimes = append(facts.Lifetimes, LifetimeFact{ID: ids[0], CohortID: testOrg, CohortDigest: c.Digest(), Lifetime: lives[0]})
			}
			count := uint32(3)
			for _, n := range []uint64{90, 110, 130, 140} {
				exists := false
				for _, b := range blocks {
					exists = exists || b.Number == n
				}
				if !exists {
					h := Hash{byte(n)}
					if n == 90 {
						h = Hash{3}
					}
					blocks = append(blocks, CanonicalBlock{Number: n, Hash: h, Timestamp: n * 10, TxCount: &count})
				}
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
			input := rangeInput(s, 90, 150)
			if name == "transfer" {
				// An active retained edge beyond finite support makes the WHOLE
				// pass unavailable, exactly as point C2. Never omit that cell.
				if out, err := resolveRangeFixture(t.Context(), input, facts, blocks, DefaultRangeLimits()); !errors.Is(err, ErrUnavailable) || out != nil {
					t.Fatal("past-support barrier disappeared", err)
				}
				input.ThroughNumber = 140
			}
			got, err := resolveRangeFixture(t.Context(), input, facts, blocks, DefaultRangeLimits())
			if err != nil {
				t.Fatal(err)
			}
			for _, b := range blocks {
				if b.Number < 90 || b.Number > input.ThroughNumber || b.TxCount == nil {
					continue
				}
				for index := uint32(0); index < *b.TxCount; index++ {
					point := s
					address := Address{8}
					point.Roots = []Root{{Hash: Hash{20}, BlockHash: b.Hash, Number: b.Number, Index: index, Timestamp: b.Timestamp, To: &address}}
					want, err := readResolveUnchecked(point, facts, blocks)
					if err != nil {
						t.Fatalf("point at%d/%d: %v", b.Number, index, err)
					}
					w := want.Results()[0]
					cell := intervalAt(t, got, address, Position{b.Number, index})
					if cell.Kind != w.Kind || !reflect.DeepEqual(cell.OrganizationID, w.OrganizationID) || !reflect.DeepEqual(cell.BasisDigests, w.BasisDigests) || !reflect.DeepEqual(cell.TransferDigests, w.TransferDigests) {
						t.Fatalf("point/range drift at%d/%d: %+v %+v", b.Number, index, w, cell)
					}
				}
			}
			// Detached output cannot mutate a later result or its authority digest.
			before := got.AuthorityDigest()
			cells := got.Intervals()
			cells[0].Address = Address{99}
			if cells[0].OrganizationID != nil {
				*cells[0].OrganizationID = "mutated"
			}
			if got.Intervals()[0].Address != (Address{8}) || got.AuthorityDigest() != before {
				t.Fatal("result aliases exported data")
			}
		})
	}
}

func TestRangeCreationIsSeparateExactRecordZero(t *testing.T) {
	s, facts, blocks := automaticReadFixture(t)
	facts.Lifetimes = nil
	input := rangeInput(s, 100, 150)
	got, err := resolveRangeFixture(t.Context(), input, facts, blocks, DefaultRangeLimits())
	if err != nil {
		t.Fatal(err)
	}
	points := got.CreationCoordinates()
	if len(points) != 1 || points[0].Root.Hash != (Hash{88}) || points[0].Root.Number != 130 || points[0].Root.Index != 0 || points[0].Kind != KnownOrg {
		t.Fatalf("wrong creation coordinate: %+v", points)
	}
	if intervalAt(t, got, Address{8}, Position{130, 0}).Kind != Unknown || intervalAt(t, got, Address{8}, Position{130, 1}).Kind != KnownOrg {
		t.Fatal("ordinary call support backdated to creation ROOT")
	}
	point := s
	point.Roots = []Root{points[0].Root}
	want, err := readResolveUnchecked(point, facts, blocks)
	if err != nil || !reflect.DeepEqual(want.Results(), points) {
		t.Fatalf("creation point drift: %v", err)
	}
	facts.Automatic[0].Birth.Record = 1
	child, err := resolveRangeFixture(t.Context(), input, facts, blocks, DefaultRangeLimits())
	if err != nil || len(child.CreationCoordinates()) != 0 {
		t.Fatalf("child birth supplied root-creation predicate: %v", err)
	}
}

func TestRangeSourcePairingBoundsAndOriginalCancellation(t *testing.T) {
	s, facts, blocks := readFixture(t)
	input := rangeInput(s, 100, 120)
	limits := DefaultRangeLimits()
	prepared, err := PrepareRangeScope(input, limits)
	if err != nil {
		t.Fatal(err)
	}
	input.Addresses[0] = Address{99}
	if prepared.Addresses()[0] != (Address{8}) {
		t.Fatal("scope aliases caller")
	}
	input = prepared.Data()
	req, err := DiscoverRangeRequirements(t.Context(), prepared, facts, limits)
	if err != nil {
		t.Fatal(err)
	}
	p, err := PrepareRangePass(TrustedRangePass{input, blocks, req.ScopeDigest(), req.Digest()}, limits)
	if err != nil {
		t.Fatal(err)
	}
	changed := facts
	changed.NamespaceRevision++
	if out, err := ResolveRangePass(t.Context(), p, changed, limits); !errors.Is(err, ErrUnavailable) || out != nil {
		t.Fatal("changed source borrowed prior requirements", err)
	}
	pointReq := readRequirements(t, s, facts)
	if _, err := PrepareRangePass(TrustedRangePass{input, blocks, pointReq.ScopeDigest(), pointReq.Digest()}, limits); !errors.Is(err, ErrUnavailable) {
		t.Fatal("point digest borrowed for range", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if out, err := ResolveRangePass(ctx, p, facts, limits); err == nil || out != nil {
		t.Fatal("canceled parent supplied positive range")
	}
	limits.MaxIntervals = 1
	if _, err := resolveRangeFixture(t.Context(), input, facts, blocks, limits); err != nil {
		t.Fatal("single-cell limit positive", err)
	}
	input.Addresses = append(input.Addresses, Address{9})
	if out, err := resolveRangeFixture(t.Context(), input, facts, blocks, limits); !errors.Is(err, ErrTooBroad) || out != nil {
		t.Fatal("result limit restarted for next address", err)
	}
	input.Addresses = []Address{{8}}
	limits = DefaultRangeLimits()
	limits.Read.MaxOutputBytes = 1
	if out, err := resolveRangeFixture(t.Context(), input, facts, blocks, limits); !errors.Is(err, ErrTooBroad) || out != nil {
		t.Fatal("output budget ignored", err)
	}
	input.Head.Timestamp = input.Era.EndTimestampExclusive
	if _, err := PrepareRangeScope(input, DefaultRangeLimits()); !errors.Is(err, ErrInvalid) {
		t.Fatal("next unsupported era extrapolated", err)
	}
}

func TestRangeRetainedBarrierFailureDoesNotReleaseEarlierPositive(t *testing.T) {
	s, facts, blocks := readFixture(t)
	original := facts.Lifetimes[0]
	facts.Lifetimes[0].Revoked = true
	facts.Lifetimes = append(facts.Lifetimes, checkpointFact(t, facts.Network, facts.Era, Hash{10}, 105, Hash{10}))
	addReadTransfer(t, &facts, original.Lifetime.Segment, Cut{110, Hash{11}, 0})
	count := uint32(3)
	blocks = append(blocks, CanonicalBlock{Number: 105, Hash: Hash{10}, Timestamp: 1050, TxCount: &count}, CanonicalBlock{Number: 110, Hash: Hash{11}, Timestamp: 1100, TxCount: &count})
	slices.SortFunc(blocks, func(a, b CanonicalBlock) int {
		if a.Number < b.Number {
			return -1
		}
		if a.Number > b.Number {
			return 1
		}
		return 0
	})
	input := rangeInput(s, 100, 150)
	if out, err := resolveRangeFixture(t.Context(), input, facts, blocks, DefaultRangeLimits()); !errors.Is(err, ErrUnavailable) || out != nil {
		t.Fatal("retained missing support turned into positive/partial range", err)
	}
}

func TestRangeAddressCeilingAndOwnedTimeout(t *testing.T) {
	s, facts, blocks := readFixture(t)
	facts.Lifetimes = nil
	input := rangeInput(s, 100, 120)
	input.Addresses = make([]Address, 4096)
	for i := range input.Addresses {
		binary.BigEndian.PutUint32(input.Addresses[i][16:], uint32(i))
	}
	result, err := resolveRangeFixture(t.Context(), input, facts, blocks, DefaultRangeLimits())
	if err != nil || len(result.Intervals()) != 4096 {
		t.Fatalf("maximum simple address shape: %v", err)
	}
	input.Addresses = append(input.Addresses, Address{})
	binary.BigEndian.PutUint32(input.Addresses[4096][16:], 4096)
	if result, err := resolveRangeFixture(t.Context(), input, facts, blocks, DefaultRangeLimits()); !errors.Is(err, ErrTooBroad) || result != nil {
		t.Fatal("4097th address accepted", err)
	}
	input.Addresses = []Address{{8}}
	limits := DefaultRangeLimits()
	limits.Read.Timeout = time.Nanosecond
	if result, err := resolveRangeFixture(context.Background(), input, facts, blocks, limits); err == nil || result != nil {
		t.Fatal("pure entry assumed Background already had a timeout")
	}
}

func TestRangeCanonicalRequirementsAndDeterministicWitnesses(t *testing.T) {
	s, facts, blocks := readFixture(t)
	facts.Lifetimes = append(facts.Lifetimes, checkpointFact(t, facts.Network, facts.Era, Hash{9}, 120, Hash{5}))
	input := rangeInput(s, 100, 120)
	first, err := resolveRangeFixture(t.Context(), input, facts, blocks, DefaultRangeLimits())
	if err != nil {
		t.Fatal(err)
	}
	slices.Reverse(facts.Lifetimes)
	second, err := resolveRangeFixture(t.Context(), input, facts, blocks, DefaultRangeLimits())
	if err != nil || first.AuthorityDigest() != second.AuthorityDigest() || !reflect.DeepEqual(first.Intervals(), second.Intervals()) {
		t.Fatal("candidate input order changed witness identity", err)
	}
	withoutCount := slices.Clone(blocks)
	withoutCount[2].TxCount = nil // actual finite end requires a count even outside the requested range
	if out, err := resolveRangeFixture(t.Context(), input, facts, withoutCount, DefaultRangeLimits()); !errors.Is(err, ErrUnavailable) || out != nil {
		t.Fatal("missing factual count became positive range", err)
	}
	wrongHead := slices.Clone(blocks)
	wrongHead[len(wrongHead)-1].Hash = Hash{99}
	if out, err := resolveRangeFixture(t.Context(), input, facts, wrongHead, DefaultRangeLimits()); !errors.Is(err, ErrUnavailable) || out != nil {
		t.Fatal("foreign canonical head accepted", err)
	}
	foreign := facts
	foreign.Network = Digest{99}
	if out, err := resolveRangeFixture(t.Context(), input, foreign, blocks, DefaultRangeLimits()); !errors.Is(err, ErrUnavailable) || out != nil {
		t.Fatal("foreign namespace source accepted", err)
	}
}
