package protectedsource

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/google/uuid"
	c "privacy-proxy/internal/creationfacts"
	d "privacy-proxy/internal/disclosuredata"
	p "privacy-proxy/internal/disclosurepolicy"
	f "privacy-proxy/internal/disclosuretest"
	x "privacy-proxy/internal/explorerquery"
	h "privacy-proxy/internal/historynamespace"
)

func TestActualSharedTransactionPagesOne25And100AcrossBlockShapes(t *testing.T) {
	for _, shape := range []struct {
		name             string
		blocks, perBlock int
	}{
		{"distinct", 105, 1}, {"same", 1, 100},
	} {
		t.Run(shape.name, func(t *testing.T) {
			node := ownedFunctionalNodeShape(t, shape.blocks, shape.perBlock)
			config := actualFunctionalConfig(t, node)
			source, err := New(t.Context(), config)
			if err != nil {
				t.Fatal(err)
			}
			base := p.Scope{TargetActors: []string{f.Actor(f.Subject)}, Resources: []p.Resource{p.Transactions}, Addresses: p.Addresses{Mode: "all-target-addresses", Values: []string{}}, DataTime: p.Interval{Start: f.Now - 200, End: f.Now + 10}, Level: p.Full}
			for _, limit := range []uint16{1, 25, 100} {
				t.Run(fmt.Sprint(limit), func(t *testing.T) {
					query, err := d.NormalizeRetained(d.Query{Version: 1, Resource: p.Transactions, View: d.List, Limit: &limit}, base)
					if err != nil {
						t.Fatal(err)
					}
					scope := d.ReadScope{Namespace: digestParts("shared-paging"), CaseID: uuid.NewString(), CaseVersion: 1, RecipientActorID: f.Actor(f.AdminSubject), DataOrganizationID: f.Org, BundleDigest: source.Plan().BundleDigest, RuleDigest: digestParts("shared-paging-rule"), EffectiveUntil: config.Clock().Add(time.Minute), Query: query}
					seen := map[[32]byte]bool{}
					var after *d.Position
					var basis *d.RetainedBasis
					var refs []d.SourceRef
					// Limit1 is an admission-size control;25/100 traverse the
					// full original cut to verify continuation without gaps.
					for page := 0; page < 6; page++ {
						before := node.attempts()
						read, err := source.OpenRetained(t.Context(), scope, refs, basis, after)
						if err != nil {
							t.Fatal("open", page, err)
						}
						facts, err := read.Read(t.Context(), scope, after)
						if err != nil {
							read.Close()
							t.Fatal(err)
						}
						want := min(int(limit), len(node.transactions)-len(seen))
						if len(facts.Transactions) != want {
							read.Close()
							t.Fatal("unexpected short page", page, len(facts.Transactions), want)
						}
						for _, tx := range facts.Transactions {
							if seen[tx.Hash] {
								t.Fatal("duplicate transaction", page)
							}
							seen[tx.Hash] = true
						}
						end := len(seen) == len(node.transactions)
						if facts.End != end || (facts.Next == nil) != end {
							read.Close()
							t.Fatal("false end/lost continuation", page)
						}
						if !end {
							last := facts.Transactions[len(facts.Transactions)-1]
							if facts.Next.Transaction.Hash != last.Hash || facts.Next.Transaction.BlockNumber != last.BlockNumber || facts.Next.Transaction.TransactionIndex != last.TransactionIndex {
								t.Fatal("cursor advanced beyond last returned root")
							}
						}
						for check := 0; check < 2; check++ {
							if err = read.CheckCurrent(t.Context()); err != nil {
								read.Close()
								t.Fatal("final source check", page, check, err)
							}
						}
						actual := read.(*snapshot)
						used := node.attempts() - before
						if used != int64(actual.node.wire.attempts) || used > int64(7*len(actual.node.touched)+35) || len(actual.node.touched) > 128 || actual.node.bodySets > 3 || actual.node.headerSets > 2 {
							t.Fatal("attempt ledger", used, actual.node.wire.attempts, len(actual.node.touched))
						}
						if basis == nil {
							b := read.Basis()
							basis = &b
							refs, err = d.SourceReferencesRetained(source.Plan(), read.Descriptors())
							if err != nil {
								t.Fatal(err)
							}
						} else if !read.Basis().Equal(*basis) {
							t.Fatal("continuation changed original cut")
						}
						read.Close()
						t.Logf("rows=%d page=%d physical=%d", len(facts.Transactions), page+1, used)
						if end || limit == 1 {
							break
						}
						after = d.ClonePosition(facts.Next)
					}
					if limit > 1 && len(seen) != len(node.transactions) {
						t.Fatal("incomplete traversal", len(seen))
					}
				})
			}
		})
	}
}

func TestNodeCapacityKeepsUnconsumedTransactionsReachable(t *testing.T) {
	fixture := ownedFunctionalNodeCount(t, 5)
	node, err := newNodeRead(fixture.config)
	if err != nil {
		t.Fatal(err)
	}
	if err = node.bind(time.Now().Add(5*time.Second), t.Context().Done()); err != nil {
		t.Fatal(err)
	}
	// Simulate credits already committed by earlier support work. These private
	// ledger values are deliberately not claimed as actual fixture dispatches.
	spent := make([]uint64, 125)
	for i := range spent {
		spent[i] = 1000 + uint64(i)
	}
	if err = node.touch(spent); err != nil {
		t.Fatal(err)
	}
	rows := make([]x.ProtectedRow, len(fixture.transactions))
	for i, tx := range fixture.transactions {
		header := fixture.blocks[i]
		to := [20]byte(*tx.To())
		rows[i] = x.ProtectedRow{Position: x.ProtectedPosition{Number: header.Number.Uint64(), Hash: [32]byte(tx.Hash())}, Timestamp: header.Time, From: [20]byte(crypto.PubkeyToAddress(fixture.signer.PublicKey)), To: &to}
	}
	qualified, err := node.qualify(t.Context(), rows, false)
	if err != nil || len(qualified) != 3 || len(node.touched) != 128 || fixture.attempts() != 18 {
		t.Fatal("expected ordered capacity prefix", len(qualified), len(node.touched), fixture.attempts(), err)
	}
	end, next, err := transactionPageBoundary(rows, len(qualified), true)
	if err != nil || end || next == nil || next.Transaction.Hash != rows[2].Position.Hash || next.Transaction.BlockNumber != "3" {
		t.Fatal("producer end hid unconsumed suffix", end, next, err)
	}
	if _, _, err = transactionPageBoundary(rows, 0, true); !errors.Is(err, d.ErrTooBroad) {
		t.Fatal("zero progress became successful empty result", err)
	}
	if end, next, err = transactionPageBoundary(nil, 0, true); err != nil || !end || next != nil {
		t.Fatal("actual exhausted empty feed rejected", err)
	}
	before := fixture.attempts()
	if err = node.acquireSet(t.Context(), []uint64{1, 2, 3}, nodeReserve{}, false); err != nil || fixture.attempts() != before {
		t.Fatal("cached complete bodies were reacquired", err)
	}
}

func TestActualMixedNamespaceSupportReservesBeforeIO(t *testing.T) {
	node := ownedFunctionalNodeCount(t, 3)
	config := actualFunctionalConfig(t, node)
	reader := config.Namespace
	meta, err := reader.Metadata(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	fresh, err := newNodeRead(node.config)
	if err != nil {
		t.Fatal(err)
	}
	if err = fresh.bind(time.Now().Add(5*time.Second), t.Context().Done()); err != nil {
		t.Fatal(err)
	}
	upper := canonicalHeader(c.Header{Number: node.head.Number.Uint64(), Hash: node.head.Hash(), Parent: node.head.ParentHash, Timestamp: node.head.Time})
	address := h.Address(*node.tx.To())
	input := h.TrustedRangeScope{Network: meta.Network, Era: meta.Era, CanonicalViewID: viewDigest(fresh, upper), Head: upper, FromNumber: 1, ThroughNumber: 2, Addresses: []h.Address{address}}
	requirements, err := reader.DiscoverRangeRequirements(t.Context(), input)
	if err != nil {
		t.Fatal(err)
	}
	bodies, headers, err := fresh.supportNeeds(requirements)
	if err != nil || len(bodies) == 0 || len(headers) == 0 {
		t.Fatal("fixture must require both full population and header-only support", bodies, headers, err)
	}
	reserve := headerReserve(len(headers))
	for _, kind := range []string{"wire", "owned", "calls"} {
		t.Run(kind, func(t *testing.T) {
			fresh.wire.remaining, fresh.wire.attempts, fresh.owned = maxNodeWire, 0, finalNodeOwned
			switch kind {
			case "wire":
				post := int64((len(bodies)+1)*(16<<10) + 2*(4<<10))
				fresh.wire.remaining = finalNodeWire + 2*post + 2049 + reserve.wire/2
			case "owned":
				fresh.owned = maxNodeOwned - len(bodies)*(1024+512+128) - reserve.owned/2
			case "calls":
				fresh.wire.attempts = maxNodeAttempts - finalNodeCalls - (4*len(bodies) + 6) - reserve.calls/2
			}
			if !fresh.canBodySet(bodies, nodeReserve{}) || fresh.canSupport(requirements) {
				t.Fatal("mixed support was not planned jointly", kind)
			}
			before := node.attempts()
			if _, err = fresh.supports(t.Context(), requirements); !errors.Is(err, d.ErrTooBroad) || node.attempts() != before || fresh.wire.exceeded || len(fresh.touched) != 0 {
				t.Fatal("avoidable late overflow", kind, err)
			}
		})
	}
	fresh.wire.remaining, fresh.wire.attempts, fresh.owned = maxNodeWire, 0, finalNodeOwned
	if _, err = fresh.supports(t.Context(), requirements); err != nil {
		t.Fatal("positive mixed support", err)
	}
	owned := finalNodeOwned + 128*len(fresh.canonical)
	for _, block := range fresh.blocks {
		owned += block.OwnedBytes()
	}
	if fresh.owned != owned {
		t.Fatal("cache did not keep exact decoder charge", fresh.owned, owned)
	}
	for _, number := range bodies {
		if fresh.canonical[number].TxCount == nil {
			t.Fatal("population count lost", strconv.FormatUint(number, 10))
		}
	}
	for check := 0; check < 2; check++ {
		if err = fresh.check(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
}
