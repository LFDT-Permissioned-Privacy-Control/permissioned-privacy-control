package protectedsource

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/google/uuid"
	d "privacy-proxy/internal/disclosuredata"
	p "privacy-proxy/internal/disclosurepolicy"
	f "privacy-proxy/internal/disclosuretest"
)

// The producer is the real typed Indexer service over its actual migrations.
// Five independently signed transactions occupy five distinct canonical TLS
// fixture blocks, so the original physical node budget cannot hide behind
// multiple rows sharing one whole-block acquisition.
func TestActualRetainedTransactionPagingFitsSharedDeliveryBudget(t *testing.T) {
	node := ownedFunctionalNodeCount(t, 5)
	config := actualFunctionalConfig(t, node)
	source, err := New(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}
	plan := source.Plan()
	base := p.Scope{TargetActors: []string{f.Actor(f.Subject)}, Resources: []p.Resource{p.Transactions}, Addresses: p.Addresses{Mode: "all-target-addresses", Values: []string{}}, DataTime: p.Interval{Start: f.Now - 10, End: f.Now + 10}, Level: p.Full}
	query, err := d.Normalize(d.Query{Version: 1, Resource: p.Transactions, View: d.List}, base)
	if err != nil || query.Limit() != 50 {
		t.Fatal("the external default query must remain normalized to50", query.Limit(), err)
	}
	scope := d.ReadScope{Namespace: digestParts("paging-case"), CaseID: uuid.NewString(), CaseVersion: 1, RecipientActorID: f.Actor(f.AdminSubject), DataOrganizationID: f.Org, BundleDigest: plan.BundleDigest, RuleDigest: digestParts("paging-rule"), EffectiveUntil: time.Unix(f.Now+300, 0).UTC(), Query: query}

	walk := func(t *testing.T, scope d.ReadScope, sizes []int) string {
		t.Helper()
		// The real producer is commonly one block behind the selected node.
		// Start every first page at that boundary, retaining only producer5.
		node.advanceHead(true)
		var after *d.Position
		var original *d.RetainedBasis
		var refs []d.SourceRef
		seen := map[[32]byte]bool{}
		var hashes [][32]byte
		var locator string
		for page, want := range sizes {
			before := node.attempts()
			read, err := source.OpenRetained(t.Context(), scope, refs, original, after)
			if err != nil {
				t.Fatal("actual page open", page, err)
			}
			basis := read.Basis()
			if original == nil {
				if basis.Upper.Number != "5" || basis.Upper.Hash != node.head.Hash().Hex() || !basis.Valid() {
					t.Fatal("original complete retained basis", basis)
				}
				original = &basis
				refs, err = d.SourceReferencesRetained(plan, read.Descriptors())
				if err != nil {
					t.Fatal(err)
				}
			} else if !basis.Equal(*original) {
				t.Fatal("continuation changed original upper/epoch/floor/node binding", page, basis, original)
			}
			if scope.Query.Limit() != 50 {
				t.Fatal("internal page size rewrote the authenticated normalized query")
			}
			facts, err := read.Read(t.Context(), scope, after)
			if err != nil || len(facts.Transactions) != want {
				t.Fatal("actual bounded page", page, "want", want, "got", len(facts.Transactions), err)
			}
			terminal := page == len(sizes)-1
			if facts.End != terminal || terminal && facts.Next != nil || !terminal && facts.Next == nil {
				t.Fatal("incorrect real terminal/continuation state", page, facts.End, facts.Next)
			}
			for _, tx := range facts.Transactions {
				if seen[tx.Hash] {
					t.Fatal("transaction repeated across pages", page, tx.Hash)
				}
				seen[tx.Hash] = true
				hashes = append(hashes, tx.Hash)
			}
			if !terminal {
				last := facts.Transactions[len(facts.Transactions)-1]
				next := facts.Next.Transaction
				if facts.Next.Kind != d.HistorySource || next == nil || next.BlockNumber != last.BlockNumber || next.TransactionIndex != last.TransactionIndex || next.Hash != last.Hash {
					t.Fatal("continuation must be the exact last returned transaction", page, facts.Next, last)
				}
			}
			// The retained renderer must accept a short nonterminal page while
			// the original query/cursor contract still says limit50.
			render, err := d.RenderRetained(plan, scope, read.Descriptors(), facts, d.RenderContext{PreparedAt: config.Clock(), Namespace: scope.Namespace, CaseID: scope.CaseID, DataOrganizationID: scope.DataOrganizationID, RecipientActorID: scope.RecipientActorID, Keys: config.RenderKeys, Query: scope.Query, EffectiveUntil: scope.EffectiveUntil}, uuid.NewString())
			if err != nil || int(render.ReturnedRows()) != want {
				t.Fatal("real retained renderer rejected bounded page", page, err)
			}
			if locator == "" {
				raw, err := json.Marshal(render)
				if err != nil {
					t.Fatal(err)
				}
				var result struct {
					Result struct {
						Items []struct {
							AddressID string `json:"addressId"`
						} `json:"items"`
					} `json:"result"`
				}
				if err := json.Unmarshal(raw, &result); err != nil || len(result.Result.Items) == 0 || result.Result.Items[0].AddressID == "" {
					t.Fatal("actual Full row must carry its case-bound address locator", err)
				}
				locator = result.Result.Items[0].AddressID
			}
			// Preparation/sealing and actual delivery both recheck the same
			// owned snapshot. Neither gets a fresh node budget or query context.
			for check := 0; check < 2; check++ {
				if err := read.CheckCurrent(t.Context()); err != nil {
					t.Fatal("same snapshot final delivery recheck", page, check, err)
				}
			}
			read.Close()
			used := node.attempts() - before
			if used < 1 || used > maxNodeAttempts {
				t.Fatal("page exceeded shared physical TLS request budget", page, used)
			}
			t.Logf("page%d rows%d normalized-limit50 physical-node-requests%d", page+1, want, used)
			after = d.ClonePosition(facts.Next)
		}
		wantHashes := make([][32]byte, len(node.transactions))
		for i, tx := range node.transactions {
			wantHashes[i] = [32]byte(tx.Hash())
		}
		if !reflect.DeepEqual(hashes, wantHashes) {
			t.Fatal("paged results lost, reordered or duplicated the actual five signed transactions", hashes, wantHashes)
		}
		return locator
	}

	var locator string
	t.Run("default-broad-list", func(t *testing.T) {
		locator = walk(t, scope, []int{5})
	})
	if locator == "" {
		t.Fatal("broad-page locator unavailable")
	}
	t.Run("selected-address-reserves-extra-witness", func(t *testing.T) {
		selected := scope
		selected.Query, err = d.NormalizeRetained(d.Query{Version: 1, Resource: p.Transactions, View: d.List, AddressID: &locator}, base)
		if err != nil || selected.Query.Limit() != 50 {
			t.Fatal("external selected-address normalized query changed", err)
		}
		walk(t, selected, []int{5})
	})
}
