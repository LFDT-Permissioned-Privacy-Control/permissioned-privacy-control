package protectedsource

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	d "privacy-proxy/internal/disclosuredata"
	p "privacy-proxy/internal/disclosurepolicy"
	f "privacy-proxy/internal/disclosuretest"
)

func TestRetainedActualContinuationAndRecoveryFences(t *testing.T) {
	node := ownedFunctionalNode(t)
	var control functionalControl
	config := actualFunctionalConfig(t, node, func(c functionalControl) { control = c })
	source, err := New(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}
	plan := source.Plan()
	base := p.Scope{TargetActors: []string{f.Actor(f.Subject)}, Resources: []p.Resource{p.Transactions}, Addresses: p.Addresses{Mode: "all-target-addresses", Values: []string{}}, DataTime: p.Interval{Start: f.Now - 10, End: f.Now + 10}, Level: p.Full}
	query, err := d.Normalize(d.Query{Version: 1, Resource: p.Transactions, View: d.List}, base)
	if err != nil {
		t.Fatal(err)
	}
	scope := d.ReadScope{Namespace: digestParts("recovery-case"), CaseID: uuid.NewString(), CaseVersion: 1, RecipientActorID: f.Actor(f.AdminSubject), DataOrganizationID: f.Org, BundleDigest: plan.BundleDigest, RuleDigest: digestParts("recovery-rule"), EffectiveUntil: config.Clock().Add(time.Minute), Query: query}
	open := func(ctx context.Context) d.RetainedSnapshot {
		t.Helper()
		r, e := source.OpenRetained(ctx, scope, nil, nil, nil)
		if e != nil {
			t.Fatal(e)
		}
		t.Cleanup(r.Close)
		return r
	}
	first := open(t.Context())
	facts, err := first.Read(t.Context(), scope, nil)
	if err != nil || len(facts.Transactions) != 1 {
		t.Fatal(err)
	}
	basis := first.Basis()
	refs, err := d.SourceReferencesRetained(plan, first.Descriptors())
	if err != nil {
		t.Fatal(err)
	}
	position := &d.Position{Kind: d.HistorySource, Transaction: &d.TransactionPosition{BlockNumber: facts.Transactions[0].BlockNumber, TransactionIndex: facts.Transactions[0].TransactionIndex, Hash: facts.Transactions[0].Hash}}
	node.advanceHead(true)
	next, err := source.OpenRetained(t.Context(), scope, refs, &basis, position)
	if err != nil {
		t.Fatal("H+1 continuation", err)
	}
	defer next.Close()
	if !next.Basis().Equal(basis) {
		t.Fatal("continuation moved its original upper anchor")
	}
	swapped := d.ClonePosition(position)
	swapped.Transaction.TransactionIndex++
	if _, err = next.Read(t.Context(), scope, swapped); !errors.Is(err, d.ErrInvalid) {
		t.Fatal("swapped authenticated position accepted", err)
	}
	if _, err = next.Read(t.Context(), scope, nil); !errors.Is(err, d.ErrInvalid) {
		t.Fatal("continuation position dropped", err)
	}
	page, err := next.Read(t.Context(), scope, position)
	if err != nil || len(page.Transactions) != 0 || !page.End {
		t.Fatal("original-cut continuation", page, err)
	}
	if err = next.CheckCurrent(t.Context()); err != nil {
		t.Fatal("normal head advance invalidated original cut", err)
	}
	for _, mutate := range []func(*d.RetainedBasis){func(b *d.RetainedBasis) { b.ConfiguredEpoch = uuid.NewString() }, func(b *d.RetainedBasis) { b.NodeSource = digestParts("other-node") }, func(b *d.RetainedBasis) { b.IndexSource = digestParts("other-index") }} {
		bad := basis.Clone()
		mutate(&bad)
		if read, e := source.OpenRetained(t.Context(), scope, refs, &bad, position); e == nil {
			read.Close()
			t.Fatal("foreign recovery/source basis accepted")
		}
	}
	node.advanceHead(false)
	t.Run("original-parent", func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		read := open(ctx)
		if _, e := read.Read(ctx, scope, nil); e != nil {
			t.Fatal(e)
		}
		cancel()
		if e := read.CheckCurrent(t.Context()); e == nil {
			t.Fatal("cancelled original parent replaced by fresh caller")
		}
	})
	t.Run("index-contradiction", func(t *testing.T) {
		read := open(t.Context())
		if _, e := read.Read(t.Context(), scope, nil); e != nil {
			t.Fatal(e)
		}
		functionalExec(t, control.index, `UPDATE public.transactions SET to_address=$1 WHERE hash=$2`, "0x9999999999999999999999999999999999999999", node.tx.Hash().Hex())
		if e := read.CheckCurrent(t.Context()); e == nil {
			t.Fatal("changed indexed witness accepted")
		}
		functionalExec(t, control.index, `UPDATE public.transactions SET to_address=$1 WHERE hash=$2`, node.tx.To().Hex(), node.tx.Hash().Hex())
	})
	t.Run("orphan-index-witness", func(t *testing.T) {
		read := open(t.Context())
		if _, e := read.Read(t.Context(), scope, nil); e != nil {
			t.Fatal(e)
		}
		functionalExec(t, control.index, `UPDATE public.blocks SET hash=$1 WHERE number=1`, "0x9999999999999999999999999999999999999999999999999999999999999999")
		if e := read.CheckCurrent(t.Context()); e == nil {
			t.Fatal("orphaned indexed block witness accepted")
		}
		functionalExec(t, control.index, `UPDATE public.blocks SET hash=$1 WHERE number=1`, node.head.Hash().Hex())
	})
	t.Run("wallet-revocation", func(t *testing.T) {
		read := open(t.Context())
		if _, e := read.Read(t.Context(), scope, nil); e != nil {
			t.Fatal(e)
		}
		functionalExec(t, control.wallet.Owner, `UPDATE ops_wallet_v2.wallet_links SET revoked=true,revoked_at=now() WHERE namespace=$1`, control.wallet.Namespace[:])
		if e := read.CheckCurrent(t.Context()); e == nil {
			t.Fatal("wallet revocation missed after source preparation")
		}
	})
	t.Run("namespace-recovery", func(t *testing.T) {
		read, err := source.OpenRetained(t.Context(), scope, nil, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer read.Close()
		if _, err = read.Read(t.Context(), scope, nil); err != nil {
			t.Fatal(err)
		}
		functionalExec(t, control.admission, `UPDATE ops_history_namespace_v1.namespace_network_state SET ready=false`)
		if err = read.CheckCurrent(t.Context()); err == nil {
			t.Fatal("namespace recovery missed")
		}
	})
}
