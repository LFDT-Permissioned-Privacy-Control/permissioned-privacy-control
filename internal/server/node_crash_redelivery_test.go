package server

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/google/uuid"
	"privacy-proxy/internal/db"
	"privacy-proxy/internal/nodepolicy"
)

// A node crash loses its newest, unwritten blocks (P7 L1). Their
// transactions were provisional in OPS; the node now answers them as a
// definitive canonical miss (N7 not_found), so they go back to pending and
// are redelivered, and the senders' later nonces are not held behind the gap
// (finding F7). A null answer alone never moves a provisional row.
func TestTransactionsInBlocksLostByACrashAreRedelivered(t *testing.T) {
	f := newKeeperFixture(t, 2*time.Second)
	f.batched.Store(true)
	f.r.notFound = f.batched.Load
	ctx := context.Background()
	keyA, _ := crypto.GenerateKey()
	keyB, _ := crypto.GenerateKey()
	principal, org := uuid.New(), uuid.New()
	var lostTxs []signedTransfer
	for nonce := uint64(0); nonce < 3; nonce++ {
		lostTxs = append(lostTxs, signTransfer(t, keyA, nonce))
	}
	lostTxs = append(lostTxs, signTransfer(t, keyB, 0))
	for _, tx := range lostTxs {
		f.admit(tx, principal, org, 0)
	}
	f.tick() // the keeper delivers the recorded intents
	f.flushAcks()
	f.mock.ProduceBlock()
	f.tick()
	for _, tx := range lostTxs {
		if row := f.row(tx); row.State != db.TrackProvisional {
			t.Fatalf("not provisional before the crash: %+v", row)
		}
	}
	later := signTransfer(t, keyA, 3) // delivered, waiting behind the lost nonces
	f.admit(later, principal, org, 0)
	f.tick()
	before := len(f.events("ops.system.recovery")) // the fixture's first deliveries
	if lost := f.mock.Crash(1); len(lost) != len(lostTxs) {
		t.Fatalf("crash lost %d transactions, want %d", len(lost), len(lostTxs))
	}
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		f.tick()
		f.flushAcks()
		f.mock.ProduceBlock()
		done := true
		for _, tx := range append(append([]signedTransfer{}, lostTxs...), later) {
			if f.row(tx).State != db.TrackIncluded {
				done = false
			}
		}
		if done {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	for _, tx := range append(append([]signedTransfer{}, lostTxs...), later) {
		if row := f.row(tx); row.State != db.TrackIncluded {
			t.Fatalf("a transaction of a lost block, or a later nonce, was not included again: %+v", row)
		}
	}
	if senders, txs := f.mock.Stalled(); senders != 0 || txs != 0 {
		t.Fatalf("%d senders with %d transactions held behind a gap", senders, txs)
	}
	if used, pending, err := f.tracking.runtime.PendingQuota(ctx); err != nil || used != 0 || pending != 0 {
		t.Fatalf("quota %d, pending %d: %v", used, pending, err)
	}
	// One audited renewal per lost transaction and one for the later nonce,
	// each for the restart that lost it.
	renewals := f.events("ops.system.recovery")[before:]
	if len(renewals) != len(lostTxs)+1 {
		t.Fatalf("%d recovery renewals after the crash for %d lost and 1 later transaction", len(renewals), len(lostTxs))
	}
	for _, e := range renewals {
		if !strings.Contains(string(e.Params), `"reason":"node_restarted"`) {
			t.Fatalf("renewal after a crash: %s", e.Params)
		}
	}
}

// The same node process losing a block it reported (a definitive miss, no
// restart): the delivery record is cleared, so the keeper renews and
// redelivers it as undelivered (F7 review).
func TestSameBootMissClearsTheDeliveryRecord(t *testing.T) {
	f := newKeeperFixture(t, 2*time.Second)
	f.batched.Store(true)
	key, _ := crypto.GenerateKey()
	tx := signTransfer(t, key, 0)
	f.admit(tx, uuid.New(), uuid.New(), 0)
	f.tick()
	f.flushAcks()
	f.mock.ProduceBlock()
	f.tick()
	if row := f.row(tx); row.State != db.TrackProvisional {
		t.Fatalf("not provisional: %+v", row)
	}
	before := len(f.events("ops.system.recovery")) // the fixture's first delivery
	f.mock.LoseBlocks(1)
	f.r.keeper = nil // the reconciler's transition alone first
	f.tick()
	row := f.row(tx)
	if row.State != db.TrackPending || row.DeliveredGeneration != nil || row.DeliveredBoot != uuid.Nil {
		t.Fatalf("a same-boot miss left the delivery record: %+v", row)
	}
	f.r.keeper = f.k
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) && f.row(tx).State != db.TrackIncluded {
		f.tick()
		f.flushAcks()
		f.mock.ProduceBlock()
		time.Sleep(200 * time.Millisecond)
	}
	if row := f.row(tx); row.State != db.TrackIncluded {
		t.Fatalf("not redelivered and included: %+v", row)
	}
	renewals := f.events("ops.system.recovery")[before:]
	if len(renewals) != 1 || !strings.Contains(string(renewals[0].Params), `"reason":"undelivered"`) {
		t.Fatalf("renewals %+v", renewals)
	}
}

// A definitive miss from a node that does not advertise it is an invalid
// answer: the provisional row is quarantined, never moved (F7 review).
func TestUnadvertisedMissNeverMovesAProvisionalRow(t *testing.T) {
	f := newKeeperFixture(t, time.Hour)
	f.batched.Store(true)
	f.r.notFound = func() bool { return false }
	key, _ := crypto.GenerateKey()
	tx := signTransfer(t, key, 0)
	f.admit(tx, uuid.New(), uuid.New(), 0)
	f.r.node = olderNode{f.client} // delivery and inclusion as an older node
	f.tick()
	f.mock.ProduceBlock()
	f.tick()
	if row := f.row(tx); row.State != db.TrackProvisional {
		t.Fatalf("not provisional: %+v", row)
	}
	f.r.node = f.client // now the node sends the miss it does not advertise
	f.mock.Crash(1)
	for i := 0; i < 5; i++ {
		f.tick()
	}
	if row := f.row(tx); row.State != db.TrackProvisional {
		t.Fatalf("an unadvertised miss moved a provisional row: %+v", row)
	}
	if q := f.r.rows[string(hashBytes(t, tx.hash))]; q == nil || q.quarantine == 0 {
		t.Fatal("the unadvertised miss was not treated as an invalid answer")
	}
}

// Without the node's definitive miss (a node without transaction_not_found_v1,
// or a null answer), a provisional row is never moved: null is no evidence.
func TestProvisionalRowIsNotMovedOnNoAnswer(t *testing.T) {
	f := newKeeperFixture(t, time.Hour)
	f.batched.Store(true)
	f.r.notFound = func() bool { return false } // the node does not advertise it
	f.r.node = olderNode{f.client}
	key, _ := crypto.GenerateKey()
	tx := signTransfer(t, key, 0)
	f.admit(tx, uuid.New(), uuid.New(), 0)
	f.tick()
	f.mock.ProduceBlock()
	f.tick()
	if row := f.row(tx); row.State != db.TrackProvisional {
		t.Fatalf("not provisional: %+v", row)
	}
	f.mock.Crash(1)
	for i := 0; i < 5; i++ {
		f.tick()
	}
	if row := f.row(tx); row.State != db.TrackProvisional {
		t.Fatalf("a provisional row moved without a definitive miss from a capable node: %+v", row)
	}
}

// olderNode answers as a node without transaction_not_found_v1: no answer
// (null) where the current node reports a definitive miss.
type olderNode struct{ *nodepolicy.Client }

func (n olderNode) TransactionStatuses(ctx context.Context, hashes []string) (nodepolicy.TransactionStatusBatch, error) {
	batch, err := n.Client.TransactionStatuses(ctx, hashes)
	for i, entry := range batch.Statuses {
		if entry != nil && entry.NotFound {
			batch.Statuses[i] = nil
		}
	}
	return batch, err
}
