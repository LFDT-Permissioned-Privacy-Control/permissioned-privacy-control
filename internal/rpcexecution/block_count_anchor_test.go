package rpcexecution

import (
	"testing"
	"time"
)

func TestEmptyBlockCountQualifiesTargetOnIndependentMethodNode(t *testing.T) {
	parentNode := newReadHistoryFixture(t, historySigned(t, 0, 0, false, false))
	otherNode := newReadHistoryFixture(t)
	client := otherNode.readClient(t, DefaultHistoryReadLimits())
	fence := HistoryOperationFence{Deadline: time.Now().Add(3 * time.Second)}
	// The independently selected method node shares the network genesis, but
	// its canonical block1 is empty and differs from the parent's selected hash.
	if parentNode.genesis.Hash() != otherNode.genesis.Hash() {
		t.Fatal("fixture network mismatch")
	}
	anchors := []HistoryHeader{{Number: 1, Hash: parentNode.header.Hash()}}
	if pass, err := client.AcquireExplorerBatchShared(t.Context(), nil, nil, anchors, fence, 0, NewHistorySharedBudget(nil)); err == nil || pass != nil {
		t.Fatal("empty result certified a foreign canonical target")
	}
	anchors[0].Hash = otherNode.header.Hash()
	pass, err := client.AcquireExplorerBatchShared(t.Context(), nil, nil, anchors, fence, 0, NewHistorySharedBudget(nil))
	if err != nil || len(pass.Transactions()) != 0 {
		t.Fatal("qualified empty target", err)
	}
	defer pass.Close()
	otherNode.mu.Lock()
	otherNode.reorg = true
	otherNode.mu.Unlock()
	if pass.Recheck(t.Context()) == nil {
		t.Fatal("empty target escaped final canonical recheck")
	}
}
