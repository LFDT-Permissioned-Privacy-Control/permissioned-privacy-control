package audit

import (
	"context"
	"testing"
	"time"
)

type fakeReAnchorStore struct {
	rowCount, headID int64
	headHash         string
	latest           *Checkpoint
	anchorID         int64
	anchorHash       string
	checkpoints      []Checkpoint
	reanchors        []ReAnchor
}

func (f *fakeReAnchorStore) ChainStats(_ context.Context, _ string) (int64, int64, string, error) {
	return f.rowCount, f.headID, f.headHash, nil
}
func (f *fakeReAnchorStore) LatestCheckpoint(_ context.Context, _ string) (*Checkpoint, error) {
	return f.latest, nil
}
func (f *fakeReAnchorStore) SetAnchor(_ context.Context, _ string, id int64, h string) error {
	f.anchorID, f.anchorHash = id, h
	return nil
}
func (f *fakeReAnchorStore) WriteCheckpoint(_ context.Context, c Checkpoint) error {
	f.checkpoints = append(f.checkpoints, c)
	return nil
}
func (f *fakeReAnchorStore) WriteReAnchor(_ context.Context, r ReAnchor) error {
	f.reanchors = append(f.reanchors, r)
	return nil
}

func TestReAnchorSignVerifyAndTamper(t *testing.T) {
	s := NewHMACSigner("k1", []byte("checkpoint-key"))
	r := ReAnchor{ChainName: "access_logs", Reason: "disk loss recovery", Actor: "alice", ToHeadID: 500, ToHash: "h500", CreatedAt: time.Unix(0, 1).UTC()}
	if err := SignReAnchor(s, &r); err != nil {
		t.Fatal(err)
	}
	if err := VerifyReAnchor(s, r); err != nil {
		t.Fatalf("verify untouched: %v", err)
	}
	for name, mut := range map[string]func(*ReAnchor){
		"reason": func(x *ReAnchor) { x.Reason = "different" },
		"actor":  func(x *ReAnchor) { x.Actor = "mallory" },
		"toHead": func(x *ReAnchor) { x.ToHeadID = 1 },
	} {
		c := r
		mut(&c)
		if err := VerifyReAnchor(s, c); err == nil {
			t.Errorf("tampering with %s not detected", name)
		}
	}
}

func TestBreakGlassReAnchorOrchestration(t *testing.T) {
	s := NewHMACSigner("k1", []byte("k"))
	store := &fakeReAnchorStore{
		rowCount: 120, headID: 120, headHash: "head120",
		latest: &Checkpoint{ChainName: "access_logs", HeadID: 200, HeadHash: "oldhead200", RowCount: 200},
	}
	r, err := BreakGlassReAnchor(context.Background(), store, s, "access_logs", "alice", "disk loss")
	if err != nil {
		t.Fatalf("break-glass: %v", err)
	}
	// Signed, attributable record persisted.
	if len(store.reanchors) != 1 {
		t.Fatalf("want 1 reanchor, got %d", len(store.reanchors))
	}
	if err := VerifyReAnchor(s, store.reanchors[0]); err != nil {
		t.Fatalf("persisted reanchor must verify: %v", err)
	}
	if r.Actor != "alice" || r.Reason != "disk loss" || r.ToHeadID != 120 || r.FromHeadID != 200 {
		t.Fatalf("reanchor fields wrong: %+v", r)
	}
	// Anchor moved to the recovery point.
	if store.anchorID != 120 || store.anchorHash != "head120" {
		t.Fatalf("anchor not moved: %d %s", store.anchorID, store.anchorHash)
	}
	// Fresh signed checkpoint at the recovery point.
	if len(store.checkpoints) != 1 || store.checkpoints[0].HeadID != 120 || store.checkpoints[0].RowCount != 120 {
		t.Fatalf("checkpoint wrong: %+v", store.checkpoints)
	}
	if err := VerifyCheckpoint(s, store.checkpoints[0]); err != nil {
		t.Fatalf("fresh checkpoint must verify: %v", err)
	}
}

func TestBreakGlassRequiresActorAndReason(t *testing.T) {
	s := NewHMACSigner("k1", []byte("k"))
	store := &fakeReAnchorStore{}
	if _, err := BreakGlassReAnchor(context.Background(), store, s, "access_logs", "", "reason"); err == nil {
		t.Error("missing actor should error")
	}
	if _, err := BreakGlassReAnchor(context.Background(), store, s, "access_logs", "alice", ""); err == nil {
		t.Error("missing reason should error")
	}
}
