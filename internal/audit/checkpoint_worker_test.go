package audit

import (
	"context"
	"testing"
)

type fakeCheckpointStore struct {
	rowCount int64
	headID   int64
	headHash string
	written  []Checkpoint
}

func (f *fakeCheckpointStore) ChainStats(_ context.Context, _ string) (int64, int64, string, error) {
	return f.rowCount, f.headID, f.headHash, nil
}

func (f *fakeCheckpointStore) WriteCheckpoint(_ context.Context, c Checkpoint) error {
	f.written = append(f.written, c)
	return nil
}

func TestCheckpointWorkerSignsHeadAndCount(t *testing.T) {
	store := &fakeCheckpointStore{rowCount: 4242, headID: 4242, headHash: "head-hash-xyz"}
	signer := NewHMACSigner("k1", []byte("checkpoint-key"))
	w := NewCheckpointWorker(store, signer, []ChainName{ChainAccessLogs}, 0)

	if err := w.Checkpoint(context.Background(), ChainAccessLogs); err != nil {
		t.Fatalf("checkpoint: %v", err)
	}
	if len(store.written) != 1 {
		t.Fatalf("want 1 checkpoint written, got %d", len(store.written))
	}
	c := store.written[0]
	if c.RowCount != 4242 || c.HeadID != 4242 || c.HeadHash != "head-hash-xyz" || c.ChainName != "access_logs" {
		t.Fatalf("checkpoint fields wrong: %+v", c)
	}
	if err := VerifyCheckpoint(signer, c); err != nil {
		t.Fatalf("written checkpoint must verify: %v", err)
	}
}

func TestCheckpointWorkerSkipsEmptyChain(t *testing.T) {
	store := &fakeCheckpointStore{rowCount: 0}
	w := NewCheckpointWorker(store, NewHMACSigner("k1", []byte("k")), []ChainName{ChainAccessLogs}, 0)
	if err := w.Checkpoint(context.Background(), ChainAccessLogs); err != nil {
		t.Fatalf("checkpoint: %v", err)
	}
	if len(store.written) != 0 {
		t.Fatalf("empty chain must write no checkpoint, got %d", len(store.written))
	}
}

func TestCheckpointTruncatedLogic(t *testing.T) {
	c := &Checkpoint{HeadID: 100}
	cases := []struct {
		name  string
		cp    *Checkpoint
		valid bool
		cur   int64
		want  bool
	}{
		{"head grew", c, true, 150, false},
		{"head unchanged", c, true, 100, false},
		{"head regressed — tail truncated", c, true, 90, true},
		{"chain emptied", c, false, 0, true},
		{"no checkpoint yet", nil, true, 0, false},
	}
	for _, tc := range cases {
		if got := checkpointTruncated(tc.cp, tc.valid, tc.cur); got != tc.want {
			t.Errorf("%s: checkpointTruncated=%v want %v", tc.name, got, tc.want)
		}
	}
}
