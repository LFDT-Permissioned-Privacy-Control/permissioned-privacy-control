package disclosurecase

import (
	"context"
	"testing"
	"time"
)

func TestDataReadFenceRetainsOriginalCallerAndAbsoluteDeadline(t *testing.T) {
	parent, cancel := context.WithCancel(context.Background())
	defer cancel()
	fence, err := newDataReadFence(parent)
	if err != nil {
		t.Fatal(err)
	}
	_, childCancel := context.WithDeadline(parent, fence.deadline)
	childCancel()
	if fence.check() != nil {
		t.Fatal("Read child cancellation invalidated prepared response")
	}
	original := fence.deadline
	fence.clip(time.Hour)
	if fence.deadline != original {
		t.Fatal("renewed original five-second bound")
	}
	fence.clip(time.Second)
	if !fence.deadline.Before(original) {
		t.Fatal("earlier view/case expiry ignored")
	}
	cancel()
	if fence.check() == nil {
		t.Fatal("parent cancellation after preparation accepted")
	}
	expired := dataReadFence{deadline: time.Now().Add(-time.Nanosecond)}
	if expired.check() == nil {
		t.Fatal("original deadline ignored after audit commit")
	}
	parent, stop := context.WithDeadline(context.Background(), time.Now().Add(time.Second))
	defer stop()
	fence, err = newDataReadFence(parent)
	if err != nil {
		t.Fatal(err)
	}
	deadline, _ := parent.Deadline()
	if fence.deadline != deadline {
		t.Fatal("earlier caller deadline extended")
	}
}
