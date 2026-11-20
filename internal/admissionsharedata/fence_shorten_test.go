package admissionsharedata

import (
	"context"
	"testing"
	"time"
)

func TestBorrowedCountFenceCannotExtendOriginalTimeoutOrCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	original, e := NewFence(ctx, 25*time.Millisecond)
	if e != nil {
		t.Fatal(e)
	}
	borrowed, e := original.Shortened(time.Now().Add(5 * time.Second))
	if e != nil {
		t.Fatal(e)
	}
	d, done := original.Original()
	bd, bdone := borrowed.Original()
	if !d.Equal(bd) || done != bdone {
		t.Fatal("count purpose renewed original scope")
	}
	bound, stop, e := borrowed.Bind(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	defer stop()
	select {
	case <-bound.Done():
	case <-time.After(250 * time.Millisecond):
		t.Fatal("slow source outlived original timeout")
	}
	original, e = NewFence(ctx, time.Second)
	if e != nil {
		t.Fatal(e)
	}
	borrowed, e = original.Shortened(time.Now().Add(5 * time.Second))
	if e != nil {
		t.Fatal(e)
	}
	cancel()
	if borrowed.Check() == nil {
		t.Fatal("lost original cancellation")
	}
}
