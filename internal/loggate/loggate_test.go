package loggate

import (
	"testing"
	"time"
)

func TestGateLetsOneLinePerKeyPerIntervalAndCountsTheRest(t *testing.T) {
	var g Gate
	at := time.Unix(1_000, 0)
	if held, ok := g.Allow("a", at, 10*time.Second); !ok || held != 0 {
		t.Fatalf("first line %d %v", held, ok)
	}
	for i := 0; i < 5; i++ {
		if _, ok := g.Allow("a", at.Add(time.Second), 10*time.Second); ok {
			t.Fatal("a repeat inside the interval was let through")
		}
	}
	if _, ok := g.Allow("b", at.Add(time.Second), 10*time.Second); !ok {
		t.Fatal("keys must not share an interval")
	}
	if held, ok := g.Allow("a", at.Add(10*time.Second), 10*time.Second); !ok || held != 5 {
		t.Fatalf("after the interval: held %d %v, want 5 true", held, ok)
	}
	if held, ok := g.Allow("a", at.Add(20*time.Second), 10*time.Second); !ok || held != 0 {
		t.Fatalf("held count must reset: %d %v", held, ok)
	}
}
