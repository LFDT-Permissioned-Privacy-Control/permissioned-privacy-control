package tracer

import (
	"testing"
	"time"
)

func TestTraceCache_GetSet(t *testing.T) {
	cache := NewTraceCache(1*time.Second, 100*time.Millisecond)
	defer cache.Stop()

	result := &TraceResult{
		CallTargets: []CallTarget{
			{Type: "CALL", From: "0xa", To: "0xb"},
		},
		GasUsed: 21000,
	}

	// Set and get
	cache.Set("0xfrom", "0xto", "0xdata", "0x0", "latest", result)
	cached := cache.Get("0xfrom", "0xto", "0xdata", "0x0", "latest")

	if cached == nil {
		t.Fatal("expected cached result")
	}
	if len(cached.CallTargets) != 1 {
		t.Errorf("expected 1 call target, got %d", len(cached.CallTargets))
	}
	if cached.GasUsed != 21000 {
		t.Errorf("expected gasUsed 21000, got %d", cached.GasUsed)
	}
}

func TestTraceCache_Miss(t *testing.T) {
	cache := NewTraceCache(1*time.Second, 100*time.Millisecond)
	defer cache.Stop()

	cached := cache.Get("0xfrom", "0xto", "0xdata", "0x0", "latest")
	if cached != nil {
		t.Error("expected nil for cache miss")
	}
}

func TestTraceCache_DifferentKeys(t *testing.T) {
	cache := NewTraceCache(1*time.Second, 100*time.Millisecond)
	defer cache.Stop()

	result1 := &TraceResult{GasUsed: 100}
	result2 := &TraceResult{GasUsed: 200}

	cache.Set("0xfrom1", "0xto", "0xdata", "0x0", "latest", result1)
	cache.Set("0xfrom2", "0xto", "0xdata", "0x0", "latest", result2)

	cached1 := cache.Get("0xfrom1", "0xto", "0xdata", "0x0", "latest")
	cached2 := cache.Get("0xfrom2", "0xto", "0xdata", "0x0", "latest")

	if cached1 == nil || cached1.GasUsed != 100 {
		t.Error("cached1 mismatch")
	}
	if cached2 == nil || cached2.GasUsed != 200 {
		t.Error("cached2 mismatch")
	}
}

func TestTraceCache_Expiration(t *testing.T) {
	cache := NewTraceCache(50*time.Millisecond, 10*time.Millisecond)
	defer cache.Stop()

	result := &TraceResult{GasUsed: 21000}
	cache.Set("0xfrom", "0xto", "0xdata", "0x0", "latest", result)

	// Should exist immediately
	if cache.Get("0xfrom", "0xto", "0xdata", "0x0", "latest") == nil {
		t.Error("expected cached result before expiration")
	}

	// Wait for expiration
	time.Sleep(100 * time.Millisecond)

	// Should be expired
	if cache.Get("0xfrom", "0xto", "0xdata", "0x0", "latest") != nil {
		t.Error("expected nil after expiration")
	}
}

func TestTraceCache_Cleanup(t *testing.T) {
	cache := NewTraceCache(50*time.Millisecond, 10*time.Millisecond)
	defer cache.Stop()

	// Add multiple entries
	for i := 0; i < 10; i++ {
		result := &TraceResult{GasUsed: uint64(i)}
		cache.Set("0xfrom", "0xto", string(rune('0'+i)), "0x0", "latest", result)
	}

	// Wait for cleanup to run
	time.Sleep(100 * time.Millisecond)

	// All entries should be expired and cleaned up
	cache.mu.RLock()
	remaining := len(cache.entries)
	cache.mu.RUnlock()

	if remaining != 0 {
		t.Errorf("expected 0 entries after cleanup, got %d", remaining)
	}
}

func TestTraceCache_Stop(t *testing.T) {
	cache := NewTraceCache(1*time.Second, 100*time.Millisecond)

	// Should not panic
	cache.Stop()

	// Second stop should also not panic
	cache.Stop()
}

func TestCacheKey(t *testing.T) {
	cache := NewTraceCache(1*time.Second, 100*time.Millisecond)
	defer cache.Stop()

	key1 := cache.cacheKey("0xfrom", "0xto", "0xdata", "0x0", "latest")
	key2 := cache.cacheKey("0xfrom", "0xto", "0xdata", "0x0", "latest")
	key3 := cache.cacheKey("0xfrom", "0xto", "0xdata", "0x1", "latest")

	if key1 != key2 {
		t.Error("same inputs should produce same key")
	}
	if key1 == key3 {
		t.Error("different inputs should produce different keys")
	}
	if len(key1) != 64 { // SHA256 produces 32 bytes = 64 hex chars
		t.Errorf("expected 64 char key, got %d", len(key1))
	}
}
