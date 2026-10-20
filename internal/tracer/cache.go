package tracer

import (
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"time"
)

// DefaultCacheTTL is the default TTL for trace cache entries.
const DefaultCacheTTL = 10 * time.Second

// DefaultCleanupInterval is the default interval for cache cleanup.
const DefaultCleanupInterval = 30 * time.Second

// TraceCache provides a short-TTL cache for trace results.
// It is thread-safe and performs background cleanup of expired entries.
type TraceCache struct {
	entries map[string]*cacheEntry
	ttl     time.Duration
	mu      sync.RWMutex
	wg      sync.WaitGroup
	stopCh  chan struct{}
	stopped bool
}

// cacheEntry represents a single cached trace result.
type cacheEntry struct {
	result    *TraceResult
	expiresAt time.Time
}

// NewTraceCache creates a new TraceCache with the specified TTL and cleanup interval.
// If ttl is 0, DefaultCacheTTL is used.
// If cleanupInterval is 0, DefaultCleanupInterval is used.
func NewTraceCache(ttl time.Duration, cleanupInterval time.Duration) *TraceCache {
	if ttl == 0 {
		ttl = DefaultCacheTTL
	}
	if cleanupInterval == 0 {
		cleanupInterval = DefaultCleanupInterval
	}

	c := &TraceCache{
		entries: make(map[string]*cacheEntry),
		ttl:     ttl,
		stopCh:  make(chan struct{}),
	}

	// Start background cleanup goroutine
	c.wg.Add(1)
	go c.cleanupLoop(cleanupInterval)

	return c
}

// Get retrieves a cached trace result for the given parameters.
// Returns nil if not found or expired.
func (c *TraceCache) Get(from, to, data, value, block string) *TraceResult {
	key := c.cacheKey(from, to, data, value, block)

	c.mu.RLock()
	entry, ok := c.entries[key]
	c.mu.RUnlock()

	if !ok {
		return nil
	}

	if time.Now().After(entry.expiresAt) {
		return nil
	}

	return entry.result
}

// Set stores a trace result in the cache.
func (c *TraceCache) Set(from, to, data, value, block string, result *TraceResult) {
	key := c.cacheKey(from, to, data, value, block)

	c.mu.Lock()
	c.entries[key] = &cacheEntry{
		result:    result,
		expiresAt: time.Now().Add(c.ttl),
	}
	c.mu.Unlock()
}

// Stop stops the background cleanup goroutine and waits for it to finish.
// It is safe to call Stop multiple times.
func (c *TraceCache) Stop() {
	c.mu.Lock()
	if c.stopped {
		c.mu.Unlock()
		return
	}
	c.stopped = true
	c.mu.Unlock()

	close(c.stopCh)
	c.wg.Wait()
}

// Size returns the current number of entries in the cache.
func (c *TraceCache) Size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries)
}

// Clear removes all entries from the cache.
func (c *TraceCache) Clear() {
	c.mu.Lock()
	c.entries = make(map[string]*cacheEntry)
	c.mu.Unlock()
}

// cacheKey creates a unique key by hashing the input parameters.
func (c *TraceCache) cacheKey(from, to, data, value, block string) string {
	// Concatenate all parameters with a separator
	combined := from + "|" + to + "|" + data + "|" + value + "|" + block

	// Hash using SHA256
	hash := sha256.Sum256([]byte(combined))
	return hex.EncodeToString(hash[:])
}

// cleanupLoop periodically removes expired entries.
func (c *TraceCache) cleanupLoop(interval time.Duration) {
	defer c.wg.Done()

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			c.cleanup()
		case <-c.stopCh:
			return
		}
	}
}

// cleanup removes expired entries from the cache.
func (c *TraceCache) cleanup() {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	for key, entry := range c.entries {
		if now.After(entry.expiresAt) {
			delete(c.entries, key)
		}
	}
}
