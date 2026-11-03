package server

import (
	"strings"
	"sync"
	"time"
)

// systemLinkCacheTTL and systemLinkCacheMax follow the permission cache's
// defaults (rbac.DefaultCacheConfig): a remembered link is re-checked after
// five minutes, and memory stays bounded.
const (
	systemLinkCacheTTL = 5 * time.Minute
	systemLinkCacheMax = 50_000
)

// systemLinkCache remembers (DID, sender) pairs whose system link this
// instance wrote or confirmed, so a steady stream of transactions from one
// sender does not repeat the INSERT ... ON CONFLICT DO NOTHING round trip on
// every request (RD-1410). It follows the permission cache's pattern (TTL as
// the correctness bound, bounded entries, sampled eviction, read-locked
// lookups). No product path deletes eth_address_links rows (revocation is an
// update and the row stays, so it is never re-created either way); a row
// removed directly in SQL is re-created by the next transaction at most one
// TTL later instead of at once.
type systemLinkCache struct {
	mu      sync.RWMutex
	expires map[string]time.Time
	now     func() time.Time
}

func newSystemLinkCache() *systemLinkCache {
	return &systemLinkCache{expires: map[string]time.Time{}, now: time.Now}
}

func systemLinkKey(did, address string) string { return did + "|" + strings.ToLower(address) }

// known and remember treat a nil cache (a processor built as a struct
// literal) as empty: every link is written, as before.
func (c *systemLinkCache) known(did, address string) bool {
	if c == nil {
		return false
	}
	c.mu.RLock()
	expiry, ok := c.expires[systemLinkKey(did, address)]
	c.mu.RUnlock()
	return ok && c.now().Before(expiry)
}

func (c *systemLinkCache) remember(did, address string) {
	if c == nil {
		return
	}
	now := c.now()
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.expires) >= systemLinkCacheMax {
		// Sampled eviction as in the permission cache: look at a bounded random
		// sample (map order is random), drop its expired entries, and drop
		// arbitrary ones only to make room. Eviction is memory management; the
		// TTL is the correctness bound.
		sampled, dropped := 0, 0
		for key, expiry := range c.expires {
			sampled++
			if !now.Before(expiry) || sampled > 56 {
				delete(c.expires, key)
				dropped++
			}
			if dropped >= 8 || sampled >= 64 {
				break
			}
		}
	}
	c.expires[systemLinkKey(did, address)] = now.Add(systemLinkCacheTTL)
}
