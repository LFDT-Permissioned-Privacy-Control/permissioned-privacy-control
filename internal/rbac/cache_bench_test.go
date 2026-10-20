package rbac

import (
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

// Benchmarks for the effective-permissions cache hot path (RD-1112).
//
// The proxy consults Cache.Get on every authenticated request. These
// benchmarks measure the read path under contention at a realistic warm-cache
// occupancy. Run with:
//
//	go test -run '^$' -bench BenchmarkCacheGet -benchmem -cpu 1,4,12 ./internal/rbac/
//
// before/after a change to Cache.Get is the empirical proof that the change is
// an actual optimization and not a theoretical one.

// benchPerms builds a realistic cached object (a few claims + one contract
// grant) so the benchmark reflects real entry size, not an empty struct.
func benchPerms(userID, orgID string) *EffectivePermissions {
	return &EffectivePermissions{
		ID:             userID + "-perm",
		UserID:         userID,
		OrgID:          orgID,
		AllowedMethods: []string{"eth_sendRawTransaction", "eth_getTransactionReceipt", "eth_call"},
		ContractAccess: map[string]ContractAccess{
			"0xabcabcabcabcabcabcabcabcabcabcabcabcabca": {},
		},
		Claims:     []Claim{ClaimDeploy},
		ComputedAt: time.Now(),
		ExpiresAt:  time.Now().Add(time.Hour),
	}
}

const benchOrgID = "org-bench"

// populateBenchCache fills the cache with n entries and returns their user IDs.
func populateBenchCache(c *Cache, n int) []string {
	keys := make([]string, n)
	for i := 0; i < n; i++ {
		uid := "user-" + strconv.Itoa(i)
		c.Set(benchPerms(uid, benchOrgID))
		keys[i] = uid
	}
	return keys
}

// BenchmarkCacheGetParallel measures the pure read path under concurrency at a
// warm 50k-entry occupancy — the scenario RD-1112 flags (write lock + O(n) LRU
// scan on every hit). Each goroutine uses a local index to avoid adding
// counter contention to the measurement.
func BenchmarkCacheGetParallel(b *testing.B) {
	const n = 50000
	c := NewCache(CacheConfig{TTL: time.Hour, MaxEntries: n})
	defer c.Stop()
	keys := populateBenchCache(c, n)

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			c.Get(keys[i%n], benchOrgID)
			i++
		}
	})
}

// BenchmarkCacheGetParallelMixed adds a 5% write fraction (cache refresh /
// invalidation churn) to the parallel read load — closer to production, where
// Set/Invalidate contend with the read path on the same lock.
func BenchmarkCacheGetParallelMixed(b *testing.B) {
	const n = 50000
	c := NewCache(CacheConfig{TTL: time.Hour, MaxEntries: n})
	defer c.Stop()
	keys := populateBenchCache(c, n)

	var writes uint64
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			if i%20 == 0 {
				// occasional write: refresh an existing entry
				k := keys[i%n]
				c.Set(benchPerms(k, benchOrgID))
				atomic.AddUint64(&writes, 1)
			} else {
				c.Get(keys[i%n], benchOrgID)
			}
			i++
		}
	})
	_ = writes
}

// BenchmarkCacheGetSerial isolates the single-op cost of a hit at occupancy n
// (no contention) — exposes the O(n) per-hit cost of the access-order scan.
func BenchmarkCacheGetSerial(b *testing.B) {
	const n = 50000
	c := NewCache(CacheConfig{TTL: time.Hour, MaxEntries: n})
	defer c.Stop()
	keys := populateBenchCache(c, n)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.Get(keys[i%n], benchOrgID)
	}
}
