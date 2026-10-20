package redis

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	goredis "github.com/redis/go-redis/v9"
	"privacy-proxy/internal/rbac"
)

// Verify that PermissionCache implements the rbac.PermissionCache interface.
var _ rbac.PermissionCache = (*PermissionCache)(nil)

// cachedPermissions is a wrapper for serialization that preserves the
// RPCAPIKey field. EffectivePermissions tags it with `json:"-"` to prevent
// accidental exposure in API responses, but it needs to survive the Redis
// cache roundtrip.
type cachedPermissions struct {
	*rbac.EffectivePermissions
	RPCAPIKey string `json:"_rpc_api_key,omitempty"`
}

// PermissionCache is a Redis-backed implementation of rbac.PermissionCache.
type PermissionCache struct {
	client *goredis.Client
	ttl    time.Duration
}

// NewPermissionCache creates a Redis-backed permission cache.
func NewPermissionCache(client *goredis.Client, ttl time.Duration) *PermissionCache {
	return &PermissionCache{client: client, ttl: ttl}
}

func (c *PermissionCache) key(userID, orgID string) string {
	return fmt.Sprintf("pp:rbac:%s:%s", userID, orgID)
}

// Get retrieves cached permissions for a user in an organization.
// Returns nil if not found or expired.
func (c *PermissionCache) Get(userID, orgID string) *rbac.EffectivePermissions {
	ctx := context.Background()
	data, err := c.client.Get(ctx, c.key(userID, orgID)).Bytes()
	if err != nil {
		return nil
	}
	var cached cachedPermissions
	if err := json.Unmarshal(data, &cached); err != nil {
		return nil
	}
	// Restore the RPCAPIKey that was preserved in the wrapper.
	if cached.EffectivePermissions != nil {
		cached.EffectivePermissions.RPCAPIKey = cached.RPCAPIKey
	}
	return cached.EffectivePermissions
}

// Set stores permissions in the cache with the default TTL.
func (c *PermissionCache) Set(perms *rbac.EffectivePermissions) {
	c.SetWithTTL(perms, c.ttl)
}

// SetWithTTL stores permissions in the cache with a custom TTL.
func (c *PermissionCache) SetWithTTL(perms *rbac.EffectivePermissions, ttl time.Duration) {
	if perms == nil {
		return
	}
	ctx := context.Background()
	// Wrap with cachedPermissions to preserve RPCAPIKey through serialization.
	cached := cachedPermissions{
		EffectivePermissions: perms,
		RPCAPIKey:            perms.RPCAPIKey,
	}
	data, err := json.Marshal(cached)
	if err != nil {
		return
	}
	c.client.Set(ctx, c.key(perms.UserID, perms.OrgID), data, ttl)
}

// InvalidateUser removes all cached permissions for a user.
func (c *PermissionCache) InvalidateUser(userID string) {
	ctx := context.Background()
	c.deleteByPattern(ctx, fmt.Sprintf("pp:rbac:%s:*", userID))
}

// InvalidateOrg removes all cached permissions for an organization.
func (c *PermissionCache) InvalidateOrg(orgID string) {
	ctx := context.Background()
	c.deleteByPattern(ctx, fmt.Sprintf("pp:rbac:*:%s", orgID))
}

// Invalidate removes a specific user+org entry from the cache.
func (c *PermissionCache) Invalidate(userID, orgID string) {
	ctx := context.Background()
	c.client.Del(ctx, c.key(userID, orgID))
}

// Clear removes all permission cache entries.
func (c *PermissionCache) Clear() {
	ctx := context.Background()
	c.deleteByPattern(ctx, "pp:rbac:*")
}

// Size returns the current number of permission cache entries.
func (c *PermissionCache) Size() int {
	ctx := context.Background()
	var count int
	var cursor uint64
	for {
		keys, nextCursor, err := c.client.Scan(ctx, cursor, "pp:rbac:*", 100).Result()
		if err != nil {
			return count
		}
		count += len(keys)
		cursor = nextCursor
		if cursor == 0 {
			break
		}
	}
	return count
}

// Stats returns cache statistics.
func (c *PermissionCache) Stats() rbac.CacheStats {
	return rbac.CacheStats{
		Entries:        c.Size(),
		ExpiredPending: 0, // Redis handles expiration natively
		MaxEntries:     0, // No fixed max with Redis
	}
}

// Stop is a no-op for Redis stores (no background goroutine).
func (c *PermissionCache) Stop() {}

// deleteByPattern scans for keys matching a pattern and deletes them.
func (c *PermissionCache) deleteByPattern(ctx context.Context, pattern string) {
	var cursor uint64
	for {
		keys, nextCursor, err := c.client.Scan(ctx, cursor, pattern, 100).Result()
		if err != nil {
			return
		}
		if len(keys) > 0 {
			c.client.Del(ctx, keys...)
		}
		cursor = nextCursor
		if cursor == 0 {
			break
		}
	}
}
