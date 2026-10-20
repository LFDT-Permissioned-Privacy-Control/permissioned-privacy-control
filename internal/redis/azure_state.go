package redis

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"time"

	goredis "github.com/redis/go-redis/v9"
)

// AzureStateStore is a Redis-backed CSRF state store for Azure AD logins.
// Each state token is single-use: Consume atomically retrieves and deletes via Lua.
// Implements server.AzureStateManager.
type AzureStateStore struct {
	client *goredis.Client
	ttl    time.Duration
}

// NewAzureStateStore creates a Redis-backed Azure AD state store.
func NewAzureStateStore(client *goredis.Client, ttl time.Duration) *AzureStateStore {
	return &AzureStateStore{client: client, ttl: ttl}
}

// Create generates a cryptographically random (state, nonce) pair and stores them in Redis.
func (s *AzureStateStore) Create() (state, nonce string) {
	state = randomHex(16)
	nonce = randomHex(16)
	ctx := context.Background()
	s.client.Set(ctx, "pp:azure:"+state, nonce, s.ttl)
	return state, nonce
}

// consumeScript atomically gets and deletes a key, preventing double-use.
var consumeScript = goredis.NewScript(`
local val = redis.call('GET', KEYS[1])
if val then
	redis.call('DEL', KEYS[1])
end
return val
`)

// Consume validates a state token and returns its associated nonce.
// The entry is atomically removed on retrieval (single-use).
// Returns ok=false if missing or expired.
func (s *AzureStateStore) Consume(state string) (nonce string, ok bool) {
	ctx := context.Background()
	result, err := consumeScript.Run(ctx, s.client, []string{"pp:azure:" + state}).Text()
	if err != nil {
		return "", false
	}
	return result, true
}

// Stop is a no-op for Redis stores (no background goroutine).
func (s *AzureStateStore) Stop() {}

func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand unavailable: " + err.Error())
	}
	return hex.EncodeToString(b)
}
