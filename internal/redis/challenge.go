package redis

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"privacy-proxy/internal/auth"
	"privacy-proxy/internal/types"

	goredis "github.com/redis/go-redis/v9"
)

// ChallengeStore is a Redis-backed store for ETH address linking challenges.
// Challenges are single-use: GetChallenge atomically retrieves and deletes via Lua.
type ChallengeStore struct {
	client *goredis.Client
	ttl    time.Duration
}

// NewChallengeStore creates a Redis-backed challenge store.
func NewChallengeStore(client *goredis.Client, ttl time.Duration) *ChallengeStore {
	return &ChallengeStore{client: client, ttl: ttl}
}

// CreateChallenge creates a new link challenge and stores it in Redis.
func (cs *ChallengeStore) CreateChallenge(did string) (*types.LinkChallenge, error) {
	nonce, err := auth.GenerateNonce()
	if err != nil {
		return nil, err
	}

	message := auth.GenerateLinkMessage(did, nonce)

	challenge := &types.LinkChallenge{
		DID:       did,
		Nonce:     nonce,
		Message:   message,
		CreatedAt: time.Now(),
	}

	data, err := json.Marshal(challenge)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	if err := cs.client.Set(ctx, "pp:challenge:"+nonce, data, cs.ttl).Err(); err != nil {
		return nil, fmt.Errorf("redis SET challenge: %w", err)
	}

	return challenge, nil
}

// consumeChallengeScript atomically gets and deletes a challenge key.
var consumeChallengeScript = goredis.NewScript(`
local val = redis.call('GET', KEYS[1])
if val then
	redis.call('DEL', KEYS[1])
end
return val
`)

// GetChallenge retrieves and removes a challenge by nonce.
// Returns nil if the challenge doesn't exist or has expired.
func (cs *ChallengeStore) GetChallenge(nonce string) *types.LinkChallenge {
	ctx := context.Background()
	result, err := consumeChallengeScript.Run(ctx, cs.client, []string{"pp:challenge:" + nonce}).Text()
	if err != nil {
		return nil
	}

	var challenge types.LinkChallenge
	if err := json.Unmarshal([]byte(result), &challenge); err != nil {
		return nil
	}
	return &challenge
}

// Stop is a no-op for Redis stores (no background goroutine).
func (cs *ChallengeStore) Stop() {}
