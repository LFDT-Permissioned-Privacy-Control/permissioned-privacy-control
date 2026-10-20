package main

import (
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
)

type confirmationToken struct {
	Token     string
	ToolName  string
	Params    map[string]any
	CreatedAt time.Time
}

type ConfirmationEngine struct {
	mu     sync.Mutex
	tokens map[string]*confirmationToken
	ttl    time.Duration
}

func NewConfirmationEngine() *ConfirmationEngine {
	return &ConfirmationEngine{
		tokens: make(map[string]*confirmationToken),
		ttl:    60 * time.Second,
	}
}

func (e *ConfirmationEngine) Request(toolName string, params map[string]any) string {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.gc()

	paramsCopy := make(map[string]any, len(params))
	for k, v := range params {
		paramsCopy[k] = v
	}
	token := uuid.New().String()
	e.tokens[token] = &confirmationToken{
		Token:     token,
		ToolName:  toolName,
		Params:    paramsCopy,
		CreatedAt: time.Now(),
	}
	return token
}

// Validate checks and consumes a confirmation token. Returns the params that
// were captured when the token was issued — callers MUST use these returned
// params (via confirmParam) for the actual operation, not the args from the
// second tool call. This prevents parameter-swap attacks where a token issued
// for "delete org A" is replayed with args pointing to "org B".
func (e *ConfirmationEngine) Validate(token, toolName string) (map[string]any, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.gc()

	ct, ok := e.tokens[token]
	if !ok {
		return nil, fmt.Errorf("invalid or expired confirmation token")
	}
	if ct.ToolName != toolName {
		return nil, fmt.Errorf("token was issued for %q, not %q", ct.ToolName, toolName)
	}

	params := ct.Params
	delete(e.tokens, token)
	return params, nil
}

func confirmParam(params map[string]any, key string) string {
	if v, ok := params[key].(string); ok {
		return v
	}
	return ""
}

func (e *ConfirmationEngine) gc() {
	now := time.Now()
	for k, v := range e.tokens {
		if now.Sub(v.CreatedAt) > e.ttl {
			delete(e.tokens, k)
		}
	}
}
