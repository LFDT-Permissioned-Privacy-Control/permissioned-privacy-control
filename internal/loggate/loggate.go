// Package loggate rate-limits repeated log lines: one line per key per
// interval, with the number of lines held back since the last one. A
// component that fails every request then costs one log line per interval,
// not one per request. Keys must come from a small fixed set (a message and an
// error class), never from error text or request data, so the gate's memory
// stays bounded.
package loggate

import (
	"sync"
	"time"
)

// Gate is safe for concurrent use; its zero value is ready.
type Gate struct {
	mu   sync.Mutex
	next map[string]time.Time
	held map[string]int
}

// Allow reports whether a line for key may be logged at now and, if so, how
// many were held back since the previous one.
func (g *Gate) Allow(key string, now time.Time, every time.Duration) (int, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if now.Before(g.next[key]) {
		g.held[key]++
		return 0, false
	}
	if g.next == nil {
		g.next, g.held = map[string]time.Time{}, map[string]int{}
	}
	g.next[key] = now.Add(every)
	held := g.held[key]
	g.held[key] = 0
	return held, true
}
