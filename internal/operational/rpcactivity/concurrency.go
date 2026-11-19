package rpcactivity

import (
	"strings"
	"sync"

	"privacy-proxy/internal/identity"
)

func (s *Service) bindFairness(c Config) error {
	if c.Snapshot == nil || c.Clock == nil || c.Engine != nil && !c.Engine.UsesSnapshot(c.Snapshot) || c.Metadata != nil && !c.Metadata.UsesSnapshot(c.Snapshot) || c.State != nil && !c.State.UsesSnapshot(c.Snapshot) || c.History != nil && !c.History.UsesSnapshot(c.Snapshot) || c.Explorer != nil && !c.Explorer.UsesSnapshot(c.Snapshot) {
		return ErrInvalid
	}
	catalog, ok := c.Snapshot.Identity()
	if !ok {
		return ErrInvalid
	}
	verifier, err := identity.NewVerifier(catalog, c.Clock)
	if err != nil {
		return ErrInvalid
	}
	s.verifier = verifier
	s.fairness = newLocalConcurrency(cap(s.slots))
	return nil
}

func (s *Service) acquireFairness(headers []string) (func(), bool) {
	if s == nil || s.verifier == nil || s.fairness == nil {
		return nil, false
	}
	actor := ""
	if len(headers) == 1 {
		parts := strings.Split(headers[0], " ")
		if len(parts) == 2 && strings.EqualFold(parts[0], "Bearer") && parts[1] != "" {
			if principal, err := s.verifier.VerifyAccess(parts[1]); err == nil {
				actor = principal.ActorID()
			}
		}
	}
	return s.fairness.tryAcquire(actor)
}

const perPrincipalConcurrency = 50
const anonymousConcurrency = 50

// localConcurrency stores active verified actors only. The service's existing
// global slot must already be held; maxActors additionally bounds map growth.
// It is neither a requests/second quota nor a shared fleet budget.
type localConcurrency struct {
	mu        sync.Mutex
	actors    map[string]int
	anonymous int
	maxActors int
}

func newLocalConcurrency(maxActors int) *localConcurrency {
	return &localConcurrency{actors: make(map[string]int), maxActors: maxActors}
}

func (l *localConcurrency) tryAcquire(actor string) (func(), bool) {
	if l == nil || actor != "" && !identity.ValidActorID(actor) {
		return nil, false
	}
	l.mu.Lock()
	if actor == "" {
		if l.anonymous >= anonymousConcurrency {
			l.mu.Unlock()
			return nil, false
		}
		l.anonymous++
	} else {
		n := l.actors[actor]
		if n >= perPrincipalConcurrency || n == 0 && len(l.actors) >= l.maxActors {
			l.mu.Unlock()
			return nil, false
		}
		l.actors[actor] = n + 1
	}
	l.mu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			l.mu.Lock()
			defer l.mu.Unlock()
			if actor == "" {
				l.anonymous--
				return
			}
			if l.actors[actor] == 1 {
				delete(l.actors, actor)
			} else {
				l.actors[actor]--
			}
		})
	}, true
}
