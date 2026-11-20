package rpcexecution

import "sync"

// HistorySharedBudget is a single ordinary Explorer request's outer ledger.
// Individual observations retain their own lower configured limits as well.
type historyFinalCost struct {
	physical, items int
	wire            int64
}
type HistorySharedBudget struct {
	mu                                sync.Mutex
	limits                            HistoryReadLimits
	physical, items, parents, headers int
	wire                              int64
	owned                             func(int) error
	ownedBytes                        int
	final                             map[*historyReadBudget]historyFinalCost
	reservedPhysical, reservedItems   int
	reservedWire                      int64
}

func NewHistorySharedBudget(owned func(int) error) *HistorySharedBudget {
	return &HistorySharedBudget{limits: DefaultHistoryReadLimits(), owned: owned, final: map[*historyReadBudget]historyFinalCost{}}
}
func (s *HistorySharedBudget) lower(l HistoryReadLimits) error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	next := s.limits
	next.MaxHTTPAttempts = min(next.MaxHTTPAttempts, l.MaxHTTPAttempts)
	next.MaxRPCItems = min(next.MaxRPCItems, l.MaxRPCItems)
	next.MaxParents = min(next.MaxParents, l.MaxParents)
	next.MaxHeaders = min(next.MaxHeaders, l.MaxHeaders)
	next.MaxWireBytes = min(next.MaxWireBytes, l.MaxWireBytes)
	next.MaxChargedBytes = min(next.MaxChargedBytes, l.MaxChargedBytes)
	if s.ownedBytes > next.MaxChargedBytes || s.physical+s.reservedPhysical > next.MaxHTTPAttempts || s.items+s.reservedItems > next.MaxRPCItems || s.parents > next.MaxParents || s.headers > next.MaxHeaders || s.wire+s.reservedWire > next.MaxWireBytes {
		return failure(EvidenceLimit)
	}
	s.limits = next
	return nil
}
func (s *HistorySharedBudget) charge(physical, items, parents, headers int, wire int64) error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if physical < 0 || items < 0 || parents < 0 || headers < 0 || wire < 0 || physical > s.limits.MaxHTTPAttempts-s.physical-s.reservedPhysical || items > s.limits.MaxRPCItems-s.items-s.reservedItems || parents > s.limits.MaxParents-s.parents || headers > s.limits.MaxHeaders-s.headers || wire > s.limits.MaxWireBytes-s.wire-s.reservedWire {
		return failure(EvidenceLimit)
	}
	s.physical += physical
	s.items += items
	s.parents += parents
	s.headers += headers
	s.wire += wire
	return nil
}
func (s *HistorySharedBudget) CanAcquire(proofs int) bool {
	if s == nil {
		return true
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.physical+proofs*6+12 < s.limits.MaxHTTPAttempts && s.items+proofs*12+32 < s.limits.MaxRPCItems && s.parents+16 < s.limits.MaxParents && s.headers+16 < s.limits.MaxHeaders && s.wire < 24<<20
}

func (s *HistorySharedBudget) reserveFinal(b *historyReadBudget, headers int) error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	cost := historyFinalCost{(3+b.limits.MaxBatchItems-1)/b.limits.MaxBatchItems + (headers+b.limits.MaxBatchItems-1)/b.limits.MaxBatchItems, 3 + headers, int64(3+headers) * 24 << 10}
	if s.physical+s.reservedPhysical+cost.physical > s.limits.MaxHTTPAttempts || s.items+s.reservedItems+cost.items > s.limits.MaxRPCItems || s.wire+s.reservedWire+cost.wire > s.limits.MaxWireBytes {
		return failure(EvidenceLimit)
	}
	s.final[b] = cost
	s.reservedPhysical += cost.physical
	s.reservedItems += cost.items
	s.reservedWire += cost.wire
	return nil
}
func (s *HistorySharedBudget) releaseFinal(b *historyReadBudget) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if cost, ok := s.final[b]; ok {
		delete(s.final, b)
		s.reservedPhysical -= cost.physical
		s.reservedItems -= cost.items
		s.reservedWire -= cost.wire
	}
}

func (s *HistorySharedBudget) wireAllowance() int64 {
	if s == nil {
		return 32 << 20
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.limits.MaxWireBytes - s.wire - s.reservedWire
}

func (s *HistorySharedBudget) reserveOwned(n int) error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if n < 0 || n > s.limits.MaxChargedBytes-s.ownedBytes {
		return failure(EvidenceLimit)
	}
	if s.owned != nil {
		if e := s.owned(n); e != nil {
			return failure(EvidenceLimit)
		}
	}
	s.ownedBytes += n
	return nil
}
