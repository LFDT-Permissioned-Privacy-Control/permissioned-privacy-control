package explorerquery

import "sync"

// ReadBudget belongs to one Explorer request, including its optional counters
// and every retained proof's final probes. It never grants read authority.
type ReadBudget struct {
	mu                       sync.Mutex
	calls, rows, bytes, work int
}

func NewReadBudget() *ReadBudget { return &ReadBudget{} }
func (b *ReadBudget) charge(calls, rows, bytes, work int) error {
	if b == nil {
		return nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if calls < 0 || rows < 0 || bytes < 0 || work < 0 || calls > 128-b.calls || rows > 20000-b.rows || bytes > 16<<20-b.bytes || work > 20000-b.work {
		return ErrTooBroad
	}
	b.calls += calls
	b.rows += rows
	b.bytes += bytes
	b.work += work
	return nil
}
func (b *ReadBudget) Call() error       { return b.charge(1, 0, 0, 0) }
func (b *ReadBudget) Rows(n int) error  { return b.charge(0, n, 0, 0) }
func (b *ReadBudget) Bytes(n int) error { return b.charge(0, 0, n, 0) }
func (b *ReadBudget) Work(n int) error  { return b.charge(0, 0, 0, n) }

// CanAcquire reserves headroom for final source probes. Actual probes are
// charged normally; this check does not reset or refund any counter.
func (b *ReadBudget) CanAcquire(proofs int) bool {
	if b == nil {
		return true
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.calls+proofs+8 < 128 && b.rows < 19500 && b.bytes < 12<<20 && b.work < 19000
}

func (b *ReadBudget) RemainingBytes() int {
	if b == nil {
		return 16 << 20
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return (16 << 20) - b.bytes
}
