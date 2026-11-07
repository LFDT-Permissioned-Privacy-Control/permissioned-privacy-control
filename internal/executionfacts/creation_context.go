package executionfacts

// recoverCreationContexts annotates only the new lifecycle profile. Every
// immediate child contributes its original From; no descendant or derived
// value can vote. Effective contexts/edges are rebuilt afterward by buildTree.
func recoverCreationContexts(wire []wireRecord) error {
	witnesses := make([]Address, len(wire))
	for i := len(wire) - 1; i >= 0; i-- {
		w := &wire[i]
		if w.Kind.creation() && !w.To.Known && witnesses[i].Known {
			w.recovered = witnesses[i]
		}
		parent := w.ParentIndex
		if parent < 0 {
			continue
		}
		if parent >= i {
			return fail(InvalidTrace, i, "calls", "invalid parent index")
		}
		p := wire[parent]
		if !p.Kind.creation() || p.To.Known {
			continue
		}
		candidate := knownAddress(w.From)
		if witnesses[parent].Known && witnesses[parent] != candidate {
			return fail(InvalidTrace, parent, "from", "creation children disagree on context")
		}
		witnesses[parent] = candidate
	}
	return nil
}
