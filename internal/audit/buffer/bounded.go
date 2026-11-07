package buffer

import "fmt"

// DrainBounded captures the same completed-publication frontier as Drain, but
// rejects an oversized value BEFORE copying it out of Pebble. A bound error
// returns no partial batch and never advances or deletes a sequence.
func (b *Buffer) DrainBounded(afterSeq uint64, max, maxEntryBytes, maxBytes int) ([]Entry, error) {
	if max < 1 || maxEntryBytes < 1 || maxBytes < maxEntryBytes {
		return nil, fmt.Errorf("invalid audit bounded-drain limits")
	}
	frontier := b.completedThrough()
	if afterSeq >= frontier {
		return nil, nil
	}
	// The frontier is from completed writes, never a fresh allocation floor.
	// Existing seeded range callers are bounded below signed-bigint maximum.
	it, err := b.db.NewIter(prefixBounds())
	if err != nil {
		return nil, fmt.Errorf("audit bounded drain: %w", err)
	}
	defer it.Close()
	out := []Entry{}
	total := 0
	for ok := it.SeekGE(entryKey(afterSeq + 1)); ok && len(out) < max; ok = it.Next() {
		if !validEntryKey(it.Key()) {
			return nil, fmt.Errorf("invalid audit entry key")
		}
		seq := seqFromKey(it.Key())
		if seq > frontier {
			break
		}
		value := it.Value()
		if len(value) > maxEntryBytes || len(value) > maxBytes-total {
			return nil, fmt.Errorf("audit entry exceeds bounded-drain budget")
		}
		total += len(value)
		out = append(out, Entry{Seq: seq, Data: append([]byte{}, value...)})
	}
	if err := it.Error(); err != nil {
		return nil, err
	}
	return out, nil
}
