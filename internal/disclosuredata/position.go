package disclosuredata

import (
	"bytes"
	"cmp"
	p "privacy-proxy/internal/disclosurepolicy"
)

func ClonePosition(p *Position) *Position {
	if p == nil {
		return nil
	}
	c := *p
	if p.Activity != nil {
		a := *p.Activity
		c.Activity = &a
	}
	if p.Transaction != nil {
		a := *p.Transaction
		c.Transaction = &a
	}
	if p.Address != nil {
		a := *p.Address
		c.Address = &a
	}
	return &c
}
func validPosition(a Position) bool {
	n := 0
	if a.Activity != nil {
		n++
	}
	if a.Transaction != nil {
		n++
	}
	if a.Address != nil {
		n++
	}
	if n != 1 {
		return false
	}
	switch a.Kind {
	case ActivitySource:
		x := a.Activity
		return x != nil && x.ObservedAtMicros >= 0 && x.ObservedAtMicros <= p.MaxUnixSeconds*1000000+999999 && uuidValid(x.ProducerID) && uuidValid(x.RunID) && uuidValid(x.RecordID) && countValid(x.CompletionOrdinal) && countValue(x.CompletionOrdinal) > 0
	case HistorySource:
		return a.Transaction != nil && countValid(a.Transaction.BlockNumber)
	case WalletSource:
		return a.Address != nil
	}
	return false
}
func PositionForQuery(q NormalizedQuery, a *Position) error {
	if a == nil {
		return nil
	}
	if q.view != List || !validPosition(*a) {
		return ErrInvalid
	}
	want := WalletSource
	switch q.resource {
	case p.ActivityLogs:
		want = ActivitySource
	case p.Transactions:
		want = HistorySource
	case p.AddressHistory:
	default:
		return ErrInvalid
	}
	if a.Kind != want {
		return ErrInvalid
	}
	return nil
}
func ComparePositions(a, b Position) (int, error) {
	if !validPosition(a) || !validPosition(b) || a.Kind != b.Kind {
		return 0, ErrInvalid
	}
	switch a.Kind {
	case ActivitySource:
		x, y := a.Activity, b.Activity
		for _, n := range []int{cmp.Compare(x.ObservedAtMicros, y.ObservedAtMicros), cmp.Compare(x.ProducerID, y.ProducerID), cmp.Compare(x.RunID, y.RunID), cmp.Compare(countValue(x.CompletionOrdinal), countValue(y.CompletionOrdinal)), cmp.Compare(x.RecordID, y.RecordID)} {
			if n != 0 {
				return n, nil
			}
		}
	case HistorySource:
		x, y := a.Transaction, b.Transaction
		for _, n := range []int{cmp.Compare(countValue(x.BlockNumber), countValue(y.BlockNumber)), cmp.Compare(x.TransactionIndex, y.TransactionIndex), bytes.Compare(x.Hash[:], y.Hash[:])} {
			if n != 0 {
				return n, nil
			}
		}
	case WalletSource:
		return bytes.Compare(a.Address.Address[:], b.Address.Address[:]), nil
	}
	return 0, nil
}
