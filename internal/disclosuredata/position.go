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
	if p.Events != nil {
		e := *p.Events
		if e.NextLogIndex != nil {
			v := *e.NextLogIndex
			e.NextLogIndex = &v
		}
		c.Events = &e
	}
	if p.FinanceLive != nil {
		f := *p.FinanceLive
		c.FinanceLive = &f
	}
	if p.Finance != nil {
		f := *p.Finance
		c.Finance = &f
	}
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
	if a.Events != nil {
		n++
	}
	if a.FinanceLive != nil {
		n++
	}
	if a.Finance != nil {
		n++
	}
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
	case FinanceSource:
		if a.FinanceLive != nil {
			return a.FinanceLive.ObservedAtMicros >= 0 && a.FinanceLive.ObservedAtMicros <= p.MaxUnixSeconds*1000000+999999 && countValid(a.FinanceLive.ID) && countValue(a.FinanceLive.ID) > 0 && countValue(a.FinanceLive.ID) <= 9223372036854775807
		}
		return a.Finance != nil && countValid(a.Finance.ID) && countValue(a.Finance.ID) > 0 && countValue(a.Finance.ID) <= 9223372036854775807
	case ActivitySource:
		x := a.Activity
		return x != nil && x.ObservedAtMicros >= 0 && x.ObservedAtMicros <= p.MaxUnixSeconds*1000000+999999 && uuidValid(x.ProducerID) && uuidValid(x.RunID) && uuidValid(x.RecordID) && countValid(x.CompletionOrdinal) && countValue(x.CompletionOrdinal) > 0
	case HistorySource:
		if a.Events != nil {
			return validEventsPosition(*a.Events)
		}
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
		if a.Transaction == nil {
			return ErrInvalid
		}
		want = HistorySource
	case p.Events:
		if a.Events == nil {
			return ErrInvalid
		}
		want = HistorySource
	case p.ComplianceReport:
		want = FinanceSource
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
	case FinanceSource:
		if a.FinanceLive != nil || b.FinanceLive != nil {
			if a.FinanceLive == nil || b.FinanceLive == nil {
				return 0, ErrInvalid
			}
			if n := cmp.Compare(b.FinanceLive.ObservedAtMicros, a.FinanceLive.ObservedAtMicros); n != 0 {
				return n, nil
			}
			return cmp.Compare(countValue(b.FinanceLive.ID), countValue(a.FinanceLive.ID)), nil
		}
		return cmp.Compare(countValue(a.Finance.ID), countValue(b.Finance.ID)), nil
	case ActivitySource:
		x, y := a.Activity, b.Activity
		for _, n := range []int{cmp.Compare(x.ObservedAtMicros, y.ObservedAtMicros), cmp.Compare(x.ProducerID, y.ProducerID), cmp.Compare(x.RunID, y.RunID), cmp.Compare(countValue(x.CompletionOrdinal), countValue(y.CompletionOrdinal)), cmp.Compare(x.RecordID, y.RecordID)} {
			if n != 0 {
				return n, nil
			}
		}
	case HistorySource:
		if a.Events != nil || b.Events != nil {
			if a.Events == nil || b.Events == nil {
				return 0, ErrInvalid
			}
			return compareEventsPositions(*a.Events, *b.Events), nil
		}
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

func validEventsPosition(e EventsPosition) bool {
	return countValid(e.Parent.BlockNumber) && countValue(e.Parent.BlockNumber) <= 9223372036854775807 && e.Parent.Hash != ([32]byte{}) &&
		(e.Mode == "after" && e.NextLogIndex == nil || e.Mode == "pending" && e.NextLogIndex != nil && *e.NextLogIndex <= 2147483647)
}
func compareEventsPositions(a, b EventsPosition) int {
	for _, n := range []int{cmp.Compare(countValue(a.Parent.BlockNumber), countValue(b.Parent.BlockNumber)), cmp.Compare(a.Parent.TransactionIndex, b.Parent.TransactionIndex), bytes.Compare(a.Parent.Hash[:], b.Parent.Hash[:])} {
		if n != 0 {
			return n
		}
	}
	if a.Mode != b.Mode {
		if a.Mode == "after" {
			return 1
		}
		return -1
	}
	if a.Mode == "pending" {
		return cmp.Compare(*a.NextLogIndex, *b.NextLogIndex)
	}
	return 0
}
