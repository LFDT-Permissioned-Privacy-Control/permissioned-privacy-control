package rpcexecution

import "testing"

func TestOptionalLowerNodeBudgetCannotPoisonParentFinalProbe(t *testing.T) {
	shared := NewHistorySharedBudget(nil)
	parent := &historyReadBudget{limits: DefaultHistoryReadLimits()}
	if e := shared.charge(10, 20, 2, 2, 4096); e != nil {
		t.Fatal(e)
	}
	if e := shared.reserveFinal(parent, 2); e != nil {
		t.Fatal(e)
	}
	before := shared.limits
	lower := DefaultHistoryReadLimits()
	lower.MaxHTTPAttempts = 10
	if shared.lower(lower) == nil || shared.limits != before {
		t.Fatal("optional rejection poisoned original limits")
	}
	shared.releaseFinal(parent)
	if e := shared.charge(2, 5, 0, 0, 1024); e != nil {
		t.Fatal("original final probes lost reserved capacity", e)
	}
}
func TestOptionalNodeAcquisitionsCannotSpendReservedParentWorkOrLowerOwnedLimit(t *testing.T) {
	shared := NewHistorySharedBudget(nil)
	parent := &historyReadBudget{limits: DefaultHistoryReadLimits()}
	if e := shared.reserveFinal(parent, 2); e != nil {
		t.Fatal(e)
	}
	if e := shared.charge(63, 0, 0, 0, 0); e == nil {
		t.Fatal("optional acquisition spent final physical credit")
	}
	if e := shared.reserveOwned(8 << 20); e != nil {
		t.Fatal(e)
	}
	lower := DefaultHistoryReadLimits()
	lower.MaxChargedBytes = 4 << 20
	if shared.lower(lower) == nil || shared.limits.MaxChargedBytes != 16<<20 {
		t.Fatal("lower owned limit poisoned original")
	}
	lower.MaxChargedBytes = 9 << 20
	if e := shared.lower(lower); e != nil {
		t.Fatal(e)
	}
	if e := shared.reserveOwned((1 << 20) + 1); e == nil {
		t.Fatal("aggregate reset lower working-byte ceiling")
	}
}
