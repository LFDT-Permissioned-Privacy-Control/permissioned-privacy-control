package explorerindex_test

import (
	"context"
	"testing"
	"time"

	"privacy-proxy/internal/admissionsharedata"
	q "privacy-proxy/internal/explorerquery"
)

func TestActualCurrentCountOriginalOwnerAndPruneOnlyDeliveryFence(t *testing.T) {
	reader, owner, _ := actualReader(t)
	original, stop := context.WithCancel(t.Context())
	defer stop()
	fence, e := admissionsharedata.NewFence(original, 5*time.Second)
	if e != nil {
		t.Fatal(e)
	}
	query := q.Query{Family: q.Transactions, RawLimit: 1, Fence: fence}
	acquire, cancel := context.WithCancel(original)
	pass, e := reader.ReadCohort(acquire, query)
	if e != nil {
		t.Fatal(e)
	}
	defer pass.Close()
	current, e := reader.ReadCurrentCounts(acquire, q.CurrentCountQuery{Read: q.Query{Family: q.Addresses, RawLimit: 1, Fence: fence}, Selectors: []q.CurrentCountSelector{{Family: q.Addresses, Addresses: []string{}}}})
	if e != nil {
		t.Fatal(e)
	}
	defer current.Close()
	cancel()
	if reader.Recheck(t.Context(), pass) != nil || reader.RecheckCurrentCounts(t.Context(), current) != nil {
		t.Fatal("temporary acquisition child became the retained proof owner")
	}
	before := pass.Data()
	if _, e = owner.Exec(t.Context(), `UPDATE prune_state SET pruned_through=1`); e != nil {
		t.Fatal(e)
	}
	floor := before.RunFloor
	query.Upper = before.Upper
	query.DatasetEpoch = before.DatasetEpoch
	query.RunFloor = &floor
	fresh, e := reader.ReadCohort(t.Context(), query)
	if e != nil {
		t.Fatal(e)
	}
	defer fresh.Close()
	after := fresh.Data()
	if *after.Upper != *before.Upper || after.DatasetEpoch != before.DatasetEpoch || after.RunFloor != before.RunFloor || after.HistoryFrom <= before.HistoryFrom {
		t.Fatalf("fixture did not isolate retained-floor movement: before%+v after%+v", before, after)
	}
	if reader.Recheck(t.Context(), pass) == nil || reader.RecheckCurrentCounts(t.Context(), current) == nil {
		t.Fatal("prune-only movement released obsolete exact population")
	}
	stop()
	if reader.Recheck(t.Context(), fresh) == nil {
		t.Fatal("original owner cancellation lost")
	}
}
