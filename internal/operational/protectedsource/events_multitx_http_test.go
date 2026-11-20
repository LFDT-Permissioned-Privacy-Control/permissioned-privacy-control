package protectedsource

import (
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	d "privacy-proxy/internal/disclosuredata"
	p "privacy-proxy/internal/disclosurepolicy"
	f "privacy-proxy/internal/disclosuretest"
)

func TestActualDisclosureEventsUseBlockGlobalOrdinalAcrossReceipts(t *testing.T) {
	emitter := common.HexToAddress("0x1000000000000000000000000000000000000001")
	first := []*types.Log{{Address: emitter, Topics: []common.Hash{{1}}, Data: []byte{1}}, {Address: emitter, Topics: []common.Hash{{2}}, Data: []byte{2}}}
	second := make([]*types.Log, 103)
	for i := range second {
		second[i] = &types.Log{Address: emitter, Topics: []common.Hash{{3}}, Data: []byte{byte(i)}}
	}
	node := ownedFunctionalNodeOptions(t, 1, 2, functionalEventNodeOptions{Logs: [][]*types.Log{first, second}})
	h := actualEventsHTTP(t, node)
	id := h.openCase("auditor", []p.Resource{p.Events}, p.Full, f.Now+120)
	query := d.Query{Version: 1, Resource: p.Events, View: d.List, Limit: ptrFinance(uint16(100))}
	seen := map[uint32]bool{}
	ids := map[string]bool{}
	pages := 0
	terminalEmpty := false
	for {
		page, _ := h.page(id, query)
		pages++
		if page.Result.NextCursor == nil {
			terminalEmpty = len(page.Result.Items) == 0
		}
		for _, event := range page.Result.Items {
			if event.BlockNumber != "1" || event.LogIndex > 104 || seen[event.LogIndex] || ids[event.EventID] {
				t.Fatal("block-global position repeated or invalid", event)
			}
			wantTx := uint32(0)
			if event.LogIndex >= 2 {
				wantTx = 1
			}
			if event.TransactionIndex != wantTx {
				t.Fatal("receipt-local log offset confused with block-global ordinal", event)
			}
			seen[event.LogIndex], ids[event.EventID] = true, true
		}
		if page.Result.NextCursor == nil {
			break
		}
		if pages > 5 {
			t.Fatal("pending second receipt never exhausted")
		}
		query.Cursor = page.Result.NextCursor
	}
	if len(seen) != 105 || !terminalEmpty {
		t.Fatal("multi-receipt cursor skipped logs or claimed hash-query exhaustion", len(seen), pages, terminalEmpty)
	}
	for ordinal := uint32(0); ordinal < 105; ordinal++ {
		if !seen[ordinal] {
			t.Fatal("missing global ordinal", ordinal)
		}
	}
}
