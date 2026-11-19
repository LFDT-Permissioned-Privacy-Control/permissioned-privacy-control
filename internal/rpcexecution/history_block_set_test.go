package rpcexecution

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/core/types"
)

// The protocol-only set fixture records physical dispatches, including requests
// failing before a complete header set/body can be returned. Operational tests
// separately cross TLS and the real Indexer/SQL adapters.
func historySetFixture(t *testing.T, count int) (*HistoryBlockClient, *[]string, func(func(string, any) any)) {
	t.Helper()
	f := newHistoryFixture(t, historySigned(t, 0, 7, false, false))
	headers := map[string]*types.Header{"0x0": f.genesis}
	blocks, receipts := map[string]any{}, map[string]any{}
	parent := f.genesis
	for i := 1; i <= count; i++ {
		header := types.CopyHeader(f.header)
		header.Number, header.Time, header.ParentHash = big.NewInt(int64(i)), uint64(i+1), parent.Hash()
		f.header = header
		f.rebind(t)
		number := fmtHistoryQuantity(uint64(i))
		for _, item := range f.block["transactions"].([]any) {
			item.(map[string]any)["blockNumber"] = number
		}
		for _, item := range f.receipts {
			item.(map[string]any)["blockNumber"] = number
		}
		headers[number], blocks[header.Hash().Hex()], receipts[header.Hash().Hex()] = header, f.block, f.receipts
		parent = header
	}
	methods := []string{}
	var mutate func(string, any) any
	f.transport = headerLaneTransportFunc(func(request *http.Request) (*http.Response, error) {
		var q headerLaneRPC
		if json.NewDecoder(request.Body).Decode(&q) != nil {
			t.Fatal("invalid fixture request")
		}
		methods = append(methods, q.Method)
		var key string
		if len(q.Params) > 0 {
			_ = json.Unmarshal(q.Params[0], &key)
		}
		var result any
		switch q.Method {
		case "eth_chainId":
			result = "0x1"
		case "eth_syncing":
			result = false
		case "eth_getHeaderByNumber":
			result = headers[key]
		case "eth_getBlockByHash":
			result = blocks[key]
		case "eth_getBlockReceipts":
			result = receipts[key]
		default:
			t.Fatalf("unexpected set request %s", q.Method)
		}
		if mutate != nil {
			result = mutate(q.Method, result)
		}
		raw, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": q.ID, "result": result})
		if err != nil {
			t.Fatal(err)
		}
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(string(raw)))}, nil
	})
	client := f.client(t, DefaultHistoryBlockLimits())
	// A setter is supplied through the closure to keep the transport's real
	// physical-dispatch accounting unchanged when injecting invalid evidence.
	setter := func(callback func(string, any) any) { mutate = callback }
	return client, &methods, setter
}

func TestHistoryBlockSetSharesNetworkChecksAndKeepsOriginalFence(t *testing.T) {
	for _, count := range []int{1, 25, 100} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			client, methods, _ := historySetFixture(t, count)
			numbers := make([]uint64, count)
			for i := range numbers {
				numbers[i] = uint64(count - i)
			}
			original, end := context.WithTimeout(t.Context(), 5*time.Second)
			defer end()
			deadline, _ := original.Deadline()
			phase, stop := context.WithCancel(original)
			blocks, err := client.AcquireBlockSetWithin(phase, numbers, HistoryOperationFence{deadline, original.Done()}, DefaultHistoryBlockSetLimits())
			stop()
			if err != nil || len(blocks) != count || len(*methods) != 4*count+6 {
				t.Fatal("shared full populations", len(blocks), len(*methods), err)
			}
			for i, block := range blocks {
				if block.Header().Number != numbers[i] || block.TransactionCount() != 1 || block.OwnedBytes() <= 1024 || block.originalDone != original.Done() || !block.originalDeadline.Equal(deadline) {
					t.Fatal("lost order/ownership/fence", i)
				}
				if historyOriginalFence(block) != nil {
					t.Fatal("temporary acquisition cancellation leaked into original fence")
				}
			}
			end()
			if historyOriginalFence(blocks[0]) == nil {
				t.Fatal("fresh caller renewed original operation")
			}
		})
	}
}

func TestHistoryBlockSetLoweredBudgetsRejectBeforeDispatch(t *testing.T) {
	for _, kind := range []string{"member-calls", "set-calls", "member-wire", "set-wire", "member-owned", "set-owned", "duplicate"} {
		t.Run(kind, func(t *testing.T) {
			client, methods, _ := historySetFixture(t, 2)
			limits := DefaultHistoryBlockSetLimits()
			numbers := []uint64{2, 1}
			switch kind {
			case "member-calls":
				client.limits.MaxRequests = 9
			case "set-calls":
				limits.MaxRequests = 13
			case "member-wire":
				client.limits.MaxTotalWireBytes = 1024
			case "set-wire":
				limits.MaxTotalWireBytes = 1024
			case "member-owned":
				client.limits.MaxObservationBytes = 1024
			case "set-owned":
				limits.MaxObservationBytes = 1024
			case "duplicate":
				numbers = []uint64{1, 1}
			}
			_, err := client.AcquireBlockSetWithin(t.Context(), numbers, HistoryOperationFence{Deadline: time.Now().Add(time.Second)}, limits)
			if err == nil || len(*methods) != 0 {
				t.Fatal("lowered budget dispatched", len(*methods), err)
			}
		})
	}
}

func TestHistoryBlockSetCountsIncompleteWorkAndRejectsBadTail(t *testing.T) {
	for _, stage := range []string{"before", "body", "receipt", "post"} {
		t.Run(stage, func(t *testing.T) {
			client, methods, setter := historySetFixture(t, 2)
			headers, bodies, receipts := 0, 0, 0
			setter(func(method string, value any) any {
				switch method {
				case "eth_getHeaderByNumber":
					headers++
					if stage == "before" && headers == 3 || stage == "post" && headers == 5 {
						return nil
					}
				case "eth_getBlockByHash":
					bodies++
					if stage == "body" && bodies == 2 {
						return nil
					}
				case "eth_getBlockReceipts":
					receipts++
					if stage == "receipt" && receipts == 2 {
						return []any{}
					}
				}
				return value
			})
			blocks, err := client.AcquireBlockSetWithin(t.Context(), []uint64{2, 1}, HistoryOperationFence{Deadline: time.Now().Add(time.Second)}, DefaultHistoryBlockSetLimits())
			if err == nil || len(blocks) != 0 {
				t.Fatal("invalid tail became prefix", stage, len(blocks), err)
			}
			want := map[string]int{"before": 5, "body": 8, "receipt": 9, "post": 13}[stage]
			if len(*methods) != want {
				t.Fatal("lost attempted partial work", stage, len(*methods), want)
			}
		})
	}
}

func TestHistoryBlockFinishCannotOutliveAcquisitionChild(t *testing.T) {
	f := newHistoryFixture(t, historySigned(t, 0, 7, false, false))
	client := f.client(t, DefaultHistoryBlockLimits())
	block := historyAcquire(t, client)
	phase, stop := context.WithCancel(t.Context())
	stop()
	selector, _ := HistoryBlockNumber(1)
	// The caller remains live. Cancellation in the gap after post headers and
	// before the final digest must still prevent a completed observation.
	if historyOriginalFence(block) != nil {
		t.Fatal("original must still be live")
	}
	if _, err := client.finishBody(phase, block, selector, time.Now().Add(time.Second), t.Context().Done()); err == nil {
		t.Fatal("acquisition cancellation ignored after digest")
	}
}

func TestHistoryBlockOwnershipIncludesReceiptLogsAndHonorsTightSetBudget(t *testing.T) {
	plain := newHistoryFixture(t, historySigned(t, 0, 0, false, false))
	base := historyAcquire(t, plain.client(t, DefaultHistoryBlockLimits()))
	logged := historyLogFixture(t, false)
	block := historyAcquire(t, logged.client(t, DefaultHistoryBlockLimits()))
	// One retained log owns its128-byte fixed metadata,32-byte topic and3-byte
	// data, in addition to the complete transaction and512-byte receipt charge.
	if block.OwnedBytes() != base.OwnedBytes()+128+32+3 {
		t.Fatal("receipt/log ownership was omitted", base.OwnedBytes(), block.OwnedBytes())
	}
	for _, delta := range []int{0, -1} {
		limits := DefaultHistoryBlockSetLimits()
		limits.MaxObservationBytes = block.OwnedBytes() + 512 + delta
		blocks, err := logged.client(t, DefaultHistoryBlockLimits()).AcquireBlockSetWithin(t.Context(), []uint64{1}, HistoryOperationFence{Deadline: time.Now().Add(time.Second)}, limits)
		if delta == 0 && (err != nil || len(blocks) != 1 || blocks[0].OwnedBytes() != block.OwnedBytes()) {
			t.Fatal("exact owned budget rejected", err)
		}
		if delta < 0 && (err == nil || len(blocks) != 0) {
			t.Fatal("one-byte ownership overflow became successful prefix", err)
		}
	}
}

func TestHistoryBlockSetChargesUnconsumedBeforeHeaders(t *testing.T) {
	client, methods, _ := historySetFixture(t, 3)
	// Measure one complete member, then fund exactly one member plus less than
	// the minimum next-member room. Before-headers still cover all three.
	selector, _ := HistoryBlockNumber(1)
	one, err := client.AcquireBlock(t.Context(), selector)
	if err != nil {
		t.Fatal(err)
	}
	*methods = nil
	limits := DefaultHistoryBlockSetLimits()
	limits.MaxObservationBytes = 3*512 + one.OwnedBytes() + 1023
	blocks, err := client.AcquireBlockSetWithin(t.Context(), []uint64{3, 2, 1}, HistoryOperationFence{Deadline: time.Now().Add(time.Second)}, limits)
	if err != nil || len(blocks) != 1 || blocks[0].Header().Number != 3 || len(*methods) != 12 {
		t.Fatal("lost before-fetched suffix charge", len(blocks), len(*methods), err)
	}
}
