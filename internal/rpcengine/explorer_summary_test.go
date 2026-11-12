package rpcengine

import (
	"encoding/json"
	"math"
	"strings"
	"testing"

	wire "privacy-proxy/internal/explorerv2data"
)

func TestObservedExplorerStatsCountOnlyEmittedProjection(t *testing.T) {
	zero := "0x" + strings.Repeat("0", 40)
	visible := "0x" + strings.Repeat("1", 40)
	items := []any{wire.Transaction{BlockNumber: qptr(1), From: zero, To: &zero}, wire.Transaction{BlockNumber: qptr(1), From: visible, To: &visible}, wire.Transaction{BlockNumber: qptr(2), From: visible}}
	stats, err := observedExplorerStats(items, wire.PageInfo{Coverage: wire.ObservedVisiblePage})
	if err != nil || stats.ObservedTransactions != "3" || stats.ObservedBlocks != "2" || stats.ObservedParticipantAddresses != "1" || stats.TotalTransactions != nil || stats.TotalAddresses != nil {
		t.Fatal(stats, err)
	}
	empty, err := observedExplorerStats(nil, wire.PageInfo{Coverage: wire.ObservedVisiblePage})
	if err != nil || empty.ObservedTransactions != "0" || empty.ObservedBlocks != "0" || empty.ObservedParticipantAddresses != "0" {
		t.Fatal(empty, err)
	}
}

func TestObservedExplorerUTCBucketsAndNoInventedEmptyIntervals(t *testing.T) {
	for _, test := range []struct {
		interval string
		times    []uint64
		want     string
	}{
		{"hour", []uint64{3599, 3600, 3601}, `[{"timestamp":"0","count":"1"},{"timestamp":"3600","count":"2"}]`},
		{"day", []uint64{86399, 86400, 4 * 86400}, `[{"timestamp":"0","count":"1"},{"timestamp":"86400","count":"1"},{"timestamp":"345600","count":"1"}]`},
		{"week", []uint64{345599, 345600, 950399, 950400}, `[{"timestamp":"0","count":"1"},{"timestamp":"345600","count":"2"},{"timestamp":"950400","count":"1"}]`},
	} {
		t.Run(test.interval, func(t *testing.T) {
			items := []any{}
			for _, stamp := range test.times {
				items = append(items, wire.Transaction{BlockTimestamp: qptr(stamp)})
			}
			points, err := observedExplorerHistory(items, test.interval)
			raw, _ := json.Marshal(points)
			if err != nil || string(raw) != test.want {
				t.Fatal(string(raw), err)
			}
		})
	}
	points, err := observedExplorerHistory(nil, "day")
	raw, _ := json.Marshal(points)
	if err != nil || string(raw) != "[]" {
		t.Fatal(string(raw), err)
	}
	if _, err := observedExplorerHistory([]any{wire.Transaction{BlockTimestamp: qptr(math.MaxUint64)}}, "week"); err != nil {
		t.Fatal("uint64 overflow", err)
	}
	for _, label := range []string{"stats", "stats/tx-history"} {
		request, err := parseExplorerRequest("/api/v2/explorer/"+label, "limit=1&cursor=opaque")
		if err != nil || request.limit != 1 || request.cursor != "opaque" {
			t.Fatal(label, request, err)
		}
		if _, err := parseExplorerRequest("/api/v2/explorer/"+label, "category=coin_transfer"); err == nil {
			t.Fatal("unsupported stats filter", label)
		}
	}
}
