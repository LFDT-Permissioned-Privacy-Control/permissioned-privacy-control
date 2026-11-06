package executionfacts_test

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"os"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"privacy-proxy/internal/executionfacts"
)

func logEntry() map[string]any {
	return map[string]any{"address": proxy.Hex(), "topics": []any{}, "data": "0x01", "position": "0x0"}
}

func logFailure(t *testing.T, raw []byte, limits executionfacts.Limits, code executionfacts.ErrorCode) {
	t.Helper()
	tree, err := executionfacts.Parse(raw, expected(), executionfacts.GethCallTracerWithLogsProfile(), limits)
	var detail *executionfacts.Error
	if tree != nil || !errors.As(err, &detail) || detail.Code != code {
		t.Fatalf("want nil tree and %s, got tree=%v err=%v", code, tree, err)
	}
}

func TestCapturedLogBearingGethTrace(t *testing.T) {
	raw, err := os.ReadFile("testdata/geth-1.14.11/logged.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Request struct{ From, To, Data, Value string }
		Result  json.RawMessage
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	input, err := hex.DecodeString(fixture.Request.Data[2:])
	if err != nil {
		t.Fatal(err)
	}
	value, ok := new(big.Int).SetString(fixture.Request.Value[2:], 16)
	if !ok {
		t.Fatal("bad fixture value")
	}
	e := executionfacts.ExpectedRoot{Kind: executionfacts.Call, From: common.HexToAddress(fixture.Request.From), To: addr(common.HexToAddress(fixture.Request.To)), Input: input, Value: value}
	tree, err := executionfacts.Parse(fixture.Result, e, executionfacts.GethCallTracerWithLogsProfile(), executionfacts.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	r := tree.Records()
	if tree.Profile() != executionfacts.WithLogsProfileID || len(r) != 2 || len(r[0].Logs) != 2 || len(r[1].Logs) != 1 || len(r[0].Logs[0].Topics) != 0 || r[0].Logs[0].Position != 0 || r[0].Logs[1].Position != 1 || len(r[1].Logs[0].Data) != 96 || r[0].Logs[0].Index != nil {
		t.Fatal("real log order/LOG0/optional index/data were not preserved")
	}
	requireFailure(t, fixture.Result, e, executionfacts.DefaultLimits(), executionfacts.InvalidTrace)
}

func TestLogsAreClosedBoundedAndNonAuthoritative(t *testing.T) {
	for name, change := range map[string]func(map[string]any){
		"null topics":   func(l map[string]any) { l["topics"] = nil },
		"object topics": func(l map[string]any) { l["topics"] = map[string]any{} },
		"short topic":   func(l map[string]any) { l["topics"] = []any{"0x01"} },
		"numeric topic": func(l map[string]any) { l["topics"] = []any{1} },
		"five topics": func(l map[string]any) {
			l["topics"] = []any{common.Hash{}.Hex(), common.Hash{}.Hex(), common.Hash{}.Hex(), common.Hash{}.Hex(), common.Hash{}.Hex()}
		},
		"missing address":       func(l map[string]any) { delete(l, "address") },
		"invalid address":       func(l map[string]any) { l["address"] = "0x01" },
		"null data":             func(l map[string]any) { l["data"] = nil },
		"odd data":              func(l map[string]any) { l["data"] = "0x1" },
		"invalid data":          func(l map[string]any) { l["data"] = "0xzz" },
		"missing position":      func(l map[string]any) { delete(l, "position") },
		"position beyond calls": func(l map[string]any) { l["position"] = "0x1" },
		"numeric position":      func(l map[string]any) { l["position"] = 0 },
		"null index":            func(l map[string]any) { l["index"] = nil },
		"index overflow":        func(l map[string]any) { l["index"] = "0x10000000000000000" },
		"unknown authority":     func(l map[string]any) { l["groupIds"] = []any{"admin"} },
	} {
		t.Run(name, func(t *testing.T) {
			root := frame("CALL", alice, proxy, "0x7")
			log := logEntry()
			change(log)
			root["logs"] = []any{log}
			logFailure(t, encode(t, root), executionfacts.DefaultLimits(), executionfacts.InvalidTrace)
		})
	}
	for _, logs := range []any{nil, map[string]any{}, []any{nil}, []any{1}} {
		root := frame("CALL", alice, proxy, "0x7")
		root["logs"] = logs
		logFailure(t, encode(t, root), executionfacts.DefaultLimits(), executionfacts.InvalidTrace)
	}
	root := frame("CALL", alice, proxy, "0x7")
	root["logs"] = []any{logEntry()}
	raw := encode(t, root)
	raw = []byte(strings.Replace(string(raw), `"position":"0x0"`, `"position":"0x0","position":"0x0"`, 1))
	logFailure(t, raw, executionfacts.DefaultLimits(), executionfacts.InvalidTrace)
	_, err := executionfacts.Parse(encode(t, root), expected(), executionfacts.Profile{}, executionfacts.DefaultLimits())
	var detail *executionfacts.Error
	if !errors.As(err, &detail) || detail.Code != executionfacts.InvalidOptions {
		t.Fatal("zero/unknown runtime profile accepted")
	}
}

func TestLogBudgetsAndCopyingIncludeAllFrames(t *testing.T) {
	root := frame("CALL", alice, proxy, "0x7")
	a := logEntry()
	a["index"] = "0x0"
	a["topics"] = []any{common.Hash{}.Hex()}
	root["logs"] = []any{a}
	child := frame("CALL", proxy, lib, "0x0")
	child["logs"] = []any{logEntry()}
	root["calls"] = []any{child}
	raw := encode(t, root)
	limits := executionfacts.DefaultLimits()
	limits.MaxLogs = 2
	limits.MaxAggregateLogBytes = 2
	tree, err := executionfacts.Parse(raw, expected(), executionfacts.GethCallTracerWithLogsProfile(), limits)
	if err != nil {
		t.Fatal(err)
	}
	r := tree.Records()
	*r[0].Logs[0].Index = 9
	r[0].Logs[0].Topics[0] = common.HexToHash("0x12")
	r[0].Logs[0].Data[0] = 9
	r = tree.Records()
	if *r[0].Logs[0].Index != 0 || r[0].Logs[0].Topics[0] != (common.Hash{}) || r[0].Logs[0].Data[0] != 1 {
		t.Fatal("log accessor mutation reached tree")
	}
	limits.MaxLogs = 1
	logFailure(t, raw, limits, executionfacts.LimitExceeded)
	limits.MaxLogs = 2
	limits.MaxAggregateLogBytes = 1
	logFailure(t, raw, limits, executionfacts.LimitExceeded)
	root = frame("CALL", alice, proxy, "0x7")
	logs := make([]any, 4096)
	for i := range logs {
		l := logEntry()
		l["data"] = "0x"
		logs[i] = l
	}
	root["logs"] = logs
	if _, err := executionfacts.Parse(encode(t, root), expected(), executionfacts.GethCallTracerWithLogsProfile(), executionfacts.DefaultLimits()); err != nil {
		t.Fatal(err)
	}
	root["logs"] = append(logs, logEntry())
	logFailure(t, encode(t, root), executionfacts.DefaultLimits(), executionfacts.LimitExceeded)
}
