package executionfacts_test

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/ethereum/go-ethereum/common"

	"privacy-proxy/internal/executionfacts"
)

var (
	alice = common.HexToAddress("0x1111111111111111111111111111111111111111")
	proxy = common.HexToAddress("0x2222222222222222222222222222222222222222")
	lib   = common.HexToAddress("0x3333333333333333333333333333333333333333")
	other = common.HexToAddress("0x4444444444444444444444444444444444444444")
)

func addr(value common.Address) executionfacts.Address {
	return executionfacts.Address{Value: value, Known: true}
}

func frame(kind string, from, to common.Address, value string) map[string]any {
	f := map[string]any{"type": kind, "from": from.Hex(), "to": to.Hex(), "input": "0x", "gas": "0x100000", "gasUsed": "0x0"}
	if value != "" {
		f["value"] = value
	}
	return f
}

func expected() executionfacts.ExpectedRoot {
	return executionfacts.ExpectedRoot{Kind: executionfacts.Call, From: alice, To: addr(proxy), Value: big.NewInt(7)}
}

func encode(t *testing.T, f map[string]any) []byte {
	t.Helper()
	b, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func parse(t *testing.T, f map[string]any) *executionfacts.Tree {
	t.Helper()
	tree, err := executionfacts.Parse(encode(t, f), expected(), executionfacts.GethCallTracerProfile(), executionfacts.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	return tree
}

func requireFailure(t *testing.T, raw []byte, root executionfacts.ExpectedRoot, limits executionfacts.Limits, code executionfacts.ErrorCode) {
	t.Helper()
	tree, err := executionfacts.Parse(raw, root, executionfacts.GethCallTracerProfile(), limits)
	var detailed *executionfacts.Error
	if tree != nil || !errors.As(err, &detailed) || detailed.Code != code {
		t.Fatalf("want nil tree and %s; tree=%v error=%v", code, tree, err)
	}
}

func TestCapturedGethCallTracerSemantics(t *testing.T) {
	for _, name := range []string{"direct", "delegated", "coded", "staticCoded", "caught", "destroy"} {
		t.Run(name, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join("testdata", "geth-1.14.11", name+".json"))
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
			root := executionfacts.ExpectedRoot{Kind: executionfacts.Call, From: common.HexToAddress(fixture.Request.From), To: addr(common.HexToAddress(fixture.Request.To)), Input: input, Value: value}
			tree, err := executionfacts.Parse(fixture.Result, root, executionfacts.GethCallTracerProfile(), executionfacts.DefaultLimits())
			if err != nil {
				t.Fatal(err)
			}
			records := tree.Records()
			if tree.Profile() != executionfacts.ProfileID || records[0].ParentIndex != -1 || records[0].CallerAddress != addr(root.From) || !tree.Requirements().CodeProvenance {
				t.Fatal("root binding or unresolved executed-code provenance lost")
			}
			for i := 1; i < len(records); i++ {
				if records[i].ParentIndex != i-1 || records[i].Depth != i {
					t.Fatal("ordered parent/depth lost")
				}
			}
			switch name {
			case "direct", "delegated", "coded":
				if len(records) != 2 {
					t.Fatal("nested frame lost")
				}
				r := records[1]
				wantCaller, wantStorage := root.To, r.To
				if name == "delegated" {
					wantCaller, wantStorage = addr(root.From), root.To
				}
				if name == "coded" {
					wantStorage = root.To
				}
				if r.CallerAddress != wantCaller || r.StorageAddress != wantStorage || r.From != root.To.Value || r.Value.Cmp(big.NewInt(7)) != 0 || len(r.Input) != 4 {
					t.Fatalf("incorrect %s execution facts: %+v", name, r)
				}
				// The fixture contract returns msg.sender, msg.value and address(this).
				// This checks reconstructed semantics against actual VM output too.
				if len(r.Output) != 96 || common.BytesToAddress(r.Output[:32]) != wantCaller.Value || new(big.Int).SetBytes(r.Output[32:64]).Cmp(r.Value) != 0 || common.BytesToAddress(r.Output[64:]) != wantStorage.Value {
					t.Fatal("facts disagree with real fixture VM output")
				}
			case "staticCoded":
				if len(records) != 3 || records[1].Kind != executionfacts.StaticCall || records[1].Value.Sign() != 0 || !records[1].Static || records[2].Kind != executionfacts.CallCode || !records[2].Static || records[2].Value.Cmp(big.NewInt(7)) != 0 {
					t.Fatal("static status or explicit CALLCODE value lost")
				}
			case "caught":
				if len(records) != 3 || records[0].Failed() || records[1].Kind != executionfacts.Create || !records[1].Failed() || records[1].To.Known || records[1].StorageAddress.Known || !records[2].AncestorFailed || !tree.Requirements().UnresolvedExecutionContext {
					t.Fatal("caught failed constructor must preserve unresolved context and nested evidence")
				}
			case "destroy":
				if len(records) != 2 || records[1].Kind != executionfacts.SelfDestruct || !tree.Requirements().Lifecycle || records[1].NominalCodeAddress.Known || records[1].StorageAddress != root.To {
					t.Fatal("lifecycle effect must not become synthetic code execution")
				}
			}
		})
	}
}

func TestNestedDelegateCallCodeAndRepeatedFrames(t *testing.T) {
	root := frame("CALL", alice, proxy, "0x7")
	a := frame("DELEGATECALL", proxy, lib, "0x7")
	b := frame("CALLCODE", proxy, other, "0x3")
	c := frame("DELEGATECALL", proxy, lib, "0x3")
	d := frame("CALL", proxy, other, "0x2")
	c["calls"] = []any{d, d}
	b["calls"] = []any{c}
	a["calls"] = []any{b}
	root["calls"] = []any{a}
	r := parse(t, root).Records()
	if len(r) != 6 || r[1].CallerAddress != addr(alice) || r[2].CallerAddress != addr(proxy) || r[3].CallerAddress != addr(proxy) || r[3].Value.Int64() != 3 || r[3].StorageAddress != addr(proxy) || r[4].StorageAddress != addr(other) || r[5].ParentIndex != 3 {
		t.Fatal("nested delegate/callcode semantics or repeated frames lost")
	}
}

func TestUnknownCreationContextAndIndependentRootRecovery(t *testing.T) {
	root := frame("CREATE", alice, proxy, "0x7")
	delete(root, "to")
	root["error"] = "execution reverted"
	child := frame("DELEGATECALL", other, lib, "0x7")
	root["calls"] = []any{child}
	e := executionfacts.ExpectedRoot{Kind: executionfacts.Create, From: alice, Value: big.NewInt(7)}
	tree, err := executionfacts.Parse(encode(t, root), e, executionfacts.GethCallTracerProfile(), executionfacts.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	r := tree.Records()
	if len(r) != 2 || r[0].To.Known || r[0].StorageAddress.Known || r[1].StorageAddress.Known || !tree.Requirements().UnresolvedExecutionContext || !r[1].AncestorFailed {
		t.Fatal("unknown creation context was guessed or nested evidence lost")
	}
	e.CreatedAddress = addr(other)
	tree, err = executionfacts.Parse(encode(t, root), e, executionfacts.GethCallTracerProfile(), executionfacts.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	r = tree.Records()
	if r[0].To.Known || !r[0].ContextFromExpected || r[0].StorageAddress != addr(other) || r[1].StorageAddress != addr(other) || tree.Requirements().UnresolvedExecutionContext {
		t.Fatal("independently supplied root address not distinguished from reported To")
	}
	e.CreatedAddress = addr(proxy)
	requireFailure(t, encode(t, root), e, executionfacts.DefaultLimits(), executionfacts.InvalidTrace)
}

func TestExpectedRootCannotBeReplacedByTraceFields(t *testing.T) {
	raw := encode(t, frame("CALL", alice, proxy, "0x7"))
	for _, change := range []func(*executionfacts.ExpectedRoot){
		func(e *executionfacts.ExpectedRoot) { e.From = other },
		func(e *executionfacts.ExpectedRoot) { e.To = addr(other) },
		func(e *executionfacts.ExpectedRoot) { e.Input = []byte{1} },
		func(e *executionfacts.ExpectedRoot) { e.Value = big.NewInt(8) },
		func(e *executionfacts.ExpectedRoot) { e.Kind = executionfacts.Create; e.To = executionfacts.Address{} },
	} {
		e := expected()
		change(&e)
		requireFailure(t, raw, e, executionfacts.DefaultLimits(), executionfacts.RootMismatch)
	}
	for _, change := range []func(*executionfacts.ExpectedRoot){
		func(e *executionfacts.ExpectedRoot) { e.Value = nil },
		func(e *executionfacts.ExpectedRoot) { e.Value = big.NewInt(-1) },
		func(e *executionfacts.ExpectedRoot) { e.To.Known = false },
		func(e *executionfacts.ExpectedRoot) { e.Kind = executionfacts.StaticCall },
		func(e *executionfacts.ExpectedRoot) { e.CreatedAddress = addr(other) },
	} {
		e := expected()
		change(&e)
		requireFailure(t, raw, e, executionfacts.DefaultLimits(), executionfacts.InvalidOptions)
	}
}

func TestMissingMalformedAndUntrustedFieldsReject(t *testing.T) {
	cases := map[string]func(map[string]any){
		"missing value":           func(f map[string]any) { delete(f, "value") },
		"null value":              func(f map[string]any) { f["value"] = nil },
		"numeric value":           func(f map[string]any) { f["value"] = 7 },
		"decimal value":           func(f map[string]any) { f["value"] = "7" },
		"leading zero":            func(f map[string]any) { f["value"] = "0x07" },
		"value overflow":          func(f map[string]any) { f["value"] = "0x1" + strings.Repeat("0", 64) },
		"gas overflow":            func(f map[string]any) { f["gas"] = "0x10000000000000000" },
		"missing input":           func(f map[string]any) { delete(f, "input") },
		"null input":              func(f map[string]any) { f["input"] = nil },
		"odd input":               func(f map[string]any) { f["input"] = "0x1" },
		"invalid input":           func(f map[string]any) { f["input"] = "0xzz" },
		"short address":           func(f map[string]any) { f["to"] = "0x01" },
		"missing destination":     func(f map[string]any) { delete(f, "to") },
		"wrong casing":            func(f map[string]any) { f["Type"] = f["type"]; delete(f, "type") },
		"lowercase opcode":        func(f map[string]any) { f["type"] = "call" },
		"unknown opcode":          func(f map[string]any) { f["type"] = "AUTHCALL" },
		"raw ownership":           func(f map[string]any) { f["storageAddress"] = proxy.Hex() },
		"wrong tracer":            func(f map[string]any) { f["structLogs"] = []any{} },
		"logs":                    func(f map[string]any) { f["logs"] = []any{} },
		"null calls":              func(f map[string]any) { f["calls"] = nil },
		"object calls":            func(f map[string]any) { f["calls"] = map[string]any{} },
		"scalar child":            func(f map[string]any) { f["calls"] = []any{1} },
		"null output":             func(f map[string]any) { f["output"] = nil },
		"missing gas used":        func(f map[string]any) { delete(f, "gasUsed") },
		"bad child source":        func(f map[string]any) { f["calls"] = []any{frame("CALL", alice, lib, "0x0")} },
		"delegate value mismatch": func(f map[string]any) { f["calls"] = []any{frame("DELEGATECALL", proxy, lib, "0x1")} },
		"nonzero static":          func(f map[string]any) { f["calls"] = []any{frame("STATICCALL", proxy, lib, "0x1")} },
		"failed creation without error": func(f map[string]any) {
			c := frame("CREATE", proxy, lib, "0x0")
			delete(c, "to")
			f["calls"] = []any{c}
		},
		"selfdestruct children": func(f map[string]any) {
			c := frame("SELFDESTRUCT", proxy, lib, "0x0")
			c["calls"] = []any{frame("CALL", proxy, lib, "0x0")}
			f["calls"] = []any{c}
		},
		"selfdestruct input": func(f map[string]any) {
			c := frame("SELFDESTRUCT", proxy, lib, "0x0")
			c["input"] = "0x01"
			f["calls"] = []any{c}
		},
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			f := frame("CALL", alice, proxy, "0x7")
			change(f)
			requireFailure(t, encode(t, f), expected(), executionfacts.DefaultLimits(), executionfacts.InvalidTrace)
		})
	}
	for _, raw := range []string{"", "null", "[]", "{}", `{"type":"CALL"`, string(encode(t, frame("CALL", alice, proxy, "0x7"))) + `{}`, strings.Replace(string(encode(t, frame("CALL", alice, proxy, "0x7"))), `"type":"CALL"`, `"type":"CALL","type":"CALL"`, 1)} {
		requireFailure(t, []byte(raw), expected(), executionfacts.DefaultLimits(), executionfacts.InvalidTrace)
	}
}

func TestTreeAndExpectedInputsAreDetached(t *testing.T) {
	f := frame("CALL", alice, proxy, "0x7")
	f["input"] = "0xaabb"
	f["output"] = "0xccdd"
	raw := encode(t, f)
	e := expected()
	e.Input = []byte{0xaa, 0xbb}
	tree, err := executionfacts.Parse(raw, e, executionfacts.GethCallTracerProfile(), executionfacts.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	for i := range raw {
		raw[i] = 0
	}
	e.Input[0] = 0
	e.Value.SetInt64(99)
	check := func() {
		r := tree.Records()
		if r[0].Value.Int64() != 7 || r[0].Input[0] != 0xaa || r[0].Output[0] != 0xcc {
			t.Error("caller mutation reached immutable tree")
		}
		r[0].Value.SetInt64(100)
		r[0].Input[0] = 0
		r[0].Output[0] = 0
		r[0].To.Value = other
	}
	var workers sync.WaitGroup
	for range 16 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for range 20 {
				check()
			}
		}()
	}
	workers.Wait()
	check()
	var absent *executionfacts.Tree
	if absent.Profile() != "" || len(absent.Records()) != 0 || !absent.Requirements().UnresolvedExecutionContext {
		t.Fatal("nil tree must not imply resolved evidence")
	}
}

func TestOutcomeKeepsTheSameExecutionResult(t *testing.T) {
	root := frame("CALL", alice, proxy, "0x7")
	root["output"], root["error"], root["revertReason"] = "0x0102", "execution reverted", "fixture revert"
	tree := parse(t, root)
	outcome, ok := tree.Outcome()
	if !ok || len(outcome.Output) != 2 || outcome.Output[0] != 1 || outcome.Error != "execution reverted" || outcome.RevertReason != "fixture revert" {
		t.Fatal("root result differs from the checked execution")
	}
	outcome.Output[0] = 9
	if next, _ := tree.Outcome(); next.Output[0] != 1 {
		t.Fatal("outcome getter exposed mutable bytes")
	}
	delete(root, "output")
	if result, ok := parse(t, root).Outcome(); !ok || len(result.Output) != 0 {
		t.Fatal("omitted geth output must mean empty return data")
	}
	var absent *executionfacts.Tree
	if _, ok := absent.Outcome(); ok {
		t.Fatal("nil tree supplied an outcome")
	}
	if _, ok := new(executionfacts.Tree).Outcome(); ok {
		t.Fatal("zero tree supplied an outcome")
	}
}
