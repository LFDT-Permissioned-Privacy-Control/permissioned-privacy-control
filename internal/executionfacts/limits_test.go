package executionfacts_test

import (
	"math/big"
	"strings"
	"testing"

	"privacy-proxy/internal/executionfacts"
)

func TestResourceBudgetBoundaries(t *testing.T) {
	root := frame("CALL", alice, proxy, "0x7")
	root["input"] = "0xaabb"
	root["error"] = "boom"
	root["revertReason"] = "four"
	child := frame("CALL", proxy, lib, "0x0")
	child["input"] = "0xccdd"
	root["calls"] = []any{child}
	raw := encode(t, root)
	e := expected()
	e.Input = []byte{0xaa, 0xbb}
	for name, set := range map[string]func(*executionfacts.Limits, bool){
		"raw bytes": func(l *executionfacts.Limits, over bool) {
			l.MaxRawBytes = len(raw)
			if over {
				l.MaxRawBytes--
			}
		},
		"records": func(l *executionfacts.Limits, over bool) {
			l.MaxRecords = 2
			if over {
				l.MaxRecords--
			}
		},
		"depth": func(l *executionfacts.Limits, over bool) {
			l.MaxDepth = 1
			if over {
				l.MaxDepth--
			}
		},
		"node input": func(l *executionfacts.Limits, over bool) {
			l.MaxInputBytes = 2
			if over {
				l.MaxInputBytes--
			}
		},
		"aggregate input": func(l *executionfacts.Limits, over bool) {
			l.MaxAggregateInputBytes = 4
			if over {
				l.MaxAggregateInputBytes--
			}
		},
		"text bytes": func(l *executionfacts.Limits, over bool) {
			l.MaxTextBytes = 4
			if over {
				l.MaxTextBytes--
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			limits := executionfacts.DefaultLimits()
			set(&limits, false)
			if tree, err := executionfacts.Parse(raw, e, executionfacts.GethCallTracerProfile(), limits); tree == nil || err != nil {
				t.Fatalf("boundary rejected: %v", err)
			}
			set(&limits, true)
			requireFailure(t, raw, e, limits, executionfacts.LimitExceeded)
		})
	}
}

func TestMaximumDepthAndRecordBudgets(t *testing.T) {
	root := frame("CALL", alice, proxy, "0x7")
	last := root
	for range 256 {
		child := frame("CALL", proxy, proxy, "0x0")
		last["calls"] = []any{child}
		last = child
	}
	if tree := parse(t, root); len(tree.Records()) != 257 {
		t.Fatal("maximum depth lost records")
	}
	last["calls"] = []any{frame("CALL", proxy, proxy, "0x0")}
	requireFailure(t, encode(t, root), expected(), executionfacts.DefaultLimits(), executionfacts.LimitExceeded)
	root = frame("CALL", alice, proxy, "0x7")
	children := make([]any, 4095)
	for i := range children {
		children[i] = frame("CALL", proxy, lib, "0x0")
	}
	root["calls"] = children
	if tree := parse(t, root); len(tree.Records()) != 4096 {
		t.Fatal("maximum width lost records")
	}
	root["calls"] = append(children, frame("CALL", proxy, lib, "0x0"))
	requireFailure(t, encode(t, root), expected(), executionfacts.DefaultLimits(), executionfacts.LimitExceeded)
}

func TestQuantityBoundariesAndInvalidOptions(t *testing.T) {
	root := frame("CALL", alice, proxy, "0x"+strings.Repeat("f", 64))
	root["gas"], root["gasUsed"] = "0xffffffffffffffff", "0xffffffffffffffff"
	e := expected()
	e.Value = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1))
	if tree, err := executionfacts.Parse(encode(t, root), e, executionfacts.GethCallTracerProfile(), executionfacts.DefaultLimits()); tree == nil || err != nil {
		t.Fatal(err)
	}
	root["value"] = "0x1" + strings.Repeat("0", 64)
	requireFailure(t, encode(t, root), e, executionfacts.DefaultLimits(), executionfacts.InvalidTrace)
	root = frame("CALL", alice, proxy, "0x7")
	for _, gas := range []string{"0x10000000000000000", "0x00", "0X1", "0xA", "-1", "1", "0x"} {
		root["gas"] = gas
		requireFailure(t, encode(t, root), expected(), executionfacts.DefaultLimits(), executionfacts.InvalidTrace)
	}
	root = frame("CALL", alice, proxy, "0x7")
	tooDeep := executionfacts.DefaultLimits()
	tooDeep.MaxDepth = 257
	for _, limits := range []executionfacts.Limits{{}, tooDeep} {
		requireFailure(t, encode(t, root), expected(), limits, executionfacts.InvalidOptions)
	}
	raw := encode(t, root)
	raw = append(raw[:len(raw)-1], append([]byte(`,"error":"`), append([]byte{0xff}, []byte(`"}`)...)...)...)
	requireFailure(t, raw, expected(), executionfacts.DefaultLimits(), executionfacts.InvalidTrace)
}

func TestCreationKindsAndStaticOmissionAreExplicit(t *testing.T) {
	root := frame("CALL", alice, proxy, "0x7")
	c := frame("CREATE2", proxy, other, "0x0")
	root["calls"] = []any{c, frame("STATICCALL", proxy, lib, "")}
	tree := parse(t, root)
	r := tree.Records()
	if r[1].Kind != executionfacts.Create2 || r[1].StorageAddress != addr(other) || !tree.Requirements().Creation || r[2].Value.Sign() != 0 || !r[2].Static {
		t.Fatal("creation kind or STATICCALL semantic zero lost")
	}
	c["error"] = "execution reverted"
	delete(c, "to")
	if tree := parse(t, root); !tree.Requirements().UnresolvedExecutionContext {
		t.Fatal("unresolved CREATE2 accepted as known")
	}
}
