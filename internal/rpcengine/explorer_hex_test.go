package rpcengine

import (
	"encoding/json"
	"testing"
)

func TestIndexedHexOnlyAcceptsExactWriterOrNodeEncoding(t *testing.T) {
	for _, test := range []struct {
		raw, canonical string
		want           bool
	}{
		{`""`, "0x", true}, {`"0x"`, "0x", true}, {`"ab01"`, "0xab01", true}, {`"0xab01"`, "0xab01", true},
		{`null`, "0x", false}, {``, "0x", false}, {`false`, "0x", false}, {`7`, "0x", false}, {`{}`, "0x", false},
		{`"0Xab01"`, "0xab01", false}, {`"AB01"`, "0xab01", false}, {`"0xAB01"`, "0xab01", false},
		{`"0x0xab01"`, "0xab01", false}, {`" ab01"`, "0xab01", false}, {`"ab02"`, "0xab01", false},
		{`""`, "0x00", false}, {`"00"`, "0x", false},
		{`"0xAB"`, "0xAB", false}, {`"0x0"`, "0x0", false}, {`"0xzz"`, "0xzz", false},
	} {
		if got := indexedHexMatches(json.RawMessage(test.raw), test.canonical); got != test.want {
			t.Fatalf("%s against %s: %v", test.raw, test.canonical, got)
		}
	}
}
