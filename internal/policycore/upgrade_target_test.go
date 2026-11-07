package policycore

import (
	"testing"

	"github.com/ethereum/go-ethereum/common"
)

func TestSharedUpgradeInspectionKeepsCanonicalOffsetsAndFailures(t *testing.T) {
	want := common.HexToAddress("0x1111111111111111111111111111111111111111")
	for selector, index := range map[string]int{"0x3659cfe6": 0, "0x4f1ef286": 0, "0xd784d426": 0, "0x99a88ec4": 1, "0x9623609d": 1} {
		input := make([]byte, 4+32*(index+1))
		copy(input, common.FromHex(selector))
		copy(input[4+32*index+12:], want.Bytes())
		got, recognized, err := InspectUpgradeTarget(input)
		if err != nil || !recognized || got != want {
			t.Fatalf("%s target=%s recognized=%v err=%v", selector, got, recognized, err)
		}
		if _, recognized, err := InspectUpgradeTarget(input[:len(input)-1]); !recognized || err == nil {
			t.Fatal("truncated recognized upgrade accepted")
		}
		input[4+32*index] = 1
		if _, recognized, err := InspectUpgradeTarget(input); !recognized || err == nil {
			t.Fatal("noncanonical address accepted")
		}
	}
	if _, recognized, err := InspectUpgradeTarget([]byte{0, 1, 2, 3}); recognized || err != nil {
		t.Fatal("unknown selector became upgrade")
	}
}
